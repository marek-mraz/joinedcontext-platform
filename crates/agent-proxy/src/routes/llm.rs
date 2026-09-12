//! LLM model provider mediation and token budget tracking (/v1/llm/*).

use crate::audit::{log_request, AuditEntry};
use crate::auth::authenticate;
use crate::ProxyState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use std::time::Instant;

pub async fn handler(
    State(state): State<ProxyState>,
    method: Method,
    headers: HeaderMap,
    Path(rest): Path<String>,
    req: Request<Body>,
) -> Response {
    let start = Instant::now();
    let run = match authenticate(&headers, &state.runs, &state.config).await {
        Ok(r) => r,
        Err(p) => return (*p).into_response(),
    };

    if !matches!(
        rest.as_str(),
        "v1/chat/completions" | "v1/messages" | "chat/completions" | "messages"
    ) {
        return jc_core::ProblemDetails::forbidden()
            .with_detail("only chat/messages completion endpoints permitted")
            .into_response();
    }

    if let Err(msg) = state.limits.check_tokens(&run.id, run.max_tokens).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            jc_core::ProblemDetails::new(429, "too-many-requests", msg),
        )
            .into_response();
    }

    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return jc_core::ProblemDetails::bad_request()
                .with_detail("failed to read body")
                .into_response()
        }
    };

    if body_bytes.len() > 4 * 1024 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            jc_core::ProblemDetails::new(
                413,
                "payload-too-large",
                "request body exceeds 4 MiB limit",
            ),
        )
            .into_response();
    }

    let target_url = format!(
        "{}/{}",
        state.config.model_base.as_str().trim_end_matches('/'),
        rest.trim_start_matches('/')
    );

    let key = state.credentials.get_model_key();
    let mut client_req = state.http.request(method.clone(), &target_url);

    if state.config.model_provider == "anthropic" {
        client_req = client_req
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json");
    } else {
        client_req = client_req
            .bearer_auth(key)
            .header("content-type", "application/json");
    }

    client_req = client_req.body(body_bytes);

    let upstream_resp = match client_req.send().await {
        Ok(r) => r,
        Err(e) => return jc_core::ProblemDetails::internal_opaque(&e.to_string()).into_response(),
    };

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();

    // Extract token usage
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp_bytes) {
        let tokens = if let Some(usage) = v.get("usage") {
            let total = usage.get("total_tokens").and_then(|n| n.as_u64());
            let input = usage
                .get("input_tokens")
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            let output = usage
                .get("output_tokens")
                .and_then(|n| n.as_u64())
                .unwrap_or(0);
            total.unwrap_or(input + output)
        } else {
            0
        };

        if tokens > 0 {
            state.limits.record_tokens(&run.id, tokens).await;
            // Report usage asynchronously to Portal
            let portal_base = state.config.portal_base.clone();
            let proxy_token = state.credentials.get_proxy_token().to_string();
            let run_id = run.id.clone();
            let http = state.http.clone();
            tokio::spawn(async move {
                let mut url = portal_base;
                url.set_path("internal/agent-runs/events");
                let _ = http
                    .post(url)
                    .bearer_auth(proxy_token)
                    .json(&serde_json::json!({
                        "runId": run_id,
                        "kind": "usage",
                        "payload": { "tokensThisStep": tokens }
                    }))
                    .send()
                    .await;
            });
        }
    }

    log_request(&AuditEntry {
        run_id: &run.id,
        user: &run.created_by,
        upstream: "model-provider",
        method: method.as_str(),
        path: &rest,
        status: status.as_u16(),
        bytes: resp_bytes.len(),
        duration_ms: start.elapsed().as_millis(),
    });

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(resp_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
