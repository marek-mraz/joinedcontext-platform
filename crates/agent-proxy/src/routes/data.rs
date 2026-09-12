//! Data route forwarding to Context Gateway (/v1/data/*).

use crate::audit::{log_request, AuditEntry};
use crate::auth::authenticate;
use crate::ProxyState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use std::time::Instant;

const FORBIDDEN_CLIENT_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "ngsild-tenant",
    "x-userinfo",
    "x-access-token",
    "x-allowed-scope-ids",
    "x-endpoint-slug",
    "x-consumer-identity",
];

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

    if rest.contains("..") || rest.starts_with('/') || rest.contains("//") {
        return jc_core::ProblemDetails::forbidden()
            .with_detail("path traversal not permitted")
            .into_response();
    }

    if !run.allows_write {
        if matches!(method, Method::PATCH | Method::PUT | Method::DELETE) {
            return jc_core::ProblemDetails::forbidden()
                .with_detail("write operations not permitted on read-only run")
                .into_response();
        }
        if method == Method::POST
            && rest != "mcp"
            && !rest.ends_with("/query")
            && rest != "entityOperations/query"
        {
            return jc_core::ProblemDetails::forbidden()
                .with_detail("mutating POST requests not permitted on read-only run")
                .into_response();
        }
    }

    let token = match state
        .credentials
        .get_endpoint_token(&run.endpoint_slug)
        .await
    {
        Ok(t) => t,
        Err(e) => return jc_core::ProblemDetails::internal_opaque(&e).into_response(),
    };

    let target_url = format!(
        "{}/api/endpoint/{}/{}",
        state.config.gateway_base.as_str().trim_end_matches('/'),
        run.endpoint_slug,
        rest.trim_start_matches('/')
    );

    let body_bytes = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return jc_core::ProblemDetails::bad_request()
                .with_detail("failed to read body")
                .into_response()
        }
    };

    // If MCP tools/call on read-only run, inspect for mutation tools
    if rest == "mcp" && !run.allows_write {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            if v.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
                if let Some(tool) = v
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                {
                    if matches!(tool, "upsert_entity" | "create_subscription") {
                        return jc_core::ProblemDetails::forbidden()
                            .with_detail("mutation tools not permitted on read-only run")
                            .into_response();
                    }
                }
            }
        }
    }

    let mut client_req = state.http.request(method.clone(), &target_url);
    for (k, v) in headers.iter() {
        let name = k.as_str().to_lowercase();
        if !FORBIDDEN_CLIENT_HEADERS.contains(&name.as_str())
            && !name.starts_with("x-jc-")
            && name != "host"
        {
            client_req = client_req.header(k, v);
        }
    }
    client_req = client_req.bearer_auth(token).body(body_bytes);

    let upstream_resp = match client_req.send().await {
        Ok(r) => r,
        Err(e) => return jc_core::ProblemDetails::internal_opaque(&e.to_string()).into_response(),
    };

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp_builder = Response::builder().status(status);

    for (k, v) in upstream_resp.headers().iter() {
        if k.as_str().to_lowercase() != "set-cookie" {
            resp_builder = resp_builder.header(k, v);
        }
    }

    let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();
    log_request(&AuditEntry {
        run_id: &run.id,
        user: &run.created_by,
        upstream: "context-gateway",
        method: method.as_str(),
        path: &rest,
        status: status.as_u16(),
        bytes: resp_bytes.len(),
        duration_ms: start.elapsed().as_millis(),
    });

    resp_builder
        .body(Body::from(resp_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
