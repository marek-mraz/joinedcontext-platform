//! Workspace event forwarding to Portal backend (/v1/runs/events).

use crate::audit::{log_request, AuditEntry};
use crate::auth::authenticate;
use crate::ProxyState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use std::time::Instant;

#[derive(serde::Deserialize)]
pub struct EventPayload {
    pub kind: String,
    pub payload: serde_json::Value,
}

pub async fn handler(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    Json(body): Json<EventPayload>,
) -> impl IntoResponse {
    let start = Instant::now();
    let run = match authenticate(&headers, &state.runs, &state.config).await {
        Ok(r) => r,
        Err(p) => return (*p).into_response(),
    };

    if let Err(msg) = state
        .limits
        .check_rpm(&run.id, run.requests_per_minute)
        .await
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            jc_core::ProblemDetails::new(429, "too-many-requests", msg),
        )
            .into_response();
    }

    let mut url = state.config.portal_base.clone();
    url.set_path("internal/agent-runs/events");

    let post_body = serde_json::json!({
        "runId": run.id,
        "kind": body.kind,
        "payload": body.payload,
    });

    let resp = state
        .http
        .post(url)
        .bearer_auth(state.credentials.get_proxy_token())
        .json(&post_body)
        .send()
        .await;

    let (status, bytes) = match resp {
        Ok(r) => {
            let s = StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let b = r.bytes().await.unwrap_or_default();
            (s, b)
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            bytes::Bytes::from(e.to_string()),
        ),
    };

    log_request(&AuditEntry {
        run_id: &run.id,
        user: &run.created_by,
        upstream: "portal",
        method: "POST",
        path: "internal/agent-runs/events",
        status: status.as_u16(),
        bytes: bytes.len(),
        duration_ms: start.elapsed().as_millis(),
    });

    (status, bytes).into_response()
}
