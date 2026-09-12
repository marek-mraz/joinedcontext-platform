//! Run ticket authentication and service mesh identity verification.

use crate::config::Config;
use crate::runs::{RunContext, RunResolver};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::HeaderMap;
use std::sync::Arc;

pub const RUN_HEADER: &str = "x-jc-run";
pub const TICKET_HEADER: &str = "x-jc-ticket";

pub async fn authenticate(
    headers: &HeaderMap,
    resolver: &RunResolver,
    config: &Config,
) -> Result<Arc<RunContext>, Box<jc_core::ProblemDetails>> {
    let run_id = headers
        .get(RUN_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            Box::new(jc_core::ProblemDetails::unauthorized().with_detail("missing X-JC-Run header"))
        })?;

    let ticket = headers
        .get(TICKET_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            Box::new(
                jc_core::ProblemDetails::unauthorized().with_detail("missing X-JC-Ticket header"),
            )
        })?;

    let run = resolver.resolve(run_id).await.map_err(|_| {
        Box::new(jc_core::ProblemDetails::unauthorized().with_detail("invalid or inactive run"))
    })?;

    let parsed_hash = PasswordHash::new(&run.ticket_hash)
        .map_err(|_| Box::new(jc_core::ProblemDetails::internal_opaque("hash-error")))?;

    if Argon2::default()
        .verify_password(ticket.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(Box::new(
            jc_core::ProblemDetails::unauthorized().with_detail("invalid run credentials"),
        ));
    }

    if config.require_mesh_identity {
        let client_id = headers
            .get("l5d-client-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let expected = format!("agent-run-{}", run.id);
        if !client_id.contains(&expected) {
            return Err(Box::new(
                jc_core::ProblemDetails::forbidden().with_detail("mesh workload identity mismatch"),
            ));
        }
    }

    Ok(run)
}
