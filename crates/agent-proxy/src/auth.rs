//! Run ticket authentication and service mesh identity verification.

use crate::config::Config;
use crate::runs::{RunContext, RunResolver};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::HeaderMap;
use std::sync::Arc;

pub const RUN_HEADER: &str = "x-jc-run";
pub const TICKET_HEADER: &str = "x-jc-ticket";
/// The bearer form of the same credential, for a client that cannot set headers of its own.
///
/// An OpenAI-compatible model client sends one thing and one thing only: `Authorization: Bearer
/// <api key>`. The workspace has no key, it has a ticket, so the ticket travels in that slot as
/// `jcr_<run id>.<ticket>` and is verified exactly as the two headers are (AG-52, ADR-N-020).
pub const TICKET_BEARER_PREFIX: &str = "jcr_";

/// The run and ticket a request presents, in either of the two forms.
fn credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    if let (Some(run), Some(ticket)) = (header(RUN_HEADER), header(TICKET_HEADER)) {
        return Some((run, ticket));
    }
    let bearer = header("authorization")?;
    let token = bearer.strip_prefix("Bearer ")?.trim();
    let (run, ticket) = token.strip_prefix(TICKET_BEARER_PREFIX)?.split_once('.')?;
    if run.is_empty() || ticket.is_empty() {
        return None;
    }
    Some((run.to_owned(), ticket.to_owned()))
}

pub async fn authenticate(
    headers: &HeaderMap,
    resolver: &RunResolver,
    config: &Config,
) -> Result<Arc<RunContext>, Box<jc_core::ProblemDetails>> {
    let (run_id, ticket) = credentials(headers).ok_or_else(|| {
        Box::new(jc_core::ProblemDetails::unauthorized().with_detail(
            "missing run credentials: X-JC-Run with X-JC-Ticket, or Authorization: Bearer jcr_<run>.<ticket>",
        ))
    })?;
    let (run_id, ticket) = (run_id.as_str(), ticket.as_str());

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
