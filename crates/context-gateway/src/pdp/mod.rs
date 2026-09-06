//! The in-process policy decision point (ADR-N-003, gateway-firewall).

pub mod evaluator;
pub mod geo;
pub mod projection;
pub mod reaper;
pub mod scope_folding;
pub mod temporal;
pub mod write_guard;

use crate::resolver::Endpoint;
use chrono::{DateTime, Utc};
use evaluator::{Request, Subject, Verdict};
use jc_core::kinds::Operation;
use std::time::{SystemTime, UNIX_EPOCH};

/// What decides. Every request passes it before anything is forwarded (GW1, ADR-N-003).
///
/// A trait rather than a function so a test can assert what the enforcement point does
/// with a verdict without having to write the policy that produces it.
pub trait Pdp: Send + Sync + 'static {
    /// The verdict for one caller, one operation and one request on one endpoint.
    fn decide(
        &self,
        subject: &Subject,
        operation: Operation,
        request: &Request,
        endpoint: &Endpoint,
    ) -> Verdict;
}

/// The decision point the gateway runs: the endpoint's own policies, evaluated now.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyPdp;

impl Pdp for PolicyPdp {
    fn decide(
        &self,
        subject: &Subject,
        operation: Operation,
        request: &Request,
        endpoint: &Endpoint,
    ) -> Verdict {
        evaluator::evaluate(
            subject,
            operation,
            request,
            &endpoint.space,
            &endpoint.policies,
            now(),
        )
    }
}

/// The wall clock, as a `chrono` instant.
///
/// `jc-core` builds `chrono` without its `clock` feature so that manifest parsing cannot
/// depend on the time of day; the gateway does need the time of day, for policy validity
/// windows and key expiry, and reads it here in one place.
pub fn now() -> DateTime<Utc> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    DateTime::from_timestamp(since.as_secs() as i64, since.subsec_nanos()).unwrap_or_default()
}
