//! The in-process policy decision point (ADR-N-003, gateway-firewall).

pub mod conditional;
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
use std::collections::{BTreeMap, BTreeSet};
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
        let verdict = evaluator::evaluate(
            subject,
            operation,
            request,
            &endpoint.space,
            &endpoint.policies,
            now(),
        );
        // OPS-16: the one number a dashboard cannot get from the edge. APISIX counts requests
        // and statuses; only the decision point knows a request was answered because a policy
        // let it through rather than because nothing looked.
        crate::telemetry::decided(operation, verdict.is_deny());

        // EP-61: the endpoint's own publication narrowing, folded into the one decision
        // every representation reads, so no encoder can forget it and no new
        // representation has to remember it.
        let verdict = match verdict {
            Verdict::Rewrite(mut constraints) if !endpoint.hidden_attributes.is_empty() => {
                constraints.hidden = endpoint.hidden_attributes.clone();
                constraints.restricted = true;
                Verdict::Rewrite(constraints)
            }
            verdict => verdict,
        };

        // MP-02: the endpoint's projection, intersected into the same decision. Types and
        // attributes narrow like a grant's; the residual filter is conjoined like a REWRITE
        // constraint; nothing here can add what a policy did not give.
        match (verdict, &endpoint.projection) {
            (Verdict::Rewrite(constraints), Some(projection)) => {
                project_constraints(*constraints, projection)
            }
            (verdict, _) => verdict,
        }
    }
}

/// The constraints of one decision, narrowed to a projection (MP-02).
///
/// A request type outside the projection is a refusal rather than an empty answer: an
/// empty `types` set means "no type filter" downstream, and the broker would be asked for
/// every type instead of none (the same rule the evaluator applies to grants, GW10).
fn project_constraints(
    mut constraints: evaluator::Constraints,
    projection: &jc_core::kinds::ModelProjectionSpec,
) -> Verdict {
    let classes: BTreeSet<String> = projection
        .classes
        .iter()
        .map(|class| class.name.clone())
        .collect();
    let types = evaluator::narrow(&constraints.types, &classes);
    if types.is_empty() {
        return Verdict::Deny;
    }
    // Per type, because a projection is a statement about a class: `User: [age]` and
    // `Vehicle: [weight]` joined into one set served a Vehicle's `age` to anyone who asked for
    // both types (T-1862, MP-02). The joined set stays as `attrs`, which is the one list CIM 009
    // lets the broker be told; the answer is stripped by the map.
    let by_type: BTreeMap<String, BTreeSet<String>> = types
        .iter()
        .map(|class| {
            let slots: BTreeSet<String> = projection.attributes_of(class).unwrap_or_default();
            (
                class.clone(),
                evaluator::narrow_to_identity(&constraints.attrs, &slots),
            )
        })
        .collect();
    let slots: BTreeSet<String> = types
        .iter()
        .filter_map(|class| projection.attributes_of(class))
        .flatten()
        .collect();
    constraints.attrs = evaluator::narrow_to_identity(&constraints.attrs, &slots);
    constraints.attrs_by_type = by_type;
    constraints.types = types;
    if let Some(filter) = &projection.filter {
        if let Some(q) = &filter.q {
            constraints.q = evaluator::conjoin(constraints.q.as_deref(), std::slice::from_ref(q));
        }
        // A filter the constraint set has no slot to conjoin with applies when the grants
        // set none; a grant's own geo or temporal clamp is narrower by construction (GW11).
        if constraints.geo_q.is_none() {
            constraints.geo_q = filter.geo_q.clone();
        }
        if constraints.temporal_q.is_none() {
            constraints.temporal_q = filter.temporal_q.clone();
        }
    }
    constraints.restricted = true;
    Verdict::Rewrite(Box::new(constraints))
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
