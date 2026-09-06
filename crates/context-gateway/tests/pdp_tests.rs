use chrono::{DateTime, Utc};
use context_gateway::pdp::evaluator::{evaluate, Request, Subject, Verdict};
use jc_core::kinds::{Operation, PolicySpec};
use std::collections::BTreeSet;

fn now() -> DateTime<Utc> {
    "2026-09-06T12:00:00Z"
        .parse()
        .expect("a fixed instant, so a verdict is reproducible")
}

fn policy(yaml: &str) -> PolicySpec {
    serde_norway::from_str(yaml).expect("the policy spec parses")
}

fn public_read() -> PolicySpec {
    policy(
        r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity, retrieveEntity]
information:
  - entities:
      - type: AirQualityObserved
        idPattern: "^urn:ngsi-ld:AirQualityObserved:banskabystrica\\.sk:ovzdusie:.*$"
    propertyNames: [pm10, pm25, dateObserved, location]
q: "pm10>=0"
scopeQ: "/geo/SK/BB"
"#,
    )
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// GW5, R5: nothing granted it, so it is refused. Not an empty result, not a guess.
#[test]
fn an_empty_policy_set_denies() {
    let verdict = evaluate(
        &Subject::anonymous(),
        Operation::QueryEntity,
        &Request::default(),
        "ovzdusie",
        &[],
        now(),
    );

    assert_eq!(verdict, Verdict::Deny);
    assert!(verdict.constraints().is_none());
}

/// GW22: anonymous is the role `public`, evaluated by exactly the same machinery.
#[test]
fn an_anonymous_caller_gets_the_public_grant_as_a_rewrite() {
    let verdict = evaluate(
        &Subject::anonymous(),
        Operation::QueryEntity,
        &Request::default(),
        "ovzdusie",
        &[public_read()],
        now(),
    );

    let constraints = verdict.constraints().expect("the public grant rewrites");
    assert_eq!(
        constraints.tenant, "ovzdusie",
        "the tenant is always pinned"
    );
    assert_eq!(constraints.types, set(&["AirQualityObserved"]));
    assert_eq!(
        constraints.attrs,
        set(&["dateObserved", "location", "pm10", "pm25"]),
        "asking for nothing yields the granted set, which is what the response is cut to"
    );
    assert_eq!(constraints.q.as_deref(), Some("(pm10>=0)"));
    assert_eq!(constraints.scope_q.as_deref(), Some("(/geo/SK/BB)"));
    assert!(constraints
        .id_patterns
        .iter()
        .all(|p| p.starts_with('^') && p.ends_with('$')));
}

/// GW3: an ordinary caller never gets a plain ALLOW. The floor is REWRITE, because the
/// tenant alone is pinned by the gateway.
#[test]
fn a_caller_the_policy_does_not_name_is_denied() {
    let stranger = Subject {
        user: Some("someone.else".to_owned()),
        ..Subject::default()
    };

    assert!(evaluate(
        &stranger,
        Operation::QueryEntity,
        &Request::default(),
        "ovzdusie",
        &[public_read()],
        now(),
    )
    .is_deny());
}

/// GW5: the grant lists the operations it grants, and nothing else. A read grant is not a
/// write grant, whatever else matches.
#[test]
fn an_operation_outside_the_grant_is_denied() {
    for operation in [
        Operation::CreateEntity,
        Operation::UpdateAttrs,
        Operation::DeleteEntity,
        Operation::QueryTemporal,
    ] {
        assert!(
            evaluate(
                &Subject::anonymous(),
                operation,
                &Request::default(),
                "ovzdusie",
                &[public_read()],
                now(),
            )
            .is_deny(),
            "{operation:?} is not in the grant"
        );
    }
}

/// R8: a grant may name a CIM 009 operation group, and it covers exactly the operations
/// Table 4.20-2 lists for it.
#[test]
fn an_operation_group_grant_covers_its_table_members() {
    let grant = policy(
        r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [retrieveOps]
"#,
    );

    for covered in [Operation::RetrieveEntity, Operation::QueryEntity] {
        assert!(
            !evaluate(
                &Subject::anonymous(),
                covered,
                &Request::default(),
                "ovzdusie",
                std::slice::from_ref(&grant),
                now()
            )
            .is_deny(),
            "retrieveOps covers {covered:?}"
        );
    }
    for outside in [
        Operation::CreateEntity,
        Operation::QueryTemporal,
        Operation::QueryBatch,
    ] {
        assert!(
            evaluate(
                &Subject::anonymous(),
                outside,
                &Request::default(),
                "ovzdusie",
                std::slice::from_ref(&grant),
                now()
            )
            .is_deny(),
            "retrieveOps does not cover {outside:?}"
        );
    }
}

/// GW4: a prohibition is evaluated first and ends the evaluation, whatever the caller's
/// other grants say.
#[test]
fn a_prohibition_overrides_a_permission_that_would_have_matched() {
    let prohibition = policy(
        r#"contextSpaceRef: ovzdusie
effect: prohibition
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity, retrieveEntity]
information:
  - entities:
      - type: AirQualityObserved
"#,
    );

    let allowed = evaluate(
        &Subject::anonymous(),
        Operation::QueryEntity,
        &Request::default(),
        "ovzdusie",
        &[public_read()],
        now(),
    );
    assert!(!allowed.is_deny(), "the permission alone rewrites");

    let denied = evaluate(
        &Subject::anonymous(),
        Operation::QueryEntity,
        &Request::default(),
        "ovzdusie",
        &[public_read(), prohibition],
        now(),
    );
    assert_eq!(denied, Verdict::Deny, "the prohibition wins");
}

/// GW7: a policy outside its validity window grants nothing, in either direction.
#[test]
fn a_policy_outside_its_validity_window_grants_nothing() {
    let expired = policy(
        r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity]
validity: { from: "2026-01-01T00:00:00Z", to: "2026-06-01T00:00:00Z" }
"#,
    );
    let future = policy(
        r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity]
validity: { from: "2027-01-01T00:00:00Z" }
"#,
    );

    for policy in [expired, future] {
        assert!(evaluate(
            &Subject::anonymous(),
            Operation::QueryEntity,
            &Request::default(),
            "ovzdusie",
            &[policy],
            now(),
        )
        .is_deny());
    }
}

/// GW11, per dimension: the request is intersected with the grant, never widened by it.
#[test]
fn asking_for_more_than_the_grant_covers_narrows_to_the_grant() {
    let asked = Request {
        types: set(&["AirQualityObserved", "ParkingSpot"]),
        attrs: set(&["pm10", "operatorPhone"]),
        q: Some("pm10>50".to_owned()),
        ..Request::default()
    };

    let verdict = evaluate(
        &Subject::anonymous(),
        Operation::QueryEntity,
        &asked,
        "ovzdusie",
        &[public_read()],
        now(),
    );
    let constraints = verdict.constraints().expect("a narrowed rewrite");

    assert_eq!(
        constraints.types,
        set(&["AirQualityObserved"]),
        "type narrowed"
    );
    assert_eq!(constraints.attrs, set(&["pm10"]), "attrs narrowed");
    assert_eq!(
        constraints.q.as_deref(),
        Some("(pm10>50);(pm10>=0)"),
        "the caller's filter is conjoined with the grant's, never replaced by it"
    );
    assert!(
        constraints.restricted,
        "the answer says it was narrowed (R22)"
    );
}

/// ADR 006: the caller's filter must never be able to reach outside itself and regroup
/// what follows it. An unbalanced filter is dropped, leaving the grants alone in force.
#[test]
fn a_caller_filter_cannot_break_out_of_its_parentheses() {
    let injected = Request {
        // Closing the wrapping parenthesis early would turn the conjunction into a
        // disjunction and hand the caller everything the second operand matches.
        q: Some("pm10>50)|(pm10<0".to_owned()),
        ..Request::default()
    };

    let verdict = evaluate(
        &Subject::anonymous(),
        Operation::QueryEntity,
        &injected,
        "ovzdusie",
        &[public_read()],
        now(),
    );
    let q = verdict
        .constraints()
        .expect("a rewrite")
        .q
        .clone()
        .expect("the grant's own filter stays");

    assert_eq!(
        q, "(pm10>=0)",
        "the unbalanced filter was dropped, not conjoined"
    );
    assert!(!q.contains("pm10<0"));
}

/// GW10: grants are OR-ed with each other and AND-ed with the caller, so holding two
/// grants never lets one grant's filter apply to the other's types.
#[test]
fn several_grants_are_or_ed_with_each_other_and_and_ed_with_the_caller() {
    let second = policy(
        r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity]
information:
  - entities:
      - type: ParkingSpot
    propertyNames: [availableSpotNumber]
q: "availableSpotNumber>0"
"#,
    );

    let verdict = evaluate(
        &Subject::anonymous(),
        Operation::QueryEntity,
        &Request {
            q: Some("dateObserved>\"2026-09-01\"".to_owned()),
            ..Request::default()
        },
        "ovzdusie",
        &[public_read(), second],
        now(),
    );
    let constraints = verdict.constraints().expect("a rewrite");

    assert_eq!(
        constraints.q.as_deref(),
        Some("(dateObserved>\"2026-09-01\");((pm10>=0)|(availableSpotNumber>0))")
    );
    assert_eq!(
        constraints.types,
        set(&["AirQualityObserved", "ParkingSpot"]),
        "the union of what the grants cover"
    );
}

/// The intersection must never widen, in any dimension. One negative case each: whatever
/// the caller sends, the grant's own constraint is still in the answer (GW11).
#[test]
fn no_dimension_can_be_widened_by_what_the_caller_sends() {
    let grant = policy(
        r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity]
information:
  - entities:
      - type: AirQualityObserved
    propertyNames: [pm10]
q: "pm10>=0"
scopeQ: "/geo/SK/BB"
geoQ: "georel=within;geometry=Polygon;coordinates=[[[19.1,48.7],[19.2,48.7],[19.2,48.76],[19.1,48.76],[19.1,48.7]]]"
temporalQ: "timerel=after;timeAt=P-1D"
"#,
    );

    // The caller asks for a different everything: another type, another attribute, a
    // wider filter, a wider scope, a wider area, a wider window.
    let greedy = Request {
        types: set(&["ParkingSpot"]),
        attrs: set(&["operatorPhone"]),
        q: Some("pm10<0".to_owned()),
        scope_q: Some("/geo/SK".to_owned()),
        geo_q: Some(
            "georel=within;geometry=Polygon;coordinates=[[[0,0],[90,0],[90,90],[0,90],[0,0]]]"
                .to_owned(),
        ),
        temporal_q: Some("timerel=after;timeAt=P-10Y".to_owned()),
    };

    let verdict = evaluate(
        &Subject::anonymous(),
        Operation::QueryEntity,
        &greedy,
        "ovzdusie",
        &[grant],
        now(),
    );
    let constraints = verdict.constraints().expect("a rewrite");

    assert!(
        constraints.types.is_empty(),
        "no granted type was asked for, so nothing is served"
    );
    assert!(
        constraints.attrs.is_empty(),
        "no granted attribute was asked for"
    );
    assert!(constraints.restricted);

    for (dimension, value, granted) in [
        ("q", &constraints.q, "pm10>=0"),
        ("scopeQ", &constraints.scope_q, "/geo/SK/BB"),
        ("geoQ", &constraints.geo_q, "coordinates=[[[19.1,48.7]"),
        ("temporalQ", &constraints.temporal_q, "timeAt=P-1D"),
    ] {
        let value = value
            .as_deref()
            .unwrap_or_else(|| panic!("{dimension} survives"));
        assert!(
            value.contains(granted),
            "{dimension} lost the grant's own constraint: {value}"
        );
    }
}
