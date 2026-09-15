//! T-0563: an endpoint that references a `ModelProjection` reads the projected subset of
//! the model and nothing wider (MP-02, MP-03).
//!
//! The grant says who may read; the projection says what the endpoint is about; the
//! gateway intersects the two before any representation. What is worth a test: an
//! attribute outside the projection never reaches the wire, a type outside it is refused
//! before the broker is asked, the residual filter is conjoined so a caller cannot widen
//! it, a grant narrower than the projection wins, and the schema surface describes the
//! projected model only.

mod common;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::routing::any;
use axum::Router;
use context_gateway::app::{router, Gateway};
use context_gateway::handlers::schema;
use context_gateway::pdp::evaluator::Subject;
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::{Endpoint, Model};
use jc_core::envelope::ResourceEnvelope;
use jc_core::kinds::{Audience, ModelProjectionSpec, PolicySpec, Representation};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const SLUG: &str = "3ecozggnnhjlp5miouhia53mr2";
const PROJECT: &str = "helsinki";
const SPACE: &str = "fleet";
const DOMAIN: &str = "hel.fi";

const PARTNER_VIEW: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: ModelProjection
metadata:
  name: partner-view
  namespace: helsinki
spec:
  contextSpaceRef: fleet
  dataModelRef: { kind: DataModel, name: fleet, version: "1" }
  classes:
    - name: Vehicle
      slots: [name, speed]
    - name: User
      slots: [name, age]
  filter:
    q: category=="public"
"#;

fn projection() -> Arc<ModelProjectionSpec> {
    let parsed = ResourceEnvelope::<ModelProjectionSpec>::from_yaml(PARTNER_VIEW).expect("parses");
    parsed.validate().expect("valid");
    Arc::new(parsed.spec)
}

fn vehicle() -> Value {
    json!({
        "id": "urn:ngsi-ld:Vehicle:hel.fi:fleet:bus-01",
        "type": "Vehicle",
        "name": { "type": "Property", "value": "Bus 01" },
        "speed": { "type": "Property", "value": 32 },
        "odometer": { "type": "Property", "value": 120_000 },
        "maintenanceNote": { "type": "Property", "value": "brake pads next week" }
    })
}

type Hops = Arc<Mutex<Vec<String>>>;

async fn broker() -> (String, Hops) {
    let hops: Hops = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&hops);
    let app = Router::new().fallback(any(move |request: Request| {
        let recorder = Arc::clone(&recorder);
        async move {
            recorder
                .lock()
                .expect("the hop log")
                .push(request.uri().query().unwrap_or_default().to_owned());
            axum::Json(json!([vehicle()]))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let address = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), hops)
}

fn policy(information: &str) -> PolicySpec {
    serde_norway::from_str(&format!(
        "contextSpaceRef: {SPACE}\n\
         assigner: did:web:{DOMAIN}\n\
         assignee: {{ kind: role, id: public }}\n\
         operations: [queryEntity, retrieveEntity]\n\
         {information}"
    ))
    .expect("the policy spec parses")
}

fn endpoint(policy: PolicySpec, projection: Option<Arc<ModelProjectionSpec>>) -> Endpoint {
    Endpoint {
        slug: SLUG.to_owned(),
        title: std::collections::BTreeMap::new(),
        description: std::collections::BTreeMap::new(),
        space: SPACE.to_owned(),
        project: PROJECT.to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd],
        rate_limit: None,
        file_limits: None,
        hidden_attributes: Default::default(),
        projection,
        view_mapping: None,
        base_path: format!("/api/endpoint/{SLUG}"),
        models: vec![Model {
            name: "fleet".to_owned(),
            version: "1.0.0".to_owned(),
            major: 1,
            classes: vec!["Vehicle".to_owned(), "User".to_owned(), "Depot".to_owned()],
            json_schema: None,
            context: None,
        }],
        policies: vec![policy],
    }
}

async fn query(endpoint: Endpoint, uri: &str) -> (StatusCode, Value, Vec<String>) {
    let (upstream, hops) = broker().await;
    let gateway = Arc::new(
        Gateway::new(Broker::new(upstream), Box::new(PolicyPdp), DOMAIN).serve([endpoint]),
    );
    let response = router(gateway)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/endpoint/{SLUG}{uri}"))
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the gateway answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let asked = hops.lock().expect("the hop log").clone();
    (status, body, asked)
}

/// MP-02: the whole-entity grant stays a whole-entity grant on the space; on this endpoint
/// the projection keeps `name` and `speed` of a Vehicle and nothing else.
#[tokio::test]
async fn a_query_through_the_projection_returns_only_the_projected_attributes() {
    let (status, body, asked) = query(
        endpoint(policy(""), Some(projection())),
        "/ngsi-ld/v1/entities?type=Vehicle",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entity = &body[0];
    assert_eq!(entity["name"]["value"], json!("Bus 01"));
    assert_eq!(entity["speed"]["value"], json!(32));
    assert!(
        entity.get("odometer").is_none(),
        "outside the projection: {entity}"
    );
    assert!(
        entity.get("maintenanceNote").is_none(),
        "outside the projection: {entity}"
    );
    assert_eq!(
        entity["type"],
        json!("Vehicle"),
        "identity is never projected away"
    );
    assert!(
        asked[0].contains("category"),
        "the residual filter reached the broker: {}",
        asked[0]
    );
}

/// A caller asking for an attribute outside the projection gets the entity without it,
/// not an error; asking for a type outside it is refused before the broker is asked.
#[tokio::test]
async fn an_attribute_outside_is_dropped_and_a_type_outside_is_refused() {
    let (status, body, _) = query(
        endpoint(policy(""), Some(projection())),
        "/ngsi-ld/v1/entities?type=Vehicle&attrs=name,odometer",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body[0]["name"]["value"], json!("Bus 01"));
    assert!(body[0].get("odometer").is_none());

    let (status, _, asked) = query(
        endpoint(policy(""), Some(projection())),
        "/ngsi-ld/v1/entities?type=Depot",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        asked.is_empty(),
        "the broker was never asked for a type the projection lacks"
    );
}

/// T-0805: an attribute no grant names is answered with nothing, never with the whole
/// entity, and the broker is not asked.
#[tokio::test]
async fn an_attribute_outside_the_grant_serves_nothing_and_never_the_whole_entity() {
    let named =
        policy("information:\n  - entities: [{ type: Vehicle }]\n    propertyNames: [name]\n");
    let (status, body, asked) = query(
        endpoint(named, None),
        "/ngsi-ld/v1/entities?type=Vehicle&attrs=maintenanceNote",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!([]), "nothing granted was asked for");
    assert!(asked.is_empty(), "the broker was never asked: {asked:?}");
}

/// T-0805 edge cases: an addressed read for an ungranted attribute is 404 and never a hop; a
/// grant over the whole entity is not narrowed by `attrs`, the caller's selection stands.
#[tokio::test]
async fn an_addressed_read_for_an_ungranted_attribute_is_not_found_and_a_whole_grant_stays() {
    let named =
        policy("information:\n  - entities: [{ type: Vehicle }]\n    propertyNames: [name]\n");
    let (status, _, asked) = query(
        endpoint(named, None),
        "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:hel.fi:fleet:bus-01?attrs=maintenanceNote",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(asked.is_empty(), "the broker was never asked: {asked:?}");

    let (status, body, asked) = query(
        endpoint(policy(""), None),
        "/ngsi-ld/v1/entities?type=Vehicle&attrs=maintenanceNote",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body[0]["maintenanceNote"]["value"],
        json!("brake pads next week")
    );
    assert!(asked[0].contains("attrs=maintenanceNote"), "{asked:?}");
}

/// T-0812: a policy whitelist that shares no slot with the projection leaves identity only;
/// it does not switch the projection off.
#[tokio::test]
async fn a_policy_whitelist_disjoint_from_the_projection_serves_identity_only() {
    let odometer =
        policy("information:\n  - entities: [{ type: Vehicle }]\n    propertyNames: [odometer]\n");
    let (status, body, _) = query(
        endpoint(odometer, Some(projection())),
        "/ngsi-ld/v1/entities?type=Vehicle",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entity = &body[0];
    assert_eq!(entity["type"], json!("Vehicle"));
    for name in ["name", "speed", "odometer", "maintenanceNote"] {
        assert!(entity.get(name).is_none(), "{name} served: {entity}");
    }
}

/// GW10: the projection's `q` is conjoined with the caller's, so a caller's own filter
/// cannot widen what the endpoint is about.
#[tokio::test]
async fn the_residual_filter_is_intersected_and_a_caller_cannot_widen_it() {
    let (status, _, asked) = query(
        endpoint(policy(""), Some(projection())),
        "/ngsi-ld/v1/entities?type=Vehicle&q=category%3D%3D%22internal%22",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sent = &asked[0];
    assert!(
        sent.contains("internal"),
        "the caller's filter is kept: {sent}"
    );
    assert!(
        sent.contains("public"),
        "the projection's filter is kept beside it: {sent}"
    );
}

/// A grant narrower than the projection wins: the projection cannot hand out `speed` when
/// the policy names only `name`.
#[tokio::test]
async fn a_policy_grant_narrower_than_the_projection_wins() {
    let narrower =
        policy("information:\n  - entities: [{ type: Vehicle }]\n    propertyNames: [name]\n");
    let (status, body, _) = query(
        endpoint(narrower, Some(projection())),
        "/ngsi-ld/v1/entities?type=Vehicle",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body[0]["name"]["value"], json!("Bus 01"));
    assert!(
        body[0].get("speed").is_none(),
        "the grant did not give speed: {body}"
    );
}

/// MP-03: the schema surface describes the projected classes and slots only, and the
/// document (so its ETag) changes when the projection does.
#[test]
fn the_schema_surface_serves_the_projected_model() {
    let now = context_gateway::pdp::now();
    let subject = Subject::anonymous();

    let unprojected = endpoint(policy(""), None);
    let visible = schema::visible(&subject, &unprojected, now);
    let types: BTreeSet<String> = schema::visible_types(&unprojected, &visible)
        .into_iter()
        .collect();
    assert!(types.contains("Depot"), "{types:?}");

    let projected = endpoint(policy(""), Some(projection()));
    let visible = schema::visible(&subject, &projected, now);
    let types: BTreeSet<String> = schema::visible_types(&projected, &visible)
        .into_iter()
        .collect();
    assert_eq!(
        types,
        BTreeSet::from(["Vehicle".to_owned(), "User".to_owned()]),
        "exactly the projected classes"
    );
    let index_before = schema::index(
        &unprojected,
        &schema::visible(&subject, &unprojected, now),
        |b| format!("{:x}", b.len()),
    );
    let index_after = schema::index(&projected, &visible, |b| format!("{:x}", b.len()));
    assert_ne!(
        index_before, index_after,
        "the projection changes what is published"
    );
}
