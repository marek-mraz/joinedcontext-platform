//! T-0175: serving one space as somebody else's model (EP-54, DM-51, DM-52).
//!
//! A view Endpoint is the one surface where the caller and the broker do not speak the same
//! model, so both directions have to hold at once: what comes back is rebuilt in the target
//! model, and what goes out — `attrs`, `q`, `geoQ` — is written back into the source model
//! the broker actually stores. A translation that works in one direction only is a view that
//! answers correctly right up until somebody filters.

mod common;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::routing::any;
use axum::Router;
use context_gateway::app::{router, Gateway};
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::Endpoint;
use context_gateway::translators::view_mapping::{InvalidIr, ViewMapping};
use jc_core::kinds::{Audience, PolicySpec, Representation};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const SLUG: &str = "v6h3zq8ntm2xc7wrb4sdk9jfp5";
const PROJECT: &str = "banskabystrica";
const SPACE: &str = "ovzdusie";
const DOMAIN: &str = "banskabystrica.sk";
const STATION: &str = "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:senzor-01";

/// The IR Model Tools compiles: the local model on the left, Smart Data Models on the right.
fn ir() -> Value {
    json!({
        "version": 1,
        "sourceClass": "MestskySenzor",
        "targetClass": "AirQualityObserved",
        "slots": [
            { "target": "pm25", "source": "pm2p5", "kind": "rename", "filterable": true },
            {
                "target": "temperature", "source": "teplota", "kind": "unitConversion",
                "factor": 1.0, "offset": -273.15, "filterable": true
            },
            {
                "target": "reliability", "source": "spolahlivost", "kind": "valueMappings",
                "forward": { "vysoka": "high", "nizka": "low" },
                "inverse": { "high": "vysoka", "low": "nizka" },
                "filterable": true
            },
            {
                "target": "stationCount", "source": "pocet", "kind": "cast",
                "range": "integer", "filterable": true
            },
            { "target": "dataProvider", "kind": "constant", "value": "bb", "filterable": false },
            { "target": "label", "kind": "expr", "filterable": false }
        ]
    })
}

fn mapping() -> ViewMapping {
    ViewMapping::parse(&ir()).expect("the IR parses")
}

/// The entity as the broker holds it, in the source model's own names.
fn stored() -> Value {
    json!({
        "id": STATION,
        "type": "MestskySenzor",
        "modifiedAt": "2026-09-07T08:00:00Z",
        "pm2p5": { "type": "Property", "value": 12.5 },
        "teplota": { "type": "Property", "value": 292.15 },
        "spolahlivost": { "type": "Property", "value": "vysoka" },
        "pocet": { "type": "Property", "value": "4" },
        "kalibracia": { "type": "Property", "value": 0.3 }
    })
}

/// One request the gateway made upstream.
#[derive(Debug, Clone, Default)]
struct Hop {
    query: String,
}

type Hops = Arc<Mutex<Vec<Hop>>>;

async fn broker() -> (String, Hops) {
    let hops: Hops = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&hops);
    let app = Router::new().fallback(any(move |request: Request| {
        let recorder = Arc::clone(&recorder);
        async move {
            recorder.lock().expect("the hop log").push(Hop {
                query: request.uri().query().unwrap_or_default().to_owned(),
            });
            axum::Json(json!([stored()]))
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

fn policy() -> PolicySpec {
    serde_norway::from_str(&format!(
        "contextSpaceRef: {SPACE}\n\
         assigner: did:web:{DOMAIN}\n\
         assignee: {{ kind: role, id: public }}\n\
         operations: [queryEntity, retrieveEntity, createEntity, updateAttrs, deleteEntity]\n"
    ))
    .expect("the policy spec parses")
}

fn endpoint(view: Option<ViewMapping>) -> Endpoint {
    Endpoint {
        slug: SLUG.to_owned(),
        space: SPACE.to_owned(),
        project: PROJECT.to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd],
        rate_limit: None,
        file_limits: None,
        hidden_attributes: Default::default(),
        view_mapping: view.map(Arc::new),
        base_path: format!("/api/endpoint/{SLUG}"),
        models: Vec::new(),
        policies: vec![policy()],
    }
}

/// One request through a view endpoint, and everything the broker was asked.
async fn through(method: Method, uri: &str) -> (StatusCode, Value, Vec<Hop>, Option<String>) {
    let (upstream, hops) = broker().await;
    let gateway = Arc::new(
        Gateway::new(Broker::new(upstream), Box::new(PolicyPdp), DOMAIN)
            .serve([endpoint(Some(mapping()))]),
    );

    let response = router(gateway)
        .oneshot(
            Request::builder()
                .method(method)
                .uri(format!("/api/endpoint/{SLUG}{uri}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "pm25": { "type": "Property", "value": 1 } }).to_string(),
                ))
                .expect("a request"),
        )
        .await
        .expect("the gateway answers");

    let status = response.status();
    let allow = response
        .headers()
        .get("allow")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a body");
    let made = hops.lock().expect("the hop log").clone();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        made,
        allow,
    )
}

#[tokio::test]
async fn an_answer_comes_back_in_the_target_model() {
    let (status, body, _, _) =
        through(Method::GET, "/ngsi-ld/v1/entities?type=AirQualityObserved").await;
    assert_eq!(status, StatusCode::OK);

    let entity = &body[0];
    assert_eq!(
        entity["type"],
        json!("AirQualityObserved"),
        "the target class"
    );
    assert_eq!(entity["pm25"]["value"], json!(12.5), "a rename");
    assert_eq!(
        entity["temperature"]["value"],
        json!(19.0),
        "kelvin to celsius"
    );
    assert_eq!(
        entity["reliability"]["value"],
        json!("high"),
        "a value mapping"
    );
    assert_eq!(entity["stationCount"]["value"], json!(4), "a cast");
    assert_eq!(entity["dataProvider"], json!("bb"), "a constant");

    assert_eq!(entity["id"], json!(STATION), "still an NGSI-LD entity");
    assert_eq!(
        entity["modifiedAt"],
        json!("2026-09-07T08:00:00Z"),
        "provenance the broker generated survives the translation"
    );
    assert!(
        entity.get("pm2p5").is_none() && entity.get("teplota").is_none(),
        "no source name survives into a view: {entity}"
    );
    assert!(
        entity.get("kalibracia").is_none(),
        "an attribute the mapping does not derive is not part of the target model: {entity}"
    );
}

#[tokio::test]
async fn a_filter_written_in_the_target_model_reaches_the_broker_in_the_source_model() {
    let (status, _, hops, _) = through(
        Method::GET,
        "/ngsi-ld/v1/entities?type=AirQualityObserved&attrs=pm25,temperature\
         &q=reliability==%22high%22;temperature%3E19",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let asked = hops.first().expect("the broker was asked");
    let query = context_gateway::query::decode(&asked.query);
    assert!(
        query.contains("type=MestskySenzor"),
        "the source class: {query}"
    );
    assert!(
        query.contains("attrs=pm2p5,teplota"),
        "source names: {query}"
    );
    assert!(
        query.contains("spolahlivost==\"vysoka\""),
        "the value goes back through the inverse table: {query}"
    );
    assert!(
        query.contains("teplota>292.15"),
        "and a converted value back through the inverse conversion: {query}"
    );
}

/// DM-51: a slot with no inverse cannot be filtered on, and saying so is better than
/// forwarding a name the broker does not know or dropping the filter silently.
#[tokio::test]
async fn a_filter_on_a_slot_the_mapping_cannot_invert_is_refused() {
    for filter in ["label==%22x%22", "dataProvider==%22bb%22"] {
        let (status, body, hops, _) = through(
            Method::GET,
            &format!("/ngsi-ld/v1/entities?type=AirQualityObserved&q={filter}"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{filter}");
        assert!(hops.is_empty(), "nothing was asked upstream for {filter}");
        assert!(
            body["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("query"),
            "the refusal says why: {body}"
        );
    }
}

#[tokio::test]
async fn a_filter_on_an_attribute_the_view_does_not_serve_is_refused() {
    let (status, _, hops, _) = through(
        Method::GET,
        "/ngsi-ld/v1/entities?type=AirQualityObserved&q=kalibracia%3E0",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        hops.is_empty(),
        "the source name is not smuggled through by a caller who guessed it"
    );
}

/// EP-54: every write, before authentication and before anything is forwarded.
#[tokio::test]
async fn a_view_endpoint_refuses_every_write() {
    for (method, uri) in [
        (Method::POST, "/ngsi-ld/v1/entities"),
        (
            Method::PATCH,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:X:a:b:c/attrs",
        ),
        (Method::PUT, "/ngsi-ld/v1/entities/urn:ngsi-ld:X:a:b:c"),
        (Method::DELETE, "/ngsi-ld/v1/entities/urn:ngsi-ld:X:a:b:c"),
    ] {
        let (status, _, hops, allow) = through(method.clone(), uri).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {uri}");
        assert_eq!(
            allow.as_deref(),
            Some("GET, HEAD, OPTIONS"),
            "a 405 names what is allowed (RFC 9110 section 15.5.6)"
        );
        assert!(
            hops.is_empty(),
            "nothing reached the broker for {method} {uri}"
        );
    }
}

/// The same endpoint without a view mapping still writes: read-only is a property of the
/// view, not of the gateway.
#[tokio::test]
async fn an_endpoint_without_a_view_mapping_still_accepts_a_write() {
    let (upstream, hops) = broker().await;
    let gateway = Arc::new(
        Gateway::new(Broker::new(upstream), Box::new(PolicyPdp), DOMAIN).serve([endpoint(None)]),
    );
    let response = router(gateway)
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!(
                    "/api/endpoint/{SLUG}/ngsi-ld/v1/entities/{STATION}/attrs"
                ))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "pm2p5": { "type": "Property", "value": 1 } }).to_string(),
                ))
                .expect("a request"),
        )
        .await
        .expect("the gateway answers");

    assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(!hops.lock().expect("the hop log").is_empty());
}

#[test]
fn the_two_directions_agree_on_every_derivation() {
    let mapping = mapping();
    let mut entity = stored();
    mapping.translate_entity(&mut entity);

    // Whatever the forward direction produced, the inverse of a filter for that same value
    // asks the broker for the value the entity actually stores.
    for (target, produced, source, stored_value) in [
        ("reliability", "high", "spolahlivost", "vysoka"),
        ("temperature", "19", "teplota", "292.15"),
        ("pm25", "12.5", "pm2p5", "12.5"),
    ] {
        let inverted = mapping
            .invert_q(&format!("{target}=={produced}"))
            .expect("the filter inverts");
        assert_eq!(inverted, format!("{source}=={stored_value}"));
    }
}

#[test]
fn an_ir_from_a_newer_model_tools_is_refused_rather_than_half_understood() {
    let mut newer = ir();
    newer["version"] = json!(2);
    assert_eq!(ViewMapping::parse(&newer), Err(InvalidIr::Version(2)));
}

#[test]
fn a_slot_kind_this_gateway_does_not_run_is_refused() {
    let refused = ViewMapping::parse(&json!({
        "version": 1,
        "sourceClass": "A",
        "targetClass": "B",
        "slots": [{ "target": "x", "source": "y", "kind": "join", "filterable": true }]
    }));
    assert!(
        matches!(refused, Err(InvalidIr::Slot { index: 0, ref reason }) if reason.contains("join")),
        "{refused:?}"
    );
}

/// The compiler decides what is filterable; an interpreter that decided for itself would
/// forward a filter through a derivation with no inverse.
#[test]
fn a_slot_that_does_not_say_it_is_filterable_is_not() {
    let mapping = ViewMapping::parse(&json!({
        "version": 1,
        "sourceClass": "A",
        "targetClass": "B",
        "slots": [{ "target": "x", "source": "y", "kind": "rename" }]
    }))
    .expect("the IR parses");

    assert!(mapping.invert_q("x==1").is_err());
    assert_eq!(mapping.source_of("x"), Some("y"), "it is still served");
}
