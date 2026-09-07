//! The endpoint as a SensorThings client sees it (T-0160, EP-12, EP-13, TS-08).
//!
//! SensorThings splits one measurement across four linked entity sets, so the thing these tests
//! hold to is that the four agree: the `Datastream` a `Thing` links to exists, its
//! `Observations` are the measurements of that one attribute, and every id is addressable on
//! its own. An id the gateway hands out and then cannot resolve is the failure this
//! representation is most prone to, because ids here are composed rather than stored.
//!
//! The other property is the one that makes it safe: the sets are views of the same projected
//! entity page, so an attribute the policy withholds is missing from all four, and the surface
//! has no write half at all.

mod common;

use axum::body::Body;
use axum::http::{Method, Request as HttpRequest, StatusCode};
use common::BrokerStub;
use context_gateway::app::{router, Gateway};
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::Endpoint;
use jc_core::kinds::{Audience, Representation};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

const SLUG: &str = "mluyob4nz52lok3ssk7pgn5vwt";
const HOST: &str = "https://city.example";
const URN: &str = "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:st-1";

fn endpoint(hidden: &[&str]) -> Endpoint {
    Endpoint {
        slug: SLUG.to_owned(),
        space: "ovzdusie".to_owned(),
        project: "ovzdusie".to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd, Representation::Sta],
        rate_limit: None,
        file_limits: None,
        hidden_attributes: hidden.iter().map(|name| (*name).to_owned()).collect(),
        base_path: format!("/api/endpoint/{SLUG}"),
        models: Vec::new(),
        view_mapping: None,
        policies: vec![serde_norway::from_str(
            r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity, retrieveEntity]
"#,
        )
        .expect("the policy spec parses")],
    }
}

fn gateway(broker: &str, endpoint: Endpoint) -> axum::Router {
    let mut gateway = Gateway::new(
        Broker::new(broker),
        Box::new(PolicyPdp),
        "banskabystrica.sk",
    );
    gateway.public_url = Some(HOST.to_owned());
    router(Arc::new(gateway.serve([endpoint])))
}

/// One station: two measurements, one label, one geometry and one secret.
fn station() -> Value {
    json!({
        "id": URN,
        "type": "AirQualityObserved",
        "name": { "type": "Property", "value": "Kallio" },
        "pm10": {
            "type": "Property",
            "value": 34.2,
            "unitCode": "GQ",
            "observedAt": "2026-09-01T10:00:00Z",
            "modifiedAt": "2026-09-01T10:00:05Z"
        },
        "pm25": { "type": "Property", "value": 12.0, "observedAt": "2026-09-01T10:00:00Z" },
        "operatorPhone": { "type": "Property", "value": "+421 900 000 000" },
        "refDevice": { "type": "Relationship", "object": "urn:ngsi-ld:Device:x" },
        "location": {
            "type": "GeoProperty",
            "value": { "type": "Point", "coordinates": [19.146, 48.736] }
        }
    })
}

fn sta(path: &str) -> String {
    format!("/api/endpoint/{SLUG}/sta/v1.1{path}")
}

async fn call(
    app: axum::Router,
    method: Method,
    path: &str,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the gateway answers");
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("a readable body");
    (
        status,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
        headers,
    )
}

async fn get(app: axum::Router, path: &str) -> (StatusCode, Value) {
    let (status, body, _) = call(app, Method::GET, path).await;
    (status, body)
}

/// The service document is the entry point a conformance suite starts from, so every set of
/// the Sensing profile has to be on it, including the ones the platform holds nothing for.
#[tokio::test]
async fn the_service_document_lists_every_sensing_entity_set() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, document) = get(gateway(&broker.url, endpoint(&[])), &sta("/")).await;
    assert_eq!(status, StatusCode::OK);

    let names: Vec<&str> = document["value"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|set| set["name"].as_str())
        .collect();
    for expected in [
        "Things",
        "Locations",
        "HistoricalLocations",
        "Datastreams",
        "Sensors",
        "Observations",
        "ObservedProperties",
        "FeaturesOfInterest",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    assert_eq!(
        document["value"][0]["url"],
        json!(format!("{HOST}/api/endpoint/{SLUG}/sta/v1.1/Things"))
    );
}

/// EP-12: one entity is one `Thing`, whose id is the URN so the link survives a broker swap.
#[tokio::test]
async fn an_entity_becomes_a_thing_addressable_by_its_urn() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, collection) = get(gateway(&broker.url, endpoint(&[])), &sta("/Things")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(collection["value"].as_array().map(Vec::len), Some(1));

    let thing = &collection["value"][0];
    assert_eq!(thing["@iot.id"], json!(URN));
    assert_eq!(thing["name"], json!("Kallio"));
    assert_eq!(thing["properties"]["type"], json!("AirQualityObserved"));
    assert_eq!(
        thing["Datastreams@iot.navigationLink"],
        json!(format!(
            "{HOST}/api/endpoint/{SLUG}/sta/v1.1/Things('{URN}')/Datastreams"
        ))
    );

    // The same thing on its own, at exactly the self link the collection handed out.
    let one = BrokerStub::start(vec![json!([station()])]).await;
    let (status, alone) = get(
        gateway(&one.url, endpoint(&[])),
        &sta(&format!("/Things('{URN}')")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alone["@iot.id"], json!(URN));
}

/// EP-12: a measured attribute is a `Datastream`, and its id is addressable even though it
/// carries a slash inside the key literal.
#[tokio::test]
async fn a_measured_attribute_is_an_addressable_datastream() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, collection) = get(gateway(&broker.url, endpoint(&[])), &sta("/Datastreams")).await;
    assert_eq!(status, StatusCode::OK);

    let ids: BTreeSet<&str> = collection["value"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|stream| stream["@iot.id"].as_str())
        .collect();
    assert_eq!(
        ids,
        BTreeSet::from([
            format!("{URN}/pm10").as_str(),
            format!("{URN}/pm25").as_str()
        ]),
        "only the numeric attributes are datastreams"
    );

    let pm10 = collection["value"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|stream| stream["@iot.id"] == json!(format!("{URN}/pm10")))
        .expect("the pm10 datastream");
    assert_eq!(pm10["unitOfMeasurement"]["symbol"], json!("GQ"));

    let one = BrokerStub::start(vec![json!([station()])]).await;
    let (status, alone) = get(
        gateway(&one.url, endpoint(&[])),
        &sta(&format!("/Datastreams('{URN}/pm10')")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the slash inside the key is part of it"
    );
    assert_eq!(alone["@iot.id"], json!(format!("{URN}/pm10")));
}

/// EP-12: an `Observation` carries the value, when it was observed and when it was written.
#[tokio::test]
async fn an_observation_carries_the_result_and_its_two_times() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, collection) = get(
        gateway(&broker.url, endpoint(&[])),
        &sta(&format!("/Datastreams('{URN}/pm10')/Observations")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        collection["value"].as_array().map(Vec::len),
        Some(1),
        "only the observations of that one datastream"
    );

    let observation = &collection["value"][0];
    assert_eq!(observation["result"], json!(34.2));
    assert_eq!(observation["phenomenonTime"], json!("2026-09-01T10:00:00Z"));
    assert_eq!(observation["resultTime"], json!("2026-09-01T10:00:05Z"));
    assert_eq!(
        observation["@iot.id"],
        json!(format!("{URN}/pm10/2026-09-01T10:00:00Z"))
    );
    assert_eq!(
        observation["Datastream@iot.navigationLink"],
        json!(format!(
            "{HOST}/api/endpoint/{SLUG}/sta/v1.1/Datastreams('{URN}/pm10')"
        ))
    );
}

/// EP-12: the entity's `location` is its `Location`, in the GeoJSON encoding STA names.
#[tokio::test]
async fn the_entitys_geometry_is_its_location() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, collection) = get(
        gateway(&broker.url, endpoint(&[])),
        &sta(&format!("/Things('{URN}')/Locations")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let location = &collection["value"][0];
    assert_eq!(location["encodingType"], json!("application/geo+json"));
    assert_eq!(location["location"]["type"], json!("Point"));
    assert_eq!(location["location"]["coordinates"], json!([19.146, 48.736]));
}

/// An expansion is served from the page already fetched, so it costs no second query.
#[tokio::test]
async fn expand_inlines_what_the_navigation_link_would_return() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, collection) = get(
        gateway(&broker.url, endpoint(&[])),
        &sta("/Things?$expand=Datastreams,Locations"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let thing = &collection["value"][0];
    assert_eq!(thing["Datastreams"].as_array().map(Vec::len), Some(2));
    assert_eq!(thing["Locations"].as_array().map(Vec::len), Some(1));
    assert_eq!(thing["Datastreams@iot.navigationLink"], Value::Null);
    assert_eq!(
        broker
            .hops()
            .iter()
            .filter(|hop| hop.path == "/ngsi-ld/v1/entities")
            .count(),
        1,
        "an expansion is a view of the page, not a second query"
    );
}

/// EP-13: an attribute with no numeric value is not a measurement, so it is not a datastream
/// and not an observation. It is still visible where STA puts what it has no slot for.
#[tokio::test]
async fn a_non_numeric_attribute_is_not_a_datastream() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (_, collection) = get(gateway(&broker.url, endpoint(&[])), &sta("/Observations")).await;
    let names: Vec<&str> = collection["value"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|observation| observation["@iot.id"].as_str())
        .collect();
    assert!(
        !names
            .iter()
            .any(|id| id.contains("refDevice") || id.contains("/name")),
        "a relationship and a label are not observations: {names:?}"
    );

    let one = BrokerStub::start(vec![json!([station()])]).await;
    let (_, thing) = get(
        gateway(&one.url, endpoint(&[])),
        &sta(&format!("/Things('{URN}')")),
    )
    .await;
    assert_eq!(
        thing["properties"]["refDevice"],
        json!("urn:ngsi-ld:Device:x")
    );
}

/// EP-07, EP-61: the four sets are views of one projected page, so what the endpoint hides is
/// missing from all of them at once.
#[tokio::test]
async fn a_hidden_attribute_is_absent_from_every_set() {
    for path in [
        "/Things",
        "/Datastreams",
        "/Observations",
        "/ObservedProperties",
    ] {
        let broker = BrokerStub::start(vec![json!([station()])]).await;
        let (_, answer) = get(
            gateway(&broker.url, endpoint(&["operatorPhone"])),
            &sta(path),
        )
        .await;
        assert!(
            !answer.to_string().contains("operatorPhone"),
            "{path} carries a hidden attribute"
        );
    }
}

/// A `$filter` becomes the same NGSI-LD `q` the other representations use, so the PDP narrows
/// it with the caller's grants rather than the gateway trusting it.
#[tokio::test]
async fn a_filter_reaches_the_broker_as_an_ngsi_ld_query() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, _) = get(
        gateway(&broker.url, endpoint(&[])),
        &sta("/Things?$filter=pm10%20gt%2020%20and%20pm25%20lt%2050"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let hop = broker
        .hops()
        .into_iter()
        .find(|hop| hop.path == "/ngsi-ld/v1/entities")
        .expect("one entity query");
    assert!(hop.query.contains("pm10%3E20"), "{}", hop.query);
    assert!(hop.query.contains("pm25%3C50"), "{}", hop.query);
    assert_eq!(hop.tenant, "ovzdusie");
}

/// A filter the translator cannot compile is refused and named, because one that is silently
/// dropped returns rows the caller asked not to see.
#[tokio::test]
async fn an_uncompilable_filter_is_refused_and_named() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, _, headers) = call(
        gateway(&broker.url, endpoint(&[])),
        Method::GET,
        &sta("/Things?$filter=geo.distance(location,POINT(1%201))%20lt%205"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        headers
            .get("x-parameter")
            .and_then(|value| value.to_str().ok()),
        Some("$filter")
    );
}

/// `$top` and `$skip` are the endpoint's own page controls under another name.
#[tokio::test]
async fn top_and_skip_become_limit_and_offset() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let (status, _) = get(
        gateway(&broker.url, endpoint(&[])),
        &sta("/Things?$top=5&$skip=10&$count=true"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let hop = broker
        .hops()
        .into_iter()
        .find(|hop| hop.path == "/ngsi-ld/v1/entities")
        .expect("one entity query");
    assert!(hop.query.contains("limit=5"), "{}", hop.query);
    assert!(hop.query.contains("offset=10"), "{}", hop.query);
}

/// EP-13: a set of the profile the platform records nothing for is empty, not missing, so a
/// conformance suite can walk the whole data model.
#[tokio::test]
async fn the_sets_with_no_data_answer_an_empty_collection() {
    for set in ["Sensors", "FeaturesOfInterest", "HistoricalLocations"] {
        let broker = BrokerStub::start(vec![json!([station()])]).await;
        let (status, answer) = get(
            gateway(&broker.url, endpoint(&[])),
            &sta(&format!("/{set}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "for {set}");
        assert_eq!(answer["value"], json!([]), "for {set}");
        assert!(
            broker.hops().is_empty(),
            "an empty set asks the broker nothing"
        );
    }
}

/// EP-13, R20: an entity the caller may not read, one that does not exist and an id that is
/// not shaped like one all answer the same 404.
#[tokio::test]
async fn an_inexpressible_or_missing_resource_answers_404() {
    for path in [
        format!("/Things('{URN}')"),
        format!("/Datastreams('{URN}/nosuch')"),
        "/Things('not-a-urn')".to_owned(),
        "/Widgets".to_owned(),
        format!("/Things('{URN}')/Widgets"),
    ] {
        let broker = BrokerStub::start(vec![json!([])]).await;
        let (status, _) = get(gateway(&broker.url, endpoint(&[])), &sta(&path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "for {path}");
    }
}

/// EP-13: the representation is read-only, on every path, with every non-safe method.
#[tokio::test]
async fn every_write_method_is_refused() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
        for path in [
            sta("/Things"),
            sta("/Observations"),
            sta(&format!("/Things('{URN}')")),
        ] {
            let (status, _, headers) =
                call(gateway(&broker.url, endpoint(&[])), method.clone(), &path).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
            assert_eq!(
                headers
                    .get(axum::http::header::ALLOW)
                    .and_then(|value| value.to_str().ok()),
                Some("GET, HEAD, OPTIONS"),
                "{method} {path}"
            );
        }
    }
    assert!(
        broker.hops().is_empty(),
        "a refused write reaches no broker"
    );
}

/// EP-05: an endpoint that does not enable the representation has no STA surface at all.
#[tokio::test]
async fn an_endpoint_without_the_representation_answers_404() {
    let broker = BrokerStub::start(vec![json!([station()])]).await;
    let mut without = endpoint(&[]);
    without.representations = vec![Representation::NgsiLd];
    let (status, _) = get(gateway(&broker.url, without), &sta("/Things")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
