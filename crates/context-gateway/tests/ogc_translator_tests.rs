//! The endpoint as a GIS client sees it (T-0159, EP-29, EP-30, EP-31, EP-32, EP-39).
//!
//! A GIS client is not a browser: it reads the landing page once, follows the `data` link,
//! remembers the collection ids and then talks only in `bbox` and `datetime` forever. So what
//! these tests hold to are the joins between documents, not their prose: a link that goes
//! nowhere, a collection id that is not the one `items` answers on, or a conformance class
//! claimed but not implemented all fail here rather than inside QGIS.
//!
//! Two properties are the reason the representation is safe at all. Every answer comes from the
//! same projected entity page the NGSI-LD surface serves, so a policy cannot be softer here.
//! And the surface has no write half: every non-safe method is refused before a path is even
//! parsed.

mod common;

use axum::body::Body;
use axum::http::{Method, Request as HttpRequest, StatusCode};
use common::BrokerStub;
use context_gateway::app::{router, Gateway};
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::{Endpoint, Space};
use jc_core::kinds::{Audience, Representation};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tower::ServiceExt;

const SLUG: &str = "mluyob4nz52lok3ssk7pgn5vwt";
const HOST: &str = "https://city.example";

fn endpoint(hidden: &[&str]) -> Endpoint {
    Endpoint {
        slug: SLUG.to_owned(),
        space: "ovzdusie".to_owned(),
        project: "ovzdusie".to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd, Representation::OgcFeatures],
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

fn space(endpoint: &Endpoint) -> Space {
    Space {
        endpoint: Arc::new(endpoint.clone()),
        title: BTreeMap::from([
            ("sk".to_owned(), "Ovzdušie".to_owned()),
            ("en".to_owned(), "Air quality".to_owned()),
        ]),
        description: BTreeMap::from([("en".to_owned(), "Municipal air quality".to_owned())]),
        is_sandbox: false,
        default_locale: Some("sk".to_owned()),
    }
}

fn gateway(broker: &str, endpoint: Endpoint) -> axum::Router {
    let space = space(&endpoint);
    let mut gateway = Gateway::new(
        Broker::new(broker),
        Box::new(PolicyPdp),
        "banskabystrica.sk",
    );
    gateway.public_url = Some(HOST.to_owned());
    router(Arc::new(gateway.serve([endpoint]).serve_spaces([space])))
}

fn station(local: &str, pm10: f64, observed: &str) -> Value {
    json!({
        "id": format!("urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:{local}"),
        "type": "AirQualityObserved",
        "pm10": { "type": "Property", "value": pm10, "observedAt": observed },
        "operatorPhone": { "type": "Property", "value": "+421 900 000 000" },
        "location": {
            "type": "GeoProperty",
            "value": { "type": "Point", "coordinates": [19.146, 48.736] }
        }
    })
}

/// A type the space holds that carries no geometry at all, which is not a Feature Collection.
fn advisory() -> Value {
    json!({
        "id": "urn:ngsi-ld:Advisory:banskabystrica.sk:ovzdusie:a-1",
        "type": "Advisory",
        "text": { "type": "Property", "value": "stay indoors" }
    })
}

async fn call(
    app: axum::Router,
    method: Method,
    path: &str,
) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
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
    let body = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("a readable body");
    (status, body.to_vec(), headers)
}

async fn get(app: axum::Router, path: &str) -> (StatusCode, Value) {
    let (status, body, _) = call(app, Method::GET, path).await;
    let parsed = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, parsed)
}

fn ogc(path: &str) -> String {
    format!("/api/endpoint/{SLUG}/ogc/features{path}")
}

fn hrefs(document: &Value, rel: &str) -> Vec<String> {
    document["links"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|link| link["rel"] == json!(rel))
        .filter_map(|link| link["href"].as_str().map(str::to_owned))
        .collect()
}

/// EP-29: the landing page is the only URL a client is given, so every door out of the
/// service has to be on it and has to be absolute.
#[tokio::test]
async fn the_landing_page_links_to_conformance_and_collections() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    let app = gateway(&broker.url, endpoint(&[]));
    let (status, landing) = get(app, &ogc("/")).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        hrefs(&landing, "conformance"),
        vec![format!(
            "{HOST}/api/endpoint/{SLUG}/ogc/features/conformance"
        )]
    );
    assert_eq!(
        hrefs(&landing, "data"),
        vec![format!(
            "{HOST}/api/endpoint/{SLUG}/ogc/features/collections"
        )]
    );
    assert_eq!(hrefs(&landing, "self").len(), 1, "exactly one self link");
    // EP-32: the title is the space's, in the locale the space declares.
    assert_eq!(landing["title"], json!("Ovzdušie"));
}

/// EP-32: a client that asks in English is answered in English, and one that asks for a
/// language nobody wrote still gets a title rather than an empty string.
#[tokio::test]
async fn the_landing_page_answers_in_the_callers_language() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    for (accept, expected) in [("en-GB,en;q=0.9", "Air quality"), ("de", "Ovzdušie")] {
        let response = gateway(&broker.url, endpoint(&[]))
            .oneshot(
                HttpRequest::builder()
                    .uri(ogc("/"))
                    .header(axum::http::header::ACCEPT_LANGUAGE, accept)
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("the gateway answers");
        let body = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .expect("a body");
        let landing: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(landing["title"], json!(expected), "for {accept}");
    }
}

/// EP-30: a claimed class is a promise a client acts on, so the list is what the code does.
#[tokio::test]
async fn the_conformance_list_claims_only_what_is_implemented() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    let (status, document) = get(gateway(&broker.url, endpoint(&[])), &ogc("/conformance")).await;
    assert_eq!(status, StatusCode::OK);

    let claimed: Vec<&str> = document["conformsTo"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(claimed.contains(&"http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core"));
    assert!(claimed.contains(&"http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson"));
    assert!(
        !claimed.iter().any(|class| class.contains("cql2")),
        "CQL2 is not implemented and must not be advertised: {claimed:?}"
    );
    assert!(
        !claimed.iter().any(|class| class.contains("oas30")),
        "there is no /api document yet: {claimed:?}"
    );
}

/// EP-31: a collection is an entity type that actually carries a geometry, and its id is the
/// type's short name so a client can build the items URL from what it read.
#[tokio::test]
async fn collections_are_the_types_that_carry_a_geometry() {
    let broker = BrokerStub::start(vec![json!([
        station("st-1", 34.2, "2026-09-01T10:00:00Z"),
        advisory()
    ])])
    .await;
    let (status, document) = get(gateway(&broker.url, endpoint(&[])), &ogc("/collections")).await;
    assert_eq!(status, StatusCode::OK);

    let ids: Vec<&str> = document["collections"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|collection| collection["id"].as_str())
        .collect();
    assert_eq!(ids, vec!["AirQualityObserved"], "Advisory has no geometry");

    let collection = &document["collections"][0];
    assert_eq!(
        hrefs(collection, "items"),
        vec![format!(
            "{HOST}/api/endpoint/{SLUG}/ogc/features/collections/AirQualityObserved/items"
        )]
    );
    assert_eq!(
        collection["crs"],
        json!([context_gateway::translators::ogc::CRS84])
    );
}

/// EP-32: the extent is what the caller's own data spans, not a guess and not the world.
#[tokio::test]
async fn a_collection_advertises_the_extent_of_the_data_the_caller_may_see() {
    let mut west = station("st-1", 34.2, "2026-09-01T10:00:00Z");
    west["location"]["value"]["coordinates"] = json!([19.10, 48.70]);
    let mut east = station("st-2", 51.0, "2026-09-03T10:00:00Z");
    east["location"]["value"]["coordinates"] = json!([19.20, 48.76]);
    let broker = BrokerStub::start(vec![json!([west, east])]).await;

    let (status, collection) = get(
        gateway(&broker.url, endpoint(&[])),
        &ogc("/collections/AirQualityObserved"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(collection["id"], json!("AirQualityObserved"));
    assert_eq!(
        collection["extent"]["spatial"]["bbox"],
        json!([[19.10, 48.70, 19.20, 48.76]])
    );
    assert_eq!(
        collection["extent"]["temporal"]["interval"],
        json!([["2026-09-01T10:00:00Z", "2026-09-03T10:00:00Z"]])
    );
}

/// EP-31, R20: a type that is not a collection here answers the same 404 as one that does not
/// exist, so a probe over type names learns nothing.
#[tokio::test]
async fn a_type_without_a_geometry_is_not_a_collection() {
    let broker = BrokerStub::start(vec![json!([advisory()])]).await;
    let (status, _) = get(
        gateway(&broker.url, endpoint(&[])),
        &ogc("/collections/Advisory"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// EP-33, EP-37, EP-38: a feature is the entity, flattened, with the way back to what it is.
#[tokio::test]
async fn items_are_features_whose_ids_are_the_entity_urns() {
    let broker =
        BrokerStub::start(vec![json!([station("st-1", 34.2, "2026-09-01T10:00:00Z")])]).await;
    let (status, page) = get(
        gateway(&broker.url, endpoint(&[])),
        &ogc("/collections/AirQualityObserved/items"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["type"], json!("FeatureCollection"));
    assert_eq!(page["numberReturned"], json!(1));

    let feature = &page["features"][0];
    let urn = "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:st-1";
    assert_eq!(feature["id"], json!(urn));
    assert_eq!(feature["geometry"]["type"], json!("Point"));
    assert_eq!(feature["properties"]["pm10"], json!(34.2));
    assert_eq!(
        hrefs(feature, "alternate"),
        vec![format!(
            "{HOST}/api/endpoint/{SLUG}/ngsi-ld/v1/entities/{urn}"
        )]
    );
}

/// EP-07, EP-61: a second representation is a second way to read, never a second set of rules.
#[tokio::test]
async fn a_hidden_attribute_is_absent_from_the_features() {
    let broker =
        BrokerStub::start(vec![json!([station("st-1", 34.2, "2026-09-01T10:00:00Z")])]).await;
    let (_, page) = get(
        gateway(&broker.url, endpoint(&["operatorPhone"])),
        &ogc("/collections/AirQualityObserved/items"),
    )
    .await;
    assert_eq!(
        page["features"][0]["properties"]["operatorPhone"],
        Value::Null
    );
    assert_eq!(page["features"][0]["properties"]["pm10"], json!(34.2));
}

/// EP-34: the two parameters a GIS client sends become the NGSI-LD query the broker answers.
#[tokio::test]
async fn bbox_and_datetime_reach_the_broker_as_an_ngsi_ld_query() {
    let broker =
        BrokerStub::start(vec![json!([station("st-1", 34.2, "2026-09-01T10:00:00Z")])]).await;
    let (status, _) = get(
        gateway(&broker.url, endpoint(&[])),
        &ogc("/collections/AirQualityObserved/items?bbox=19.10,48.70,19.20,48.76&datetime=2026-09-01T00:00:00Z/.."),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let hop = broker
        .hops()
        .into_iter()
        .find(|hop| hop.path == "/ngsi-ld/v1/entities")
        .expect("one entity query");
    assert!(hop.query.contains("georel=intersects"), "{}", hop.query);
    assert!(hop.query.contains("geometry=Polygon"), "{}", hop.query);
    assert!(hop.query.contains("timerel=after"), "{}", hop.query);
    assert_eq!(hop.tenant, "ovzdusie", "the tenant is pinned");
}

/// EP-34: a parameter the representation cannot honour is refused and named, because a client
/// that is told only "400" retries the same request.
#[tokio::test]
async fn an_unusable_parameter_is_refused_and_named() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    for (query, parameter) in [
        ("bbox=19.10,48.70", "bbox"),
        ("bbox=19.30,48.70,19.20,48.76", "bbox"),
        ("datetime=yesterday", "datetime"),
        ("crs=http://www.opengis.net/def/crs/EPSG/0/3857", "crs"),
    ] {
        let (status, body, headers) = call(
            gateway(&broker.url, endpoint(&[])),
            Method::GET,
            &ogc(&format!("/collections/AirQualityObserved/items?{query}")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "for {query}");
        assert_eq!(
            headers
                .get("x-parameter")
                .and_then(|value| value.to_str().ok()),
            Some(parameter),
            "for {query}"
        );
        assert!(!body.is_empty(), "a problem document for {query}");
    }
}

/// EP-36: a full page offers the next one, and following that link asks the broker for the
/// offset the cursor stands for.
#[tokio::test]
async fn a_full_page_offers_an_opaque_next_link() {
    let stations: Vec<Value> = (1..=2)
        .map(|n| {
            station(
                &format!("st-{n}"),
                30.0 + f64::from(n),
                "2026-09-01T10:00:00Z",
            )
        })
        .collect();
    let broker = BrokerStub::start(vec![json!(stations)]).await;
    let (_, page) = get(
        gateway(&broker.url, endpoint(&[])),
        &ogc("/collections/AirQualityObserved/items?limit=2"),
    )
    .await;

    let next = hrefs(&page, "next");
    let next = next.first().expect("a next link on a full page");
    assert!(
        next.contains("limit=2"),
        "the query is carried over: {next}"
    );
    let cursor = next
        .rsplit_once("next=")
        .map(|(_, cursor)| cursor.to_owned())
        .expect("a cursor");
    assert!(
        !cursor.contains('='),
        "the cursor is opaque, not an offset in the clear: {cursor}"
    );

    let follow = BrokerStub::start(vec![json!([])]).await;
    let (status, _) = get(
        gateway(&follow.url, endpoint(&[])),
        &ogc(&format!(
            "/collections/AirQualityObserved/items?limit=2&next={cursor}"
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let hop = follow
        .hops()
        .into_iter()
        .find(|hop| hop.path == "/ngsi-ld/v1/entities")
        .expect("one entity query");
    assert!(hop.query.contains("offset=2"), "{}", hop.query);
}

/// A short page is the last page, so no client is sent round again for nothing.
#[tokio::test]
async fn a_short_page_offers_no_next_link() {
    let broker =
        BrokerStub::start(vec![json!([station("st-1", 34.2, "2026-09-01T10:00:00Z")])]).await;
    let (_, page) = get(
        gateway(&broker.url, endpoint(&[])),
        &ogc("/collections/AirQualityObserved/items?limit=10"),
    )
    .await;
    assert!(hrefs(&page, "next").is_empty());
}

/// EP-33, R20: an entity the caller may not read and one that does not exist answer alike.
#[tokio::test]
async fn a_feature_that_is_not_there_answers_404() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    let (status, _) = get(
        gateway(&broker.url, endpoint(&[])),
        &ogc("/collections/AirQualityObserved/items/urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:nope"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// EP-39: the representation has no write half, on any path, with any method.
#[tokio::test]
async fn every_non_safe_method_is_refused() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        for path in [
            ogc("/"),
            ogc("/collections"),
            ogc("/collections/AirQualityObserved/items"),
        ] {
            let (status, _, headers) =
                call(gateway(&broker.url, endpoint(&[])), method.clone(), &path).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
            assert_eq!(
                headers
                    .get(axum::http::header::ALLOW)
                    .and_then(|v| v.to_str().ok()),
                Some("GET, HEAD, OPTIONS"),
                "{method} {path}"
            );
        }
    }
    assert!(
        broker.hops().is_empty(),
        "a refused method reaches no broker"
    );
}

/// A client discovers the read-only fact rather than guessing it.
#[tokio::test]
async fn options_answers_with_the_safe_methods() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    let (status, _, headers) = call(
        gateway(&broker.url, endpoint(&[])),
        Method::OPTIONS,
        &ogc("/collections"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        headers
            .get(axum::http::header::ALLOW)
            .and_then(|v| v.to_str().ok()),
        Some("GET, HEAD, OPTIONS")
    );
}

/// EP-05: an endpoint that does not enable the representation has no OGC surface at all, and
/// says so the same way an unknown slug does.
#[tokio::test]
async fn an_endpoint_without_the_representation_answers_404() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    let mut without = endpoint(&[]);
    without.representations = vec![Representation::NgsiLd];
    let (status, _) = get(gateway(&broker.url, without), &ogc("/collections")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A path off the Core tree is not a resource, however plausible it looks.
#[tokio::test]
async fn an_unmapped_path_answers_404() {
    let broker = BrokerStub::start(vec![json!([])]).await;
    for path in [
        "/collections/X/items/y/z",
        "/api",
        "/collections/X/queryables",
    ] {
        let (status, _) = get(gateway(&broker.url, endpoint(&[])), &ogc(path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "for {path}");
    }
}

/// Belt and braces on the fixture: the endpoint under test really does hide nothing by
/// default, so the projection tests above are measuring the policy and not the fixture.
#[test]
fn the_fixture_hides_nothing_by_default() {
    assert_eq!(endpoint(&[]).hidden_attributes, BTreeSet::new());
}
