//! The gateway in front of a real broker (T-0005).
//!
//! Everything else about the gateway is tested against its own types. This one starts
//! Antares in Docker and drives the whole path — resolve, decide, guard, forward, project
//! — because the interesting failures are the ones at the seam: a header the broker does
//! not get, a query parameter it does not understand, a status the gateway swallows.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use context_gateway::app::{router, Gateway};
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::Endpoint;
use jc_core::kinds::{Audience, PolicySpec, Representation};
use serde_json::{json, Value};
use std::process::Command;
use tower::ServiceExt;

const IMAGE: &str = "ghcr.io/marek-mraz/antares-broker:dev";
const SPACE: &str = "ovzdusie";
const ORG: &str = "banskabystrica.sk";
const PUBLIC_SLUG: &str = "k4y7pq2mzt6vhx3nbwrs5cjd8f";
const MEMBERS_SLUG: &str = "t9x2wqvn7mzc4hd6bkp3rjs5ga";
const STATION: &str =
    "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:station-integration-01";

/// A broker container that stops when the test ends, however the test ends.
struct Antares {
    id: String,
    port: u16,
}

impl Antares {
    /// Starts the broker on a free port and waits until it answers its own health probe.
    ///
    /// `None` means Docker is not available here, which is a skipped test rather than a
    /// failed one: the assertion is about the gateway, not about the sandbox.
    fn start() -> Option<Self> {
        if !Command::new("docker")
            .arg("version")
            .output()
            .is_ok_and(|out| out.status.success())
        {
            eprintln!("skipped: no Docker in this environment");
            return None;
        }

        let run = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "-p",
                "127.0.0.1:0:9090",
                "-e",
                "ANTARES_STORE=memory",
                IMAGE,
            ])
            .output()
            .expect("docker run is callable");
        assert!(
            run.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let id = String::from_utf8_lossy(&run.stdout).trim().to_owned();

        let published = Command::new("docker")
            .args(["port", &id, "9090/tcp"])
            .output()
            .expect("docker port is callable");
        let port = String::from_utf8_lossy(&published.stdout)
            .lines()
            .next()
            .and_then(|line| line.rsplit(':').next().map(str::to_owned))
            .and_then(|port| port.trim().parse().ok())
            .unwrap_or_else(|| {
                panic!(
                    "no published port: {}",
                    String::from_utf8_lossy(&published.stdout)
                )
            });

        let broker = Self { id, port };
        broker.await_health();
        Some(broker)
    }

    fn await_health(&self) {
        let url = format!("http://127.0.0.1:{}/q/health", self.port);
        for _ in 0..120 {
            let probe = Command::new("docker")
                .args(["exec", &self.id, "/antares", "--health"])
                .output();
            if probe.is_ok_and(|out| out.status.success()) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        panic!("{url} never became healthy");
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Antares {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

/// The grant DEMO step 4 describes: an anonymous caller may read and write three
/// attributes of one type in this space, and nothing else.
fn public_grant() -> PolicySpec {
    serde_norway::from_str(
        r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity, retrieveEntity, createEntity, deleteEntity]
information:
  - entities:
      - type: AirQualityObserved
        idPattern: "^urn:ngsi-ld:AirQualityObserved:banskabystrica\\.sk:ovzdusie:.*$"
    propertyNames: [pm10, pm25, location]
"#,
    )
    .expect("the grant parses")
}

fn endpoint(slug: &str, audience: Audience) -> Endpoint {
    Endpoint {
        slug: slug.to_owned(),
        space: SPACE.to_owned(),
        project: SPACE.to_owned(),
        audience,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd],
        rate_limit: None,
        policies: vec![public_grant()],
    }
}

fn gateway(broker_url: String) -> axum::Router {
    let gateway = Gateway::new(Broker::new(broker_url), Box::new(PolicyPdp), ORG).serve([
        endpoint(PUBLIC_SLUG, Audience::Public),
        endpoint(MEMBERS_SLUG, Audience::Organization),
    ]);
    router(std::sync::Arc::new(gateway))
}

fn station(extra: Option<(&str, Value)>) -> Value {
    let mut entity = json!({
        "id": STATION,
        "type": "AirQualityObserved",
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context-v1.8.jsonld",
        "pm10": { "type": "Property", "value": 34.2 },
        "pm25": { "type": "Property", "value": 12.0 },
        "location": {
            "type": "GeoProperty",
            "value": { "type": "Point", "coordinates": [19.15, 48.73] }
        }
    });
    if let Some((name, value)) = extra {
        entity[name] = value;
    }
    entity
}

async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("the gateway answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("a readable body");
    (status, body.to_vec())
}

fn post(slug: &str, path: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/endpoint/{slug}/ngsi-ld/v1{path}"))
        .header("content-type", "application/ld+json")
        .body(Body::from(body.to_string()))
        .expect("a request")
}

fn get(slug: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/api/endpoint/{slug}/ngsi-ld/v1{path}"))
        .header("accept", "application/ld+json")
        .body(Body::empty())
        .expect("a request")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_whole_path_through_the_gateway_to_a_real_broker() {
    let Some(antares) = Antares::start() else {
        return;
    };
    let app = gateway(antares.url());

    // Create, through the endpoint and its grant.
    let (status, body) = call(&app, post(PUBLIC_SLUG, "/entities", &station(None))).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create: {}",
        String::from_utf8_lossy(&body)
    );

    // Read it back. The broker holds it under the tenant the gateway pinned, which the
    // client never named.
    let (status, body) = call(&app, get(PUBLIC_SLUG, &format!("/entities/{STATION}"))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "read: {}",
        String::from_utf8_lossy(&body)
    );
    let entity: Value = serde_json::from_slice(&body).expect("an entity");
    assert_eq!(entity["id"], json!(STATION));
    assert_eq!(entity["pm10"]["value"], json!(34.2));

    // Query it back the way DEMO step 4 does.
    let (status, body) = call(&app, get(PUBLIC_SLUG, "/entities?type=AirQualityObserved")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "query: {}",
        String::from_utf8_lossy(&body)
    );
    let entities: Value = serde_json::from_slice(&body).expect("a list");
    assert_eq!(entities.as_array().map(Vec::len), Some(1));

    // An attribute outside the grant never reaches the wire, whichever way it is asked
    // for (R9).
    let (status, body) = call(
        &app,
        get(
            PUBLIC_SLUG,
            &format!("/entities/{STATION}?attrs=operatorPhone"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let entity: Value = serde_json::from_slice(&body).expect("an entity");
    assert!(entity.get("operatorPhone").is_none());

    // A write that touches an attribute outside the grant is refused whole (GW17).
    let refused = station(Some((
        "operatorPhone",
        json!({ "type": "Property", "value": "+421 900 000 000" }),
    )));
    let (status, _) = call(&app, post(PUBLIC_SLUG, "/entities", &refused)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An operation outside the grant is refused, and the body says nothing about the rule
    // (GW6).
    let (status, body) = call(
        &app,
        Request::builder()
            .method("PATCH")
            .uri(format!(
                "/api/endpoint/{PUBLIC_SLUG}/ngsi-ld/v1/entities/{STATION}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "pm10": 1.0 }).to_string()))
            .expect("a request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let problem: Value = serde_json::from_slice(&body).expect("problem+json");
    assert_eq!(problem["status"], json!(403));
    assert!(problem["type"]
        .as_str()
        .is_some_and(|t| t.ends_with("forbidden")));
    assert!(
        problem.get("detail").is_none(),
        "the body must not name the rule"
    );

    // A write into another organization's URN space is a bad request (PF-10, PF-42).
    let mut foreign = station(None);
    foreign["id"] = json!("urn:ngsi-ld:AirQualityObserved:zilina.sk:ovzdusie:station-01");
    let (status, body) = call(&app, post(PUBLIC_SLUG, "/entities", &foreign)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let problem: Value = serde_json::from_slice(&body).expect("problem+json");
    assert!(problem["type"]
        .as_str()
        .is_some_and(|t| t.ends_with("urn-scheme")));

    // An endpoint the anonymous caller is not the audience of answers 401, not 403: it is
    // a missing identity, not a refused one (EP-14).
    let (status, _) = call(&app, get(MEMBERS_SLUG, "/entities?type=AirQualityObserved")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A slug nobody issued is a miss, and so is a path off the NGSI-LD resource tree
    // (EP-03).
    let (status, _) = call(&app, get("nosuchslugnosuchslugnosuchsl", "/entities")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&app, get(PUBLIC_SLUG, "/admin/shutdown")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Delete, and it is gone.
    let (status, body) = call(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/endpoint/{PUBLIC_SLUG}/ngsi-ld/v1/entities/{STATION}"
            ))
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "delete: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, _) = call(&app, get(PUBLIC_SLUG, &format!("/entities/{STATION}"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The probes the deployment uses answer before any endpoint exists (OPS-12).
#[tokio::test]
async fn the_health_probes_need_no_endpoints_and_no_broker() {
    let app = router(std::sync::Arc::new(Gateway::new(
        Broker::new("http://127.0.0.1:1"),
        Box::new(PolicyPdp),
        ORG,
    )));
    for probe in ["/healthz", "/livez"] {
        let (status, body) = call(&app, get_raw(probe)).await;
        assert_eq!(status, StatusCode::OK, "{probe}");
        assert_eq!(body, b"ok");
    }
}

fn get_raw(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("a request")
}
