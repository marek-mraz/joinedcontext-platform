//! T-0345: what a hub endpoint does that an ordinary endpoint does not (EP-70, EP-71, PF-48).
//!
//! Almost nothing, which is the point. A space that holds registrations is served by the same
//! resolve → decide → pin → forward path as any other, because the merging is CIM 009 clause
//! 4.3.6 and the broker's job. Three things are the gateway's, and they are what is asserted
//! here: a partial answer reaches the caller as the broker sent it, provenance survives the
//! masking the hub's own policy applies, and a registration this platform cannot honour yet
//! stops the read instead of quietly answering as somebody else.

mod common;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::any;
use axum::Router;
use context_gateway::app::{router, Gateway};
use context_gateway::federation::{federations_of, Federations, Member};
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::Endpoint;
use jc_core::kinds::{Audience, FederationIdentity, PolicySpec, Representation};
use jcctl::loader::Repository;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const HUB_SLUG: &str = "h4y7pq2mzt6vhx3nbwrs5cjd8f";
const PROJECT: &str = "helsinki";
const HUB: &str = "hub";

/// The one thing a hub's own policy takes away, to prove masking still applies to a merged
/// answer (GW17, EP-61).
const HIDDEN: &str = "occupancy";

/// The registration that answered, as the broker names a part: its id, which carries the
/// manifest name and never an address (EP-71).
const SOURCE: &str = "urn:ngsi-ld:ContextSourceRegistration:transport";

fn policy() -> PolicySpec {
    serde_norway::from_str(&format!(
        r#"contextSpaceRef: {HUB}
assigner: did:web:helsinki.fi
assignee: {{ kind: role, id: public }}
operations: [queryEntity, retrieveEntity]
information:
  - entities:
      - type: Vehicle
    propertyNames:
      - location
      - speed
"#
    ))
    .expect("the policy spec parses")
}

fn hub_endpoint() -> Endpoint {
    Endpoint {
        slug: HUB_SLUG.to_owned(),
        space: HUB.to_owned(),
        project: PROJECT.to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd],
        rate_limit: None,
        file_limits: None,
        hidden_attributes: [HIDDEN.to_owned()].into_iter().collect(),
        base_path: format!("/api/endpoint/{HUB_SLUG}"),
        models: Vec::new(),
        policies: vec![policy()],
    }
}

fn member(name: &str, identity: FederationIdentity) -> Member {
    Member {
        name: name.to_owned(),
        identity,
        external: false,
    }
}

/// A federation table built by hand, which is what the repository would build.
fn table(members: Vec<Member>) -> Federations {
    let repo = written(&members);
    let built = federations_of(&repo);
    assert_eq!(
        built.members(PROJECT, HUB).len(),
        members.len(),
        "the fixture and the loader disagree about what a repository says"
    );
    built
}

/// The same registrations as manifests on disk, so the table under test is the one the
/// gateway really builds and not one the test invented.
fn written(members: &[Member]) -> Repository {
    let dir = tempdir();
    let registrations = dir
        .join("projects")
        .join(PROJECT)
        .join("spaces")
        .join(HUB)
        .join("registrations");
    std::fs::create_dir_all(&registrations).expect("the repository directory");
    for member in members {
        let account = match member.identity {
            FederationIdentity::ServiceAccount => {
                "\n    serviceAccountRef: { kind: ServiceAccount, name: hub-reader }"
            }
            FederationIdentity::Caller => "",
        };
        let identity = match member.identity {
            FederationIdentity::ServiceAccount => "serviceAccount",
            FederationIdentity::Caller => "caller",
        };
        let target = if member.external {
            "  endpoint: https://other.example/ngsi-ld/v1".to_owned()
        } else {
            format!(
                "  endpointRef: {{ kind: Endpoint, name: {}-internal }}",
                member.name
            )
        };
        std::fs::write(
            registrations.join(format!("{}.yaml", member.name)),
            format!(
                "apiVersion: joinedcontext.com/v1alpha1\n\
                 kind: ContextSourceRegistration\n\
                 metadata:\n  name: {name}\n  namespace: {PROJECT}\n\
                 spec:\n  contextSpaceRef: {HUB}\n{target}\n\
                 \x20 information:\n    - entities:\n        - type: Vehicle\n\
                 \x20 federation:\n    identity: {identity}{account}\n",
                name = member.name,
            ),
        )
        .expect("the registration is written");
    }
    Repository::load(&dir).expect("the repository loads")
}

/// A directory of this test's own, removed by the operating system rather than by a `Drop`
/// nobody would see fail.
fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "jc-hub-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    dir
}

type Calls = Arc<Mutex<Vec<String>>>;

/// A broker that answers the way a merge over two members answers: `207`, a warning naming
/// the member that did not answer, and the entities of the one that did.
async fn partial_broker() -> (String, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::clone(&calls);
    let app = Router::new()
        .fallback(any(
            |State(calls): State<Calls>, request: Request<Body>| async move {
                calls
                    .lock()
                    .expect("the call log")
                    .push(request.uri().to_string());
                let body = json!([
                    {
                        "id": "urn:ngsi-ld:Vehicle:helsinki.fi:transport:bus-17",
                        "type": "Vehicle",
                        "createdAt": "2026-09-01T06:00:00Z",
                        "modifiedAt": "2026-09-06T08:12:00Z",
                        "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [24.9, 60.1] } },
                        "speed": { "type": "Property", "value": 31 },
                        "occupancy": { "type": "Property", "value": 0.8 }
                    }
                ]);
                let mut headers = HeaderMap::new();
                headers.insert("content-type", "application/json".parse().expect("a value"));
                headers.insert(
                    "ngsild-warning",
                    format!("199 {SOURCE} \"the source did not answer in time\"")
                        .parse()
                        .expect("a value"),
                );
                (StatusCode::MULTI_STATUS, headers, body.to_string())
            },
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let address = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), calls)
}

fn gateway(broker: &str, federations: Federations) -> Arc<Gateway> {
    let gateway = Gateway::new(Broker::new(broker), Box::new(PolicyPdp), "helsinki.fi");
    let gateway = gateway.serve([hub_endpoint()]);
    gateway.replace_federation(federations);
    Arc::new(gateway)
}

async fn query(broker: &str, federations: Federations) -> (StatusCode, HeaderMap, Value) {
    let response = router(gateway(broker, federations))
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/endpoint/{HUB_SLUG}/ngsi-ld/v1/entities?type=Vehicle&options=sysAttrs"
                ))
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the gateway answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a body");
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// EP-70: a source that failed does not fail the request. The status and the warning are the
/// broker's, passed through, because only the broker knows which part did not answer.
#[tokio::test]
async fn a_partial_merge_reaches_the_caller_as_the_broker_sent_it() {
    let (broker, _) = partial_broker().await;
    let (status, headers, body) = query(
        &broker,
        table(vec![member(
            "transport",
            FederationIdentity::ServiceAccount,
        )]),
    )
    .await;

    assert_eq!(status, StatusCode::MULTI_STATUS);
    let warning = headers
        .get("ngsild-warning")
        .and_then(|value| value.to_str().ok())
        .expect("the warning survives");
    assert!(
        warning.contains(SOURCE),
        "the warning names the part: {warning}"
    );
    assert!(
        !warning.contains("http://") && !warning.contains("https://"),
        "a warning must not carry a member's address: {warning}"
    );
    assert_eq!(body.as_array().map(Vec::len), Some(1), "{body}");
}

/// EP-71: provenance is what the broker generated, and a grant is about data. The hub's
/// policy still masks a merged answer, and the system attributes still arrive.
#[tokio::test]
async fn masking_applies_to_a_merged_answer_and_provenance_survives_it() {
    let (broker, _) = partial_broker().await;
    let (_, _, body) = query(
        &broker,
        table(vec![member(
            "transport",
            FederationIdentity::ServiceAccount,
        )]),
    )
    .await;

    let entity = &body[0];
    assert!(
        entity.get("location").is_some(),
        "a granted attribute: {entity}"
    );
    assert!(
        entity.get("speed").is_some(),
        "a granted attribute: {entity}"
    );
    assert!(
        entity.get(HIDDEN).is_none(),
        "the endpoint hides {HIDDEN} whatever the merge returned: {entity}"
    );
    assert_eq!(entity["createdAt"], json!("2026-09-01T06:00:00Z"));
    assert_eq!(entity["modifiedAt"], json!("2026-09-06T08:12:00Z"));
}

/// PF-48: `caller` identity needs an RFC 8693 exchange this platform does not have. Answering
/// as the hub's own account instead would hand back data the caller was never granted on the
/// member, so the read stops and says so.
#[tokio::test]
async fn a_registration_that_forwards_the_callers_token_is_not_served_yet() {
    let (broker, calls) = partial_broker().await;
    let (status, _, body) = query(
        &broker,
        table(vec![
            member("transport", FederationIdentity::ServiceAccount),
            member("air-quality", FederationIdentity::Caller),
        ]),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["status"], json!(501));
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("serviceAccount"),
        "the refusal says which mode is served: {detail}"
    );
    assert!(
        calls.lock().expect("the call log").is_empty(),
        "nothing was forwarded, so no member answered a request the platform cannot attribute"
    );
}

/// A space with no registration at all is not a hub and is served the way it always was.
#[tokio::test]
async fn a_space_that_federates_nothing_is_served_unchanged() {
    let (broker, calls) = partial_broker().await;
    let (status, _, _) = query(&broker, Federations::new()).await;

    assert_eq!(status, StatusCode::MULTI_STATUS);
    let calls = calls.lock().expect("the call log");
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].contains("type=Vehicle"), "{calls:?}");
}

/// CC-08: the table is a projection of the repository, and a registration the loader cannot
/// make sense of is left out rather than half-applied.
#[test]
fn the_table_is_what_the_repository_says_and_nothing_else() {
    let members = vec![
        member("transport", FederationIdentity::ServiceAccount),
        Member {
            name: "regional".to_owned(),
            identity: FederationIdentity::Caller,
            external: true,
        },
    ];
    let table = federations_of(&written(&members));

    assert!(table.is_federated(PROJECT, HUB));
    assert!(!table.is_federated(PROJECT, "air-quality"));
    assert_eq!(
        table.needing_caller_identity(PROJECT, HUB),
        vec!["regional"],
        "only the registration that asks for it"
    );
    let names: Vec<&str> = table
        .members(PROJECT, HUB)
        .iter()
        .map(|member| member.name.as_str())
        .collect();
    assert_eq!(names, vec!["regional", "transport"]);
    assert!(
        table.members(PROJECT, HUB)[0].external,
        "a source elsewhere is marked as one"
    );
}
