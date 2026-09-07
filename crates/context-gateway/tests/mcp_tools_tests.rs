//! T-0335, T-0336: the Data MCP covers the CIM 009 read surface, validates what it is
//! given, and can be reached from a phone (AG-05, AG-07, AG-29…AG-32, EP-52, EP-60).

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use context_gateway::app::{router, Gateway};
use context_gateway::auth::accounts::ServiceAccounts;
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::{Endpoint, Model, Space};
use jc_core::kinds::{Audience, PolicySpec, Representation};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const PUBLIC: &str = "k4y7pq2mzt6vhx3nbwrs5cjd8f";
const PRIVATE: &str = "zt4qm7ge2xdv6ksb3ncf5arw2y";
const HOST: &str = "https://city.example";
const ENTITY: &str = "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:st-1";

fn policy(yaml: &str) -> PolicySpec {
    serde_norway::from_str(yaml).expect("the policy spec parses")
}

/// Everything the anonymous caller may do on the demo space: read entities, list the
/// types and the attributes, read history, and query in batch.
fn public_grant() -> PolicySpec {
    policy(
        r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations:
  - queryEntity
  - retrieveEntity
  - retrieveEntityTypes
  - retrieveEntityTypeDetails
  - retrieveAttrTypes
  - queryTemporal
  - retrieveTemporal
  - queryBatch
information:
  - entities:
      - type: AirQualityObserved
    propertyNames: [pm10, pm25, location]
"#,
    )
}

fn endpoint(slug: &str, audience: Audience) -> Endpoint {
    Endpoint {
        slug: slug.to_owned(),
        space: "ovzdusie".to_owned(),
        project: "ovzdusie".to_owned(),
        audience,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd, Representation::Mcp],
        rate_limit: None,
        file_limits: None,
        hidden_attributes: Default::default(),
        view_mapping: None,
        base_path: format!("/api/endpoint/{slug}"),
        models: vec![Model {
            name: "air-quality".to_owned(),
            version: "1.0.0".to_owned(),
            major: 1,
            classes: vec!["AirQualityObserved".to_owned()],
            json_schema: None,
            context: None,
        }],
        policies: vec![public_grant()],
    }
}

/// The canonical space surface, which runs the same façade under `/cs/{space}` (SP-14).
fn space() -> Space {
    let mut record = endpoint("ovzdusie", Audience::Public);
    record.base_path = "/cs/ovzdusie".to_owned();
    Space {
        endpoint: Arc::new(record),
        title: Default::default(),
        description: Default::default(),
        is_sandbox: false,
        default_locale: None,
    }
}

fn gateway(broker: &str, realm: &common::Realm) -> Arc<Gateway> {
    Arc::new(
        Gateway::new(
            Broker::new(broker),
            Box::new(PolicyPdp),
            "banskabystrica.sk",
        )
        .serve([
            endpoint(PUBLIC, Audience::Public),
            endpoint(PRIVATE, Audience::Organization),
        ])
        .serve_spaces([space()])
        .authenticate(
            Arc::new(realm.verifier()),
            ServiceAccounts::new(),
            Some(HOST.to_owned()),
        ),
    )
}

fn app(broker: &str, realm: &common::Realm) -> Router {
    router(gateway(broker, realm))
}

fn message(path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder
        .body(Body::from(body.to_string()))
        .expect("a request")
}

fn call(name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    })
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, Value, axum::http::HeaderMap) {
    let response = app.oneshot(request).await.expect("the gateway answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a body");
    let payload = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, payload, headers)
}

/// AG-29: every CIM 009 read the endpoint serves has a tool, and the list is the grant.
#[tokio::test]
async fn the_catalogue_covers_the_read_surface_and_annotates_every_tool() {
    let realm = common::Realm::new();
    let (_, answer, _) = send(
        app("http://127.0.0.1:1", &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ),
    )
    .await;

    let tools = answer["result"]["tools"].as_array().expect("a tool list");
    let mut names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "batch_query",
            "describe_access",
            "describe_schema",
            "get_entity",
            "list_attributes",
            "list_types",
            "query_entities",
            "query_temporal",
            "retrieve_temporal",
        ],
        "the anonymous grant names seven read operations, and two tools describe the endpoint"
    );

    // AG-07: an agent runtime decides whether to ask a human from these, so they have to
    // be there and they have to be right.
    for tool in tools {
        assert_eq!(
            tool["annotations"]["readOnlyHint"],
            json!(true),
            "{} is a read and must say so",
            tool["name"]
        );
        assert_eq!(tool["inputSchema"]["additionalProperties"], json!(false));
    }
}

/// AG-31: an argument the schema does not know is refused before anything is built.
#[tokio::test]
async fn an_unknown_argument_is_a_tool_error_and_never_a_broker_call() {
    let realm = common::Realm::new();
    let broker = common::BrokerStub::start(vec![json!([])]).await;

    let (_, answer, _) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            call(
                "query_entities",
                json!({ "type": "AirQualityObserved", "linit": 5 }),
            ),
        ),
    )
    .await;

    assert_eq!(answer["result"]["isError"], json!(true));
    let text = answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("linit"),
        "the refusal must name the argument the caller got wrong: {text}"
    );
    assert!(
        broker.hops().is_empty(),
        "a request that fails validation must never reach the broker (AG-21)"
    );

    // A type outside the schema is refused by the same check.
    let (_, wrong_type, _) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            call("query_entities", json!({ "type": 7 })),
        ),
    )
    .await;
    assert_eq!(wrong_type["result"]["isError"], json!(true));
    assert!(broker.hops().is_empty());
}

/// AG-30: the temporal grammar reaches the broker unchanged, on the temporal path.
#[tokio::test]
async fn the_temporal_tools_forward_the_whole_grammar_to_the_temporal_api() {
    let realm = common::Realm::new();
    let broker = common::BrokerStub::start(vec![json!([])]).await;

    send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            call(
                "query_temporal",
                json!({
                    "type": "AirQualityObserved",
                    "timerel": "between",
                    "timeAt": "2026-09-01T00:00:00Z",
                    "endTimeAt": "2026-09-02T00:00:00Z",
                    "lastN": 2,
                    "aggrMethods": ["avg", "max"],
                    "aggrPeriodDuration": "PT1H",
                    "attrs": ["pm10"],
                }),
            ),
        ),
    )
    .await;

    let hop = broker.hops().pop().expect("the broker was called");
    assert_eq!(hop.path, "/ngsi-ld/v1/temporal/entities");
    assert_eq!(
        hop.tenant, "ovzdusie",
        "the space is pinned, never asked for"
    );
    for expected in [
        "timerel=between",
        "endTimeAt=2026-09-02T00%3A00%3A00Z",
        "lastN=2",
        "aggrMethods=avg%2Cmax",
        "aggrPeriodDuration=PT1H",
    ] {
        assert!(
            hop.query.contains(expected),
            "{expected} must survive the trip: {}",
            hop.query
        );
    }

    // The one entity's history is the other CIM 009 operation, and therefore the other
    // tool: the path follows the tool, never an argument that happens to be present.
    send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            call(
                "retrieve_temporal",
                json!({ "id": ENTITY, "timerel": "after", "timeAt": "2026-09-01T00:00:00Z" }),
            ),
        ),
    )
    .await;
    let hop = broker.hops().pop().expect("the broker was called again");
    assert!(
        hop.path.starts_with("/ngsi-ld/v1/temporal/entities/urn"),
        "one entity's history is a path, not a filter: {}",
        hop.path
    );
}

/// AG-29: the type and attribute listings, and the batch query, are the operations they
/// say they are.
#[tokio::test]
async fn the_listing_and_batch_tools_make_the_requests_they_stand_for() {
    let realm = common::Realm::new();
    let broker = common::BrokerStub::start(vec![json!([])]).await;

    send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            call("list_types", json!({ "details": true })),
        ),
    )
    .await;
    let hop = broker.hops().pop().expect("a hop");
    assert_eq!(hop.path, "/ngsi-ld/v1/types");
    assert!(
        hop.query.contains("details=true"),
        "the details flag is the difference between the two type operations: {}",
        hop.query
    );

    send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            call("list_attributes", json!({})),
        ),
    )
    .await;
    assert_eq!(
        broker.hops().pop().expect("a hop").path,
        "/ngsi-ld/v1/attributes"
    );

    send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            call("batch_query", json!({ "ids": [ENTITY], "attrs": ["pm10"] })),
        ),
    )
    .await;
    let hop = broker.hops().pop().expect("a hop");
    assert_eq!(hop.path, "/ngsi-ld/v1/entityOperations/query");
}

/// EP-52, EP-60: the resources are the types, the grant document and the schema, and one
/// naming another space is not a way to read it (AG-05).
#[tokio::test]
async fn resources_list_what_the_caller_may_read_and_never_another_space() {
    let realm = common::Realm::new();
    let broker = common::BrokerStub::start(vec![json!([{ "id": ENTITY }])]).await;

    let (_, listed, _) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" }),
        ),
    )
    .await;
    let uris: Vec<&str> = listed["result"]["resources"]
        .as_array()
        .expect("a resource list")
        .iter()
        .map(|resource| resource["uri"].as_str().unwrap_or_default())
        .collect();
    assert!(uris.contains(&"ngsi-ld://ovzdusie/types/AirQualityObserved"));
    assert!(uris.contains(&format!("access://{PUBLIC}").as_str()));
    assert!(uris.iter().any(|uri| uri.starts_with("schema://")));

    // The grant document is answered from the endpoint itself, with no broker hop.
    let before = broker.hops().len();
    let (_, grants, _) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": { "uri": format!("access://{PUBLIC}") },
            }),
        ),
    )
    .await;
    assert!(grants["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .contains("AirQualityObserved"));
    assert_eq!(broker.hops().len(), before, "the access document is local");

    // A URI for a space this endpoint does not serve is an unknown resource, which is
    // what a URI nobody defined is too (SP-20, R20).
    let (_, foreign, _) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": { "uri": "ngsi-ld://doprava/types/Vehicle" },
            }),
        ),
    )
    .await;
    assert_eq!(foreign["error"]["code"], json!(-32602));
    assert_eq!(foreign["error"]["message"], json!("unknown resource"));
}

/// AG-08: a subscription outlives the conversation, so the operator has to have said yes.
#[tokio::test]
async fn creating_a_subscription_needs_the_operators_confirmation_first() {
    let realm = common::Realm::new();
    let broker = common::BrokerStub::start(vec![json!({})]).await;
    // The public grant does not include it, so it is not even advertised.
    let (_, listed, _) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ),
    )
    .await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default())
        .collect();
    assert!(!names.contains(&"create_subscription"));

    // Calling it by name answers as an undefined tool does, and reaches nothing.
    let (_, refused, _) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            call("create_subscription", json!({ "subscription": {} })),
        ),
    )
    .await;
    assert_eq!(refused["error"]["message"], json!("unknown tool"));
    assert!(broker.hops().is_empty());
}

/// AG-32: a phone with no token is told where its authorization server is.
#[tokio::test]
async fn an_unauthenticated_call_names_the_resource_metadata_and_a_public_one_does_not() {
    let realm = common::Realm::new();
    let broker = common::BrokerStub::start(vec![json!([])]).await;

    let (status, _, headers) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PRIVATE}/mcp"),
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert_eq!(
        challenge,
        format!(
            "Bearer resource_metadata=\"{HOST}/api/endpoint/{PRIVATE}/.well-known/oauth-protected-resource\""
        )
    );

    // An unknown slug answers exactly the same, so the challenge discloses nothing (R20).
    let (unknown_status, _, unknown_headers) = send(
        app(&broker.url, &realm),
        message(
            "/api/endpoint/aaaaaaaaaaaaaaaaaaaaaaaaaa/mcp",
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ),
    )
    .await;
    assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);
    assert!(
        unknown_headers.get("www-authenticate").is_some(),
        "an endpoint that needs a login and one that does not exist answer alike"
    );

    // The public endpoint needs no token at all: a phone connects with one paste.
    let (public_status, answer, _) = send(
        app(&broker.url, &realm),
        message(
            &format!("/api/endpoint/{PUBLIC}/mcp"),
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ),
    )
    .await;
    assert_eq!(public_status, StatusCode::OK);
    assert!(answer["result"]["tools"]
        .as_array()
        .is_some_and(|tools| !tools.is_empty()));
}

/// AG-32: the protected-resource document is RFC 9728 shaped and names the realm.
#[tokio::test]
async fn the_protected_resource_metadata_names_the_realm_for_every_slug() {
    let realm = common::Realm::new();
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/endpoint/{PRIVATE}/.well-known/oauth-protected-resource"
        ))
        .body(Body::empty())
        .expect("a request");
    let (status, document, _) = send(app("http://127.0.0.1:1", &realm), request).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        document["resource"],
        json!(format!("{HOST}/api/endpoint/{PRIVATE}/mcp"))
    );
    assert!(document["authorization_servers"][0].as_str().is_some());
    assert_eq!(document["bearer_methods_supported"], json!(["header"]));
}

/// SP-14: the space's canonical surface runs the same façade as the endpoint's.
#[tokio::test]
async fn the_space_surface_serves_the_same_tools_as_the_endpoint() {
    let realm = common::Realm::new();
    let broker = common::BrokerStub::start(vec![json!([])]).await;

    let (status, answer, _) = send(
        app(&broker.url, &realm),
        message(
            "/cs/ovzdusie/mcp",
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = answer["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default())
        .collect();
    assert!(names.contains(&"query_entities"));

    // And a tool call from the space surface reaches the broker pinned to that space.
    send(
        app(&broker.url, &realm),
        message(
            "/cs/ovzdusie/mcp",
            None,
            call("query_entities", json!({ "type": "AirQualityObserved" })),
        ),
    )
    .await;
    let hop = broker.hops().pop().expect("the broker was called");
    assert_eq!(hop.path, "/ngsi-ld/v1/entities");
    assert_eq!(hop.tenant, "ovzdusie");
}
