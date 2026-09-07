//! T-0166: the endpoint's own MCP instance (EP-24, EP-25, EP-26, AG-04, AG-05, SP-14…SP-20).

mod common;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::routing::any;
use axum::Router;
use context_gateway::app::{router, Gateway};
use context_gateway::auth::accounts::ServiceAccounts;
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::Endpoint;
use jc_core::kinds::{Audience, PolicySpec, Representation};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const SLUG: &str = "k4y7pq2mzt6vhx3nbwrs5cjd8f";
const NO_MCP: &str = "zt4qm7ge2xdv6ksb3ncf5arw2y";
const ENTITY: &str = "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:st-1";

fn policy(yaml: &str) -> PolicySpec {
    serde_norway::from_str(yaml).expect("the policy spec parses")
}

/// The demo endpoint: anonymous callers read air quality, a steward also writes it and
/// may list the types.
fn endpoint(slug: &str, representations: Vec<Representation>) -> Endpoint {
    Endpoint {
        slug: slug.to_owned(),
        space: "ovzdusie".to_owned(),
        project: "ovzdusie".to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations,
        rate_limit: None,
        file_limits: None,
        hidden_attributes: Default::default(),
        base_path: format!("/api/endpoint/{slug}"),
        models: Vec::new(),
        view_mapping: None,
        policies: vec![
            policy(
                r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity, retrieveEntity]
information:
  - entities:
      - type: AirQualityObserved
    propertyNames: [pm10, pm25, location]
"#,
            ),
            policy(
                r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: steward }
operations: [queryEntity, retrieveEntity, retrieveEntityTypes, queryTemporal, upsertBatch]
information:
  - entities:
      - type: AirQualityObserved
"#,
            ),
        ],
    }
}

/// The gateway of every test: both endpoints, and the throwaway realm's verifier so a
/// token can be presented at all.
fn gateway(broker: &str, realm: &common::Realm) -> Arc<Gateway> {
    Arc::new(
        Gateway::new(
            Broker::new(broker),
            Box::new(PolicyPdp),
            "banskabystrica.sk",
        )
        .serve([
            endpoint(SLUG, vec![Representation::NgsiLd, Representation::Mcp]),
            endpoint(NO_MCP, vec![Representation::NgsiLd]),
        ])
        .authenticate(Arc::new(realm.verifier()), ServiceAccounts::new(), None),
    )
}

fn app(broker: &str, realm: &common::Realm) -> Router {
    router(gateway(broker, realm))
}

/// One JSON-RPC message, with an optional token.
fn message(slug: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/endpoint/{slug}/mcp"))
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder
        .body(Body::from(body.to_string()))
        .expect("a request")
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.expect("the gateway answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a body");
    let payload = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, payload)
}

/// The tool names of a `tools/list` answer, sorted.
fn tool_names(answer: &Value) -> Vec<String> {
    let mut names: Vec<String> = answer["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    names.sort();
    names
}

/// A steward's token: a human of the organization holding the `steward` realm role.
fn steward(realm: &common::Realm) -> String {
    realm.mint(&json!({
        "iss": common::ISSUER,
        "sub": "0f5a",
        "aud": SLUG,
        "preferred_username": "jana",
        "realm_access": { "roles": ["steward"] },
        "exp": common::in_seconds(300),
        "iat": common::in_seconds(-10),
    }))
}

/// What the broker was asked, so a test can see what came out of the enforcement path.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    uri: String,
    tenant: Option<String>,
    authorization: Option<String>,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// A broker that answers an empty result set and records the request it was given.
async fn stub_broker() -> (String, Log) {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let recorder = {
        let log = Arc::clone(&log);
        Router::new().fallback(any(record)).with_state(log)
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let address = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, recorder).await;
    });
    (format!("http://{address}"), log)
}

async fn record(
    State(log): State<Log>,
    request: Request<Body>,
) -> ([(&'static str, &'static str); 1], String) {
    let header = |headers: &HeaderMap, name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    log.lock().expect("the log").push(Seen {
        method: request.method().to_string(),
        uri: request.uri().to_string(),
        tenant: header(request.headers(), "ngsild-tenant"),
        authorization: header(request.headers(), "authorization"),
    });
    ([("content-type", "application/json")], "[]".to_owned())
}

#[tokio::test]
async fn the_handshake_names_the_protocol_the_server_and_the_one_space_it_serves() {
    let realm = common::Realm::new();
    let (_, answer) = send(
        app("http://127.0.0.1:1", &realm),
        message(
            SLUG,
            None,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": { "name": "an agent", "version": "0" },
            }}),
        ),
    )
    .await;

    assert_eq!(answer["jsonrpc"], "2.0");
    assert_eq!(answer["id"], 1);
    assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        answer["result"]["serverInfo"]["name"],
        format!("joinedcontext-endpoint-{SLUG}")
    );
    assert_eq!(
        answer["result"]["capabilities"]["tools"]["listChanged"], false,
        "a stateless server has nobody to notify (SP-19)"
    );
    assert!(
        answer["result"]["instructions"]
            .as_str()
            .expect("instructions")
            .contains("ovzdusie"),
        "the agent is told which space its URNs live in"
    );
}

#[tokio::test]
async fn a_notification_is_acknowledged_and_answered_with_nothing() {
    let realm = common::Realm::new();
    let response = app("http://127.0.0.1:1", &realm)
        .oneshot(message(
            SLUG,
            None,
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        ))
        .await
        .expect("the gateway answers");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("a body");
    assert!(bytes.is_empty(), "a notification has no answer");
}

/// EP-25, SP-15: the list is rendered from the caller's grants, by the PDP that enforces
/// them, so discovery cannot advertise what a call would refuse.
#[tokio::test]
async fn the_tool_list_is_the_callers_grants_and_grows_with_the_token() {
    let realm = common::Realm::new();
    let token = steward(&realm);

    let (_, anonymous) = send(
        app("http://127.0.0.1:1", &realm),
        message(
            SLUG,
            None,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        ),
    )
    .await;
    assert_eq!(
        tool_names(&anonymous),
        vec![
            "describe_access",
            "describe_schema",
            "get_entity",
            "query_entities"
        ],
        "two reads, and the two tools that describe the endpoint to whoever it admits"
    );

    let (_, granted) = send(
        app("http://127.0.0.1:1", &realm),
        message(
            SLUG,
            Some(&token),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }),
        ),
    )
    .await;
    assert_eq!(
        tool_names(&granted),
        vec![
            "describe_access",
            "describe_schema",
            "get_entity",
            "list_types",
            "query_entities",
            "query_temporal",
            "upsert_entity"
        ],
        "the steward writes and reads history; nobody's grant hides a tool from its holder"
    );
    assert!(
        granted["result"]["tools"][0]["inputSchema"]["type"] == "object",
        "every tool carries the schema an agent needs to call it (AG-04)"
    );
}

/// SP-20: a tool the caller may not use answers exactly what a tool nobody defined does,
/// so an MCP client cannot map the grants of a space by probing it.
#[tokio::test]
async fn an_ungranted_tool_is_indistinguishable_from_one_that_does_not_exist() {
    let realm = common::Realm::new();
    let call = |name: &str| {
        json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": name, "arguments": {},
        }})
    };

    let (_, ungranted) = send(
        app("http://127.0.0.1:1", &realm),
        message(SLUG, None, call("upsert_entity")),
    )
    .await;
    let (_, unknown) = send(
        app("http://127.0.0.1:1", &realm),
        message(SLUG, None, call("summon_everything")),
    )
    .await;

    assert_eq!(ungranted["error"], unknown["error"]);
    assert_eq!(ungranted["error"]["code"], -32602);
    assert_eq!(ungranted["error"]["message"], "unknown tool");
}

/// AG-05, SP-14: the space is the URL's, and an argument that would choose another one is
/// refused rather than ignored.
#[tokio::test]
async fn an_argument_that_would_aim_the_tool_at_another_space_is_refused() {
    let realm = common::Realm::new();
    for selector in ["space", "tenant", "contextSpace"] {
        let (_, answer) = send(
            app("http://127.0.0.1:1", &realm),
            message(
                SLUG,
                None,
                json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
                    "name": "query_entities",
                    "arguments": { "type": "AirQualityObserved", selector: "doprava" },
                }}),
            ),
        )
        .await;
        assert_eq!(answer["error"]["code"], -32602, "{selector} is refused");
        assert!(answer["error"]["message"]
            .as_str()
            .expect("a message")
            .contains(selector));
    }
}

/// EP-26, SP-16: the tool call becomes the NGSI-LD request it stands for, with the tenant
/// pinned by the gateway and the caller's own token carried to the broker.
#[tokio::test]
async fn a_tool_call_reaches_the_broker_pinned_to_the_space_and_carrying_the_callers_token() {
    let realm = common::Realm::new();
    let token = steward(&realm);
    let (broker, log) = stub_broker().await;

    let (_, answer) = send(
        app(&broker, &realm),
        message(
            SLUG,
            Some(&token),
            json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
                "name": "query_entities",
                "arguments": { "type": "AirQualityObserved", "limit": 5 },
            }}),
        ),
    )
    .await;
    assert_eq!(answer["result"]["isError"], false);
    assert!(answer["result"]["structuredContent"].is_array());

    let seen = log.lock().expect("the log").clone();
    assert_eq!(seen.len(), 1, "one tool call, one broker request");
    assert_eq!(seen[0].method, "GET");
    assert!(
        seen[0].uri.starts_with("/ngsi-ld/v1/entities?"),
        "got {}",
        seen[0].uri
    );
    assert!(seen[0].uri.contains("type=AirQualityObserved"));
    assert_eq!(
        seen[0].tenant.as_deref(),
        Some("ovzdusie"),
        "the space is pinned by the endpoint, never by the agent (EP-22)"
    );
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Bearer {token}").as_str()),
        "the caller's own token, not an identity the façade holds (EP-26)"
    );
}

/// An anonymous tool call is served, and nothing invents a token for it.
#[tokio::test]
async fn an_anonymous_tool_call_carries_no_token_at_all() {
    let realm = common::Realm::new();
    let (broker, log) = stub_broker().await;

    let (_, answer) = send(
        app(&broker, &realm),
        message(
            SLUG,
            None,
            json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
                "name": "get_entity",
                "arguments": { "id": ENTITY },
            }}),
        ),
    )
    .await;
    assert_eq!(answer["result"]["isError"], false);

    let seen = log.lock().expect("the log").clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].authorization, None);
    assert!(
        seen[0].uri.contains("urn%3Angsi-ld%3AAirQualityObserved"),
        "the URN survives the trip encoded, got {}",
        seen[0].uri
    );
}

/// SP-17: a refusal is a tool error an agent can read, never an empty result it would
/// report as "there is nothing there".
#[tokio::test]
async fn a_refusal_comes_back_as_a_tool_error_and_never_as_an_empty_answer() {
    let realm = common::Realm::new();
    let (broker, log) = stub_broker().await;

    let (_, answer) = send(
        app(&broker, &realm),
        message(
            SLUG,
            None,
            json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
                "name": "get_entity",
                "arguments": { "id": "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:doprava:st-1" },
            }}),
        ),
    )
    .await;

    assert_eq!(
        answer["result"]["isError"], true,
        "an entity of another space is refused, and the agent is told so"
    );
    assert!(answer["result"]["content"][0]["text"]
        .as_str()
        .expect("a text")
        .starts_with("400 "));
    assert!(
        log.lock().expect("the log").is_empty(),
        "a refusal never reaches the broker"
    );
}

/// EP-05: the surface exists only where the endpoint enables the representation.
#[tokio::test]
async fn the_mcp_surface_is_not_there_where_the_endpoint_does_not_enable_it() {
    let realm = common::Realm::new();
    let (status, _) = send(
        app("http://127.0.0.1:1", &realm),
        message(
            NO_MCP,
            None,
            json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_body_that_is_not_json_and_a_method_nobody_defined_answer_as_json_rpc_says() {
    let realm = common::Realm::new();
    let broken = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/endpoint/{SLUG}/mcp"))
        .header("content-type", "application/json")
        .body(Body::from("{ not json"))
        .expect("a request");
    let (status, answer) = send(app("http://127.0.0.1:1", &realm), broken).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["error"]["code"], -32700);

    let (_, unknown) = send(
        app("http://127.0.0.1:1", &realm),
        message(
            SLUG,
            None,
            json!({ "jsonrpc": "2.0", "id": 10, "method": "prompts/get" }),
        ),
    )
    .await;
    assert_eq!(unknown["error"]["code"], -32601);
}

/// EP-47, EP-55: the two describing tools are the access and schema projections, answered
/// from the endpoint itself, so an agent can orient without a single broker round trip.
#[tokio::test]
async fn the_describing_tools_answer_from_the_endpoint_and_never_from_the_broker() {
    let realm = common::Realm::new();
    let (broker, log) = stub_broker().await;
    let call = |id: u32, name: &str, arguments: Value| {
        json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
            "name": name, "arguments": arguments,
        }})
    };

    let (_, access) = send(
        app(&broker, &realm),
        message(SLUG, None, call(11, "describe_access", json!({}))),
    )
    .await;
    assert_eq!(access["result"]["isError"], false);
    let permissions = &access["result"]["structuredContent"];
    assert_eq!(permissions["resource"]["id"], SLUG);
    assert_eq!(permissions["resource"]["space"], "ovzdusie");
    assert!(
        permissions["permissions"]
            .as_array()
            .expect("the caller's own grants")
            .len()
            == 1,
        "the anonymous caller sees the public grant and nobody else's (R20)"
    );

    let (_, summary) = send(
        app(&broker, &realm),
        message(SLUG, None, call(12, "describe_schema", json!({}))),
    )
    .await;
    assert_eq!(summary["result"]["structuredContent"]["endpoint"], SLUG);

    let (_, shacl) = send(
        app(&broker, &realm),
        message(
            SLUG,
            None,
            call(13, "describe_schema", json!({ "format": "shacl" })),
        ),
    )
    .await;
    assert_eq!(
        shacl["result"]["isError"], true,
        "a formalism the gateway cannot compile is named, never approximated"
    );

    assert!(
        log.lock().expect("the log").is_empty(),
        "neither tool asks the broker anything"
    );
}
