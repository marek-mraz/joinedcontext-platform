//! T-0156: a notification leaves through the gateway, not around it (R46, GW27).
//!
//! Everything else the platform sends is an answer to a request that was projected on the
//! way in. A notification is sent later and to somebody else, so the projection has to
//! happen on the way out — and it has to happen from the subscription as it was *stored*,
//! because at delivery time there is no token and no caller to decide from.

mod common;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
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

const SLUG: &str = "n4t8xq2vhm6zc9wrb5sdj3kfp7";
const PROJECT: &str = "banskabystrica";
const SPACE: &str = "ovzdusie";
const DOMAIN: &str = "banskabystrica.sk";
const PUBLIC_URL: &str = "https://gw.banskabystrica.sk";
const SUBSCRIPTION: &str = "urn:ngsi-ld:Subscription:ovzdusie:senzory";
const SENSOR: &str = "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:senzor-01";
const OTHER: &str = "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:senzor-02";
/// The attribute the grant does not name, which no delivery may ever carry.
const UNGRANTED: &str = "operatorPhone";

/// What one side of the egress path recorded.
type Seen = Arc<Mutex<Vec<Value>>>;
/// The headers one delivery arrived with.
type Headers = Arc<Mutex<Vec<(String, String)>>>;

#[derive(Clone)]
struct Sink {
    seen: Seen,
    headers: Headers,
}

/// The webhook the subscriber asked for: an ordinary HTTP server that records what arrives.
async fn sink() -> (String, Seen, Headers) {
    let state = Sink {
        seen: Arc::new(Mutex::new(Vec::new())),
        headers: Arc::new(Mutex::new(Vec::new())),
    };
    let (seen, headers) = (Arc::clone(&state.seen), Arc::clone(&state.headers));
    let app = Router::new()
        .fallback(any(
            |State(sink): State<Sink>, request: Request| async move {
                sink.headers.lock().expect("the header log").extend(
                    request.headers().iter().filter_map(|(name, value)| {
                        Some((name.to_string(), value.to_str().ok()?.to_owned()))
                    }),
                );
                let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                    .await
                    .expect("a body");
                sink.seen
                    .lock()
                    .expect("the delivery log")
                    .push(serde_json::from_slice(&bytes).unwrap_or(Value::Null));
                StatusCode::NO_CONTENT
            },
        ))
        .with_state(state);
    (serve(app).await, seen, headers)
}

#[derive(Clone)]
struct BrokerState {
    /// The subscription the broker holds, as the gateway would have stored it.
    stored: Option<Value>,
    /// The entity ids the narrowed filter still matches.
    matching: Vec<String>,
    /// The subscriptions the gateway forwarded, as it forwarded them.
    forwarded: Seen,
}

/// A broker that stores subscriptions and answers the one query the egress path makes.
async fn broker(state: BrokerState) -> (String, Seen) {
    let forwarded = Arc::clone(&state.forwarded);
    let app = Router::new()
        .fallback(any(
            |State(state): State<BrokerState>, request: Request| async move {
                let method = request.method().clone();
                let path = request.uri().path().to_owned();
                let query = request.uri().query().unwrap_or_default().to_owned();

                if method == Method::GET && path == "/ngsi-ld/v1/entities" {
                    let matched: Vec<Value> = state
                        .matching
                        .iter()
                        .filter(|id| query.contains(&percent(id)))
                        .map(|id| json!({ "id": id, "type": "AirQualityObserved" }))
                        .collect();
                    return axum::Json(Value::Array(matched)).into_response();
                }
                if method == Method::GET && path.starts_with("/ngsi-ld/v1/subscriptions/") {
                    return match state.stored.clone() {
                        Some(stored) => axum::Json(stored).into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    };
                }
                if method == Method::POST || method == Method::PATCH {
                    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                        .await
                        .expect("a body");
                    state
                        .forwarded
                        .lock()
                        .expect("the forwarding log")
                        .push(serde_json::from_slice(&bytes).unwrap_or(Value::Null));
                    return StatusCode::CREATED.into_response();
                }
                StatusCode::NO_CONTENT.into_response()
            },
        ))
        .with_state(state);
    (serve(app).await, forwarded)
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let address = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}")
}

/// The percent-encoding the gateway uses for a value it puts in a query string.
fn percent(raw: &str) -> String {
    raw.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn policy() -> PolicySpec {
    serde_norway::from_str(&format!(
        "contextSpaceRef: {SPACE}\n\
         assigner: did:web:{DOMAIN}\n\
         assignee: {{ kind: role, id: public }}\n\
         operations: [queryEntity, retrieveEntity, createSubscription, updateSubscription]\n\
         q: temperature<100\n\
         information:\n\
         \x20 - entities:\n\
         \x20     - type: AirQualityObserved\n\
         \x20   propertyNames: [temperature, location]\n"
    ))
    .expect("the policy spec parses")
}

fn endpoint(hidden: &[&str]) -> Endpoint {
    Endpoint {
        slug: SLUG.to_owned(),
        space: SPACE.to_owned(),
        project: PROJECT.to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd],
        rate_limit: None,
        file_limits: None,
        hidden_attributes: hidden.iter().map(|name| (*name).to_owned()).collect(),
        base_path: format!("/api/endpoint/{SLUG}"),
        models: Vec::new(),
        view_mapping: None,
        policies: vec![policy()],
    }
}

fn gateway(upstream: String, hidden: &[&str]) -> Arc<Gateway> {
    let realm = common::Realm::new();
    Arc::new(
        Gateway::new(Broker::new(upstream), Box::new(PolicyPdp), DOMAIN)
            .authenticate(
                Arc::new(realm.verifier()),
                ServiceAccounts::new(),
                Some(PUBLIC_URL.to_owned()),
            )
            .serve([endpoint(hidden)]),
    )
}

/// The subscription the gateway would have stored: narrowed, and routed back through itself.
fn stored(to: &str, attributes: Value, q: &str) -> Value {
    json!({
        "id": SUBSCRIPTION,
        "type": "Subscription",
        "entities": [{ "type": "AirQualityObserved" }],
        "q": q,
        "notification": {
            "attributes": attributes,
            "endpoint": {
                "uri": format!(
                    "{PUBLIC_URL}/api/endpoint/{SLUG}/egress/notifications?to={}",
                    percent(to)
                ),
                "accept": "application/json"
            }
        }
    })
}

fn notification(entities: Vec<Value>) -> Value {
    json!({
        "id": "urn:ngsi-ld:Notification:1",
        "type": "Notification",
        "subscriptionId": SUBSCRIPTION,
        "notifiedAt": "2026-09-07T08:00:00Z",
        "data": entities
    })
}

fn sensor(id: &str) -> Value {
    json!({
        "id": id,
        "type": "AirQualityObserved",
        "temperature": { "type": "Property", "value": 19.5 },
        UNGRANTED: { "type": "Property", "value": "+421 900 000 000" }
    })
}

/// Creates a subscription through the gateway and hands back what the broker was told.
async fn create(subscription: Value) -> (StatusCode, Vec<Value>) {
    let (upstream, forwarded) = broker(BrokerState {
        stored: None,
        matching: Vec::new(),
        forwarded: Arc::new(Mutex::new(Vec::new())),
    })
    .await;

    let response = router(gateway(upstream, &[]))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/endpoint/{SLUG}/ngsi-ld/v1/subscriptions"))
                .header("content-type", "application/json")
                .body(Body::from(subscription.to_string()))
                .expect("a request"),
        )
        .await
        .expect("the gateway answers");

    let status = response.status();
    let seen = forwarded.lock().expect("the forwarding log").clone();
    (status, seen)
}

/// Delivers one notification through the egress path and hands back what the sink saw.
async fn deliver(
    subscription: Option<Value>,
    matching: Vec<String>,
    entities: Vec<Value>,
    hidden: &[&str],
    to: &str,
) -> (StatusCode, Vec<Value>) {
    let (upstream, _) = broker(BrokerState {
        stored: subscription,
        matching,
        forwarded: Arc::new(Mutex::new(Vec::new())),
    })
    .await;

    let response = router(gateway(upstream, hidden))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/api/endpoint/{SLUG}/egress/notifications?to={}",
                    percent(to)
                ))
                .header("content-type", "application/json")
                .header("x-auth-token", "the receiverInfo the broker attached")
                .body(Body::from(notification(entities).to_string()))
                .expect("a request"),
        )
        .await
        .expect("the gateway answers");
    (response.status(), Vec::new())
}

#[tokio::test]
async fn a_created_subscription_is_narrowed_and_its_delivery_routed_back_through_the_gateway() {
    let (status, forwarded) = create(json!({
        "type": "Subscription",
        "entities": [{ "type": "AirQualityObserved" }, { "type": "Device" }],
        "q": "temperature>10",
        "notification": {
            "endpoint": { "uri": "http://mesto.internal/hooks/ovzdusie" }
        }
    }))
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let stored = forwarded.first().expect("the broker was told something");

    let uri = stored["notification"]["endpoint"]["uri"]
        .as_str()
        .expect("a rewritten uri");
    assert!(
        uri.starts_with(&format!(
            "{PUBLIC_URL}/api/endpoint/{SLUG}/egress/notifications?to="
        )),
        "delivery goes through the gateway: {uri}"
    );
    assert!(
        uri.ends_with(&percent("http://mesto.internal/hooks/ovzdusie")),
        "and the subscriber's own endpoint travels with it: {uri}"
    );

    assert_eq!(
        stored["entities"],
        json!([{ "type": "AirQualityObserved" }]),
        "a type outside the grant is not watched"
    );
    assert_eq!(
        stored["q"].as_str().expect("a folded filter"),
        "(temperature>10);((temperature<100))",
        "the subscriber's filter and the grant's, conjoined"
    );
    assert_eq!(
        stored["notification"]["attributes"],
        json!(["location", "temperature"]),
        "a subscription that named no attributes is stored asking for the granted ones"
    );
}

#[tokio::test]
async fn a_subscription_that_watches_nothing_granted_is_refused() {
    let (status, forwarded) = create(json!({
        "type": "Subscription",
        "entities": [{ "type": "Device" }],
        "notification": { "endpoint": { "uri": "http://mesto.internal/hooks/x" } }
    }))
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(forwarded.is_empty(), "nothing was stored: {forwarded:?}");
}

#[tokio::test]
async fn a_subscription_asking_for_an_ungranted_attribute_keeps_only_the_granted_ones() {
    let (status, forwarded) = create(json!({
        "type": "Subscription",
        "entities": [{ "type": "AirQualityObserved" }],
        "notification": {
            "attributes": ["temperature", UNGRANTED],
            "endpoint": { "uri": "http://mesto.internal/hooks/x" }
        }
    }))
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        forwarded[0]["notification"]["attributes"],
        json!(["temperature"])
    );
}

/// The gateway's dispatcher speaks HTTP, so a subscription it could never deliver is
/// refused at creation rather than stored and silently dropped later.
#[tokio::test]
async fn an_endpoint_the_gateway_cannot_reach_is_refused_at_creation() {
    let (status, forwarded) = create(json!({
        "type": "Subscription",
        "entities": [{ "type": "AirQualityObserved" }],
        "notification": { "endpoint": { "uri": "https://mesto.example/hooks/x" } }
    }))
    .await;

    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(forwarded.is_empty(), "nothing was stored: {forwarded:?}");
}

#[tokio::test]
async fn a_delivered_notification_carries_only_the_attributes_the_subscription_was_narrowed_to() {
    let (webhook, seen, headers) = sink().await;
    let (status, _) = deliver(
        Some(stored(
            &webhook,
            json!(["location", "temperature"]),
            "((temperature<100))",
        )),
        vec![SENSOR.to_owned()],
        vec![sensor(SENSOR)],
        &[],
        &webhook,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let delivered = seen.lock().expect("the delivery log").clone();
    assert_eq!(delivered.len(), 1, "one delivery: {delivered:?}");

    let entity = &delivered[0]["data"][0];
    assert_eq!(entity["temperature"]["value"], json!(19.5));
    assert!(
        entity.get(UNGRANTED).is_none(),
        "the phone number is not granted and never leaves: {entity}"
    );
    assert_eq!(entity["id"], json!(SENSOR), "still an NGSI-LD entity");

    let arrived = headers.lock().expect("the header log").clone();
    assert!(
        arrived
            .iter()
            .any(|(name, value)| name == "x-auth-token" && value.contains("receiverInfo")),
        "the authorization material the broker attached reaches the receiver: {arrived:?}"
    );
}

#[tokio::test]
async fn an_endpoints_hidden_attribute_is_stripped_even_when_the_subscription_names_it() {
    let (webhook, seen, _) = sink().await;
    let (status, _) = deliver(
        Some(stored(
            &webhook,
            json!(["location", "temperature"]),
            "((temperature<100))",
        )),
        vec![SENSOR.to_owned()],
        vec![sensor(SENSOR)],
        &["temperature"],
        &webhook,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let delivered = seen.lock().expect("the delivery log").clone();
    assert!(
        delivered[0]["data"][0].get("temperature").is_none(),
        "what the endpoint publishes nothing of is not published by a notification either"
    );
}

/// A notification says what changed. Whether the entity still satisfies the condition the
/// grant was narrowed with is a question about now, and only the broker can answer it.
#[tokio::test]
async fn an_entity_that_no_longer_matches_the_condition_is_not_delivered() {
    let (webhook, seen, _) = sink().await;
    let (status, _) = deliver(
        Some(stored(
            &webhook,
            json!(["temperature"]),
            "((temperature<100))",
        )),
        vec![SENSOR.to_owned()],
        vec![sensor(SENSOR), sensor(OTHER)],
        &[],
        &webhook,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let delivered = seen.lock().expect("the delivery log").clone();
    let ids: Vec<&Value> = delivered[0]["data"]
        .as_array()
        .expect("the entities")
        .iter()
        .map(|entity| &entity["id"])
        .collect();
    assert_eq!(ids, vec![&json!(SENSOR)], "only the one that still matches");
}

#[tokio::test]
async fn a_notification_whose_entities_all_stopped_matching_dispatches_nothing() {
    let (webhook, seen, _) = sink().await;
    let (status, _) = deliver(
        Some(stored(
            &webhook,
            json!(["temperature"]),
            "((temperature<100))",
        )),
        Vec::new(),
        vec![sensor(SENSOR)],
        &[],
        &webhook,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        seen.lock().expect("the delivery log").is_empty(),
        "nothing left the platform"
    );
}

/// A subscription created straight on the broker was never narrowed, so the gateway has no
/// projection to apply and refuses to be its delivery agent.
#[tokio::test]
async fn a_subscription_the_gateway_did_not_route_is_not_delivered() {
    let (webhook, seen, _) = sink().await;
    let unrouted = json!({
        "id": SUBSCRIPTION,
        "type": "Subscription",
        "notification": { "endpoint": { "uri": webhook.clone() } }
    });
    let (status, _) = deliver(
        Some(unrouted),
        vec![SENSOR.to_owned()],
        vec![sensor(SENSOR)],
        &[],
        &webhook,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(seen.lock().expect("the delivery log").is_empty());
}

#[tokio::test]
async fn a_delivery_naming_a_subscription_the_broker_does_not_hold_is_refused() {
    let (webhook, seen, _) = sink().await;
    let (status, _) = deliver(
        None,
        vec![SENSOR.to_owned()],
        vec![sensor(SENSOR)],
        &[],
        &webhook,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(seen.lock().expect("the delivery log").is_empty());
}

/// The target is read out of the stored subscription, never out of the request: a forged
/// delivery cannot make the gateway post anywhere the subscription does not name.
#[tokio::test]
async fn the_target_comes_from_the_stored_subscription_and_not_from_the_request() {
    let (webhook, seen, _) = sink().await;
    let (elsewhere, forged, _) = sink().await;
    let (status, _) = deliver(
        Some(stored(
            &webhook,
            json!(["temperature"]),
            "((temperature<100))",
        )),
        vec![SENSOR.to_owned()],
        vec![sensor(SENSOR)],
        &[],
        &elsewhere,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        seen.lock().expect("the delivery log").len(),
        1,
        "the subscription's own endpoint got it"
    );
    assert!(
        forged.lock().expect("the delivery log").is_empty(),
        "the one the request named did not"
    );
}
