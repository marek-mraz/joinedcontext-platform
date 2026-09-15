//! Unit and integration tests for `jc-agent-proxy` (refusal matrix and credential isolation).

use agent_proxy::config::Config;
use agent_proxy::inject::CredentialManager;
use agent_proxy::limits::LimitManager;
use agent_proxy::runs::{RunContext, RunResolver};
use agent_proxy::{router, ProxyState};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

fn test_hash(ticket: &str) -> String {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(ticket.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn sample_run(allows_write: bool, status: &str) -> RunContext {
    RunContext {
        id: "e3b0c442-98fc-1c14-9afb-4c7b2756a120".to_string(),
        project: "helsinki".to_string(),
        app_name: "bikes".to_string(),
        endpoint_slug: "scsd2eehkx42n53z2zyd6vshfh7s7irf".to_string(),
        endpoint_slugs: vec![],
        allows_write,
        branch: "agent/app-bikes/e3b0c442-98fc-1c14-9afb-4c7b2756a120".to_string(),
        path_prefix: "projects/helsinki/apps/bikes/".to_string(),
        status: status.to_string(),
        ticket_hash: test_hash("secret-ticket-123"),
        max_tokens: 1000,
        allowed_hosts: vec!["crates.io".to_string()],
        requests_per_minute: 100,
        max_response_bytes: 1048576,
        created_by: "demo.steward@hel.fi".to_string(),
        model_name: "claude-3-7".to_string(),
        reasoning_effort: None,
    }
}

fn test_state(run: RunContext) -> Arc<ProxyState> {
    test_state_with_gateway(run, "http://context-gateway:8080")
}

fn test_state_with_gateway(run: RunContext, gateway: &str) -> Arc<ProxyState> {
    test_state_with_upstreams(run, gateway, "https://api.anthropic.com")
}

fn test_state_with_upstreams(run: RunContext, gateway: &str, model: &str) -> Arc<ProxyState> {
    test_state_with(run, gateway, model, "http://gitea-http:3000")
}

fn test_state_with_forge(run: RunContext, forge: &str) -> Arc<ProxyState> {
    test_state_with(
        run,
        "http://context-gateway:8080",
        "https://api.anthropic.com",
        forge,
    )
}

fn test_state_with(run: RunContext, gateway: &str, model: &str, forge: &str) -> Arc<ProxyState> {
    let gateway = gateway.to_string();
    let model = model.to_string();
    let forge = forge.to_string();
    let config = Config::from_lookup(|k| match k {
        "JC_PROXY_BIND" => Some("127.0.0.1:0".to_string()),
        "JC_GATEWAY_BASE" => Some(gateway.clone()),
        "JC_MODEL_BASE" => Some(model.clone()),
        "JC_FORGE_BASE" => Some(forge.clone()),
        "JC_MODEL_KEY" => Some("mock-model-key".to_string()),
        "JC_FORGE_TOKEN" => Some("mock-forge-token".to_string()),
        _ => None,
    })
    .unwrap();

    let config_arc = Arc::new(config);
    let credentials = CredentialManager::new(config_arc.clone());
    let runs = RunResolver::with_cached(run);
    let limits = LimitManager::default();
    let http = reqwest::Client::new();

    Arc::new(ProxyState {
        config: config_arc,
        runs,
        credentials,
        limits,
        http,
    })
}

#[tokio::test]
async fn missing_ticket_returns_401() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .uri("/v1/data/ngsi-ld/v1/entities")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_ticket_returns_401() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .uri("/v1/data/ngsi-ld/v1/entities")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "wrong-ticket")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn path_traversal_on_data_route_returns_403() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .uri("/v1/data/../../admin")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn write_on_readonly_run_returns_403() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/data/ngsi-ld/v1/entities/some-id/attrs")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn forge_write_outside_prefix_returns_403() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/forge/contents/projects/other/secret.yaml")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn package_host_outside_allowlist_returns_403() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .uri("/v1/packages/evil.example.com/package.tar.gz")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn token_budget_exhaustion_returns_429() {
    let state = test_state(sample_run(false, "building"));
    state
        .limits
        .record_tokens("e3b0c442-98fc-1c14-9afb-4c7b2756a120", 2000)
        .await;

    let app = router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/llm/v1/chat/completions")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn terminal_run_returns_409() {
    let app = router(test_state(sample_run(false, "failed")));
    let req = Request::builder()
        .uri("/v1/data/ngsi-ld/v1/entities")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn config_debug_redacts_credentials() {
    let config = Config::from_lookup(|k| match k {
        "JC_MODEL_KEY" => Some("secret-model-key".to_string()),
        "JC_FORGE_TOKEN" => Some("secret-forge-token".to_string()),
        "JC_OIDC_CLIENT_SECRET" => Some("secret-oidc".to_string()),
        _ => None,
    })
    .unwrap();

    let debug_str = format!("{config:?}");
    assert!(!debug_str.contains("secret-model-key"));
    assert!(!debug_str.contains("secret-forge-token"));
    assert!(!debug_str.contains("secret-oidc"));
    assert!(debug_str.contains("[redacted]"));
}

#[tokio::test]
async fn the_ticket_is_accepted_as_a_bearer_token() {
    // An OpenAI-compatible model client sends nothing but `Authorization: Bearer <key>`, so the
    // ticket travels there as `jcr_<run>.<ticket>`. Anything past authentication is proof it was
    // read: this run is read-only, so a write is refused with 403 rather than 401.
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/data/ngsi-ld/v1/entities/some-id/attrs")
        .header(
            "authorization",
            "Bearer jcr_e3b0c442-98fc-1c14-9afb-4c7b2756a120.secret-ticket-123",
        )
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_bearer_with_the_wrong_ticket_is_refused() {
    let app = router(test_state(sample_run(false, "building")));
    for token in [
        "Bearer jcr_e3b0c442-98fc-1c14-9afb-4c7b2756a120.wrong-ticket",
        // No prefix, no separator, an empty half: none of these is a credential.
        "Bearer e3b0c442-98fc-1c14-9afb-4c7b2756a120.secret-ticket-123",
        "Bearer jcr_e3b0c442-98fc-1c14-9afb-4c7b2756a120",
        "Bearer jcr_.secret-ticket-123",
        "Bearer sk-or-v1-a-model-provider-key",
    ] {
        let req = Request::builder()
            .uri("/v1/data/ngsi-ld/v1/entities")
            .header("authorization", token)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "accepted a bad bearer: {token}"
        );
    }
}

#[tokio::test]
async fn the_inbox_needs_a_ticket_like_every_other_route() {
    let app = router(test_state(sample_run(false, "interviewing")));
    let req = Request::builder()
        .uri("/v1/runs/inbox?after=0")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A data read reaches the gateway with its query string: the type, the attributes, the page
/// and `options=keyValues` are the read itself, and a proxy that dropped them would hand every
/// caller the first page of everything, normalized.
#[tokio::test]
async fn a_data_read_carries_its_query_string_to_the_gateway() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let gateway = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/api/endpoint/scsd2eehkx42n53z2zyd6vshfh7s7irf/ngsi-ld/v1/entities",
        ))
        .and(query_param("type", "BikeHireDockingStation"))
        .and(query_param("options", "keyValues"))
        .and(query_param("offset", "500"))
        .and(query_param("attrs", "name,location"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&gateway)
        .await;

    let app = router(test_state_with_gateway(
        sample_run(false, "building"),
        &gateway.uri(),
    ));
    let req = Request::builder()
        .uri("/v1/data/ngsi-ld/v1/entities?type=BikeHireDockingStation&options=keyValues&limit=500&offset=500&attrs=name,location")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    gateway.verify().await;
}

/// The second endpoint of a run (AP-44, AG-75): its slug in the run context.
const KPIS: &str = "q3mzkq2v7w5ayxcbn4ltdj6hof2repgu";

fn two_endpoint_run(allows_write: bool) -> RunContext {
    let mut run = sample_run(allows_write, "building");
    run.endpoint_slugs = vec![run.endpoint_slug.clone(), KPIS.to_string()];
    run
}

fn ticketed(method: &str, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

/// A read and an MCP call under the run's second endpoint reach that endpoint on the gateway,
/// each with a token minted for that endpoint's audience and not the primary's.
#[tokio::test]
async fn a_second_endpoint_of_the_run_is_reached_with_its_own_token() {
    use wiremock::matchers::{body_partial_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let gateway = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/endpoint/{KPIS}/ngsi-ld/v1/entities")))
        .and(query_param("type", "KeyPerformanceIndicator"))
        .and(header(
            "authorization",
            format!("Bearer mock-token-for-{KPIS}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&gateway)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/endpoint/{KPIS}/mcp")))
        .and(header(
            "authorization",
            format!("Bearer mock-token-for-{KPIS}").as_str(),
        ))
        .and(body_partial_json(
            serde_json::json!({ "method": "tools/call" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "content": [] } }),
        ))
        .expect(1)
        .mount(&gateway)
        .await;

    let state = test_state_with_gateway(two_endpoint_run(false), &gateway.uri());
    let read = router(state.clone())
        .oneshot(ticketed(
            "GET",
            &format!("/v1/data/endpoints/{KPIS}/ngsi-ld/v1/entities?type=KeyPerformanceIndicator"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);

    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "query_entities", "arguments": { "type": "KeyPerformanceIndicator" } }
    });
    let mcp = router(state)
        .oneshot(ticketed(
            "POST",
            &format!("/v1/data/endpoints/{KPIS}/mcp"),
            Body::from(call.to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(mcp.status(), StatusCode::OK);
    gateway.verify().await;
}

/// A slug the run does not name is refused, and nothing reaches the gateway.
#[tokio::test]
async fn an_endpoint_outside_the_run_is_refused() {
    use wiremock::MockServer;

    let gateway = MockServer::start().await;
    let app = router(test_state_with_gateway(
        two_endpoint_run(false),
        &gateway.uri(),
    ));
    let resp = app
        .oneshot(ticketed(
            "GET",
            "/v1/data/endpoints/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/ngsi-ld/v1/entities",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(gateway
        .received_requests()
        .await
        .unwrap_or_default()
        .is_empty());

    // A run whose Portal sends no slug list may address its primary endpoint alone.
    let app = router(test_state_with_gateway(
        sample_run(false, "building"),
        &gateway.uri(),
    ));
    let resp = app
        .oneshot(ticketed(
            "GET",
            &format!("/v1/data/endpoints/{KPIS}/ngsi-ld/v1/entities"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A write tool of the MCP façade stays refused on a read-only run under a second endpoint.
#[tokio::test]
async fn a_write_tool_under_a_second_endpoint_is_refused_on_a_read_only_run() {
    use wiremock::MockServer;

    let gateway = MockServer::start().await;
    let app = router(test_state_with_gateway(
        two_endpoint_run(false),
        &gateway.uri(),
    ));
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "upsert_entity", "arguments": {} }
    });
    let resp = app
        .oneshot(ticketed(
            "POST",
            &format!("/v1/data/endpoints/{KPIS}/mcp"),
            Body::from(call.to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(gateway
        .received_requests()
        .await
        .unwrap_or_default()
        .is_empty());
}

/// AG-72: the profile's reasoning effort reaches the model provider on a call whose body names
/// none, beside everything the caller sent.
#[tokio::test]
async fn a_model_call_carries_the_profiles_reasoning_effort_upstream() {
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_json(serde_json::json!({
            "model": "google/gemini-3.8-flash",
            "messages": [],
            "reasoning": { "effort": "medium" },
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&provider)
        .await;

    let mut run = sample_run(false, "building");
    run.reasoning_effort = Some("medium".to_string());
    let app = router(test_state_with_upstreams(
        run,
        "http://context-gateway:8080",
        &provider.uri(),
    ));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/llm/v1/chat/completions")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::from(
            r#"{"model":"google/gemini-3.8-flash","messages":[]}"#,
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    provider.verify().await;
}

#[tokio::test]
async fn diagnostics_refuses_an_unknown_component_before_asking_anyone() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .uri("/v1/diagnostics/database/main")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn diagnostics_refuses_an_id_that_is_not_a_name() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .uri("/v1/diagnostics/pipeline/Hsl%20Bikes")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn diagnostics_needs_the_run_ticket_like_every_door() {
    let app = router(test_state(sample_run(false, "building")));
    let req = Request::builder()
        .uri("/v1/diagnostics/pipeline/hsl-bikes")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// An endpoint the assistant added to the conversation after the proxy cached the run is reached
/// on the first call: the proxy asks the Portal again before it refuses (AG-75).
#[tokio::test]
async fn an_endpoint_added_since_the_run_was_cached_is_reached_at_once() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let gateway = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/endpoint/{KPIS}/ngsi-ld/v1/entities")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&gateway)
        .await;
    let cached = sample_run(false, "interviewing");
    let portal = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/internal/agent-runs/{}", cached.id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": cached.id,
            "project": cached.project,
            "appName": cached.app_name,
            "endpointSlug": cached.endpoint_slug,
            "endpointSlugs": [cached.endpoint_slug, KPIS],
            "allowsWrite": false,
            "branch": cached.branch,
            "pathPrefix": cached.path_prefix,
            "status": "interviewing",
            "ticketHash": cached.ticket_hash,
            "maxTokens": 1000,
            "allowedHosts": [],
            "requestsPerMinute": 100,
            "maxResponseBytes": 1048576,
            "createdBy": cached.created_by,
            "modelName": cached.model_name,
        })))
        .expect(1)
        .mount(&portal)
        .await;

    let state = test_state_with_gateway(cached.clone(), &gateway.uri());
    let state = Arc::new(ProxyState {
        runs: RunResolver::with_cached_at(portal.uri().parse().unwrap(), cached),
        ..(*state).clone()
    });
    let resp = router(state)
        .oneshot(ticketed(
            "GET",
            &format!("/v1/data/endpoints/{KPIS}/ngsi-ld/v1/entities?type=KeyPerformanceIndicator"),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    gateway.verify().await;
    portal.verify().await;
}

/// T-0817: axum decodes the path once, so a double-encoded dot segment reaches the guard as
/// `%2e%2e`, which the URL parser on the way out would fold into `..`. Nothing encoded, no
/// dot segment and no empty segment gets past the application directory, and the forge is
/// never called for it.
#[tokio::test]
async fn a_double_encoded_dot_segment_never_leaves_the_application_directory() {
    let forge = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("PUT"))
        .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
        .mount(&forge)
        .await;
    let state = test_state_with_forge(sample_run(false, "building"), &forge.uri());
    for path in [
        "projects/helsinki/apps/bikes/%252e%252e/other/x",
        "projects/helsinki/apps/bikes/%2e%2e/other/x",
        "projects/helsinki/apps/bikes/./x",
        "projects/helsinki/apps/bikes//x",
        "projects/helsinki/apps/bikes/%2Fsecret",
    ] {
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/v1/forge/contents/{path}"))
            .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
            .header("x-jc-ticket", "secret-ticket-123")
            .body(Body::from("{}"))
            .unwrap();
        let resp = router(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert!(
        forge
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the forge was called"
    );

    // A file inside the directory still reaches the forge, on the run's branch.
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/forge/contents/projects/helsinki/apps/bikes/src/App.tsx")
        .header("x-jc-run", "e3b0c442-98fc-1c14-9afb-4c7b2756a120")
        .header("x-jc-ticket", "secret-ticket-123")
        .body(Body::from(r#"{"content":"aGk=","message":"add app"}"#))
        .unwrap();
    let resp = router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let calls = forge.received_requests().await.unwrap_or_default();
    assert_eq!(calls.len(), 1);
    assert!(calls[0]
        .url
        .path()
        .ends_with("/contents/projects/helsinki/apps/bikes/src/App.tsx"));
}
