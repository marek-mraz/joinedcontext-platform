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
    }
}

fn test_state(run: RunContext) -> Arc<ProxyState> {
    let config = Config::from_lookup(|k| match k {
        "JC_PROXY_BIND" => Some("127.0.0.1:0".to_string()),
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
