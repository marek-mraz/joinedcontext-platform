//! T-0154: the token bucket, and what a caller learns from the headers (EP-20, MIM0-R7, OPS-35).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use context_gateway::app::{router, Gateway};
use context_gateway::middleware::rate_limit::RateLimiter;
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::Endpoint;
use jc_core::kinds::{Audience, RateLimits, Representation};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt;

const SLUG: &str = "zt4qm7ge2xdv6ksb3ncf5arw2y";

fn limits(per_minute: u32, burst: Option<u32>) -> RateLimits {
    RateLimits {
        requests_per_minute: per_minute,
        burst,
    }
}

fn endpoint(rate_limit: Option<RateLimits>) -> Endpoint {
    Endpoint {
        slug: SLUG.to_owned(),
        space: "ovzdusie".to_owned(),
        project: "ovzdusie".to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd, Representation::GeoJson],
        rate_limit,
        file_limits: None,
        hidden_attributes: Default::default(),
        base_path: format!("/api/endpoint/{SLUG}"),
        models: Vec::new(),
        view_mapping: None,
        policies: Vec::new(),
    }
}

#[test]
fn a_burst_is_spent_once_and_then_refills_at_the_steady_rate() {
    let limiter = RateLimiter::new();
    let limits = limits(60, Some(3));
    let start = Instant::now();

    for expected_remaining in [2, 1, 0] {
        let decision = limiter.check(SLUG, "address:10.0.0.1", &limits, start);
        assert!(decision.allowed);
        assert_eq!(decision.remaining, expected_remaining);
        assert_eq!(decision.limit, 60, "the header advertises the steady quota");
    }

    let refused = limiter.check(SLUG, "address:10.0.0.1", &limits, start);
    assert!(!refused.allowed, "the fourth request has no token left");
    assert_eq!(refused.remaining, 0);
    assert_eq!(refused.reset, 1, "60/minute is one token per second");

    // One second later exactly one token exists again, and only one.
    let after = start + Duration::from_secs(1);
    assert!(
        limiter
            .check(SLUG, "address:10.0.0.1", &limits, after)
            .allowed
    );
    assert!(
        !limiter
            .check(SLUG, "address:10.0.0.1", &limits, after)
            .allowed
    );
}

#[test]
fn one_callers_burst_is_not_another_callers() {
    let limiter = RateLimiter::new();
    let limits = limits(60, Some(1));
    let now = Instant::now();

    assert!(limiter.check(SLUG, "credential:aaaa", &limits, now).allowed);
    assert!(!limiter.check(SLUG, "credential:aaaa", &limits, now).allowed);
    assert!(
        limiter.check(SLUG, "credential:bbbb", &limits, now).allowed,
        "a second caller has a bucket of their own"
    );
    assert!(
        limiter
            .check("other-slug", "credential:aaaa", &limits, now)
            .allowed,
        "and so has the same caller on another endpoint"
    );
}

#[test]
fn a_bucket_never_holds_more_than_its_burst_however_long_the_caller_waits() {
    let limiter = RateLimiter::new();
    let limits = limits(600, Some(2));
    let start = Instant::now();

    assert!(
        limiter
            .check(SLUG, "address:10.0.0.9", &limits, start)
            .allowed
    );
    // An hour of silence refills the bucket, but only to its capacity.
    let later = start + Duration::from_secs(3600);
    assert!(
        limiter
            .check(SLUG, "address:10.0.0.9", &limits, later)
            .allowed
    );
    assert!(
        limiter
            .check(SLUG, "address:10.0.0.9", &limits, later)
            .allowed
    );
    assert!(
        !limiter
            .check(SLUG, "address:10.0.0.9", &limits, later)
            .allowed,
        "waiting does not bank more than one burst"
    );
}

#[test]
fn without_a_burst_the_bucket_is_the_whole_minute_quota() {
    let limiter = RateLimiter::new();
    let limits = limits(3, None);
    let now = Instant::now();

    for _ in 0..3 {
        assert!(
            limiter
                .check(SLUG, "address:10.0.0.2", &limits, now)
                .allowed
        );
    }
    let refused = limiter.check(SLUG, "address:10.0.0.2", &limits, now);
    assert!(!refused.allowed);
    assert_eq!(refused.reset, 20, "3 per minute is one token every 20 s");
}

/// The whole surface, through the real router: the layer answers 429 and every answer
/// carries the three standard fields (EP-20).
#[tokio::test]
async fn the_surface_answers_429_with_the_standard_headers_when_the_bucket_is_empty() {
    let gateway = Gateway::new(
        Broker::new("http://127.0.0.1:1".to_owned()),
        Box::new(PolicyPdp),
        "banskabystrica.sk",
    )
    .serve([endpoint(Some(limits(60, Some(1))))]);
    let app = router(Arc::new(gateway));

    let call = |app: axum::Router| async move {
        app.oneshot(
            Request::builder()
                .uri(format!("/api/endpoint/{SLUG}/schema/index.json"))
                .header("x-forwarded-for", "203.0.113.7")
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the stack answers")
    };

    let first = call(app.clone()).await;
    assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(first.headers()["ratelimit-limit"], "60");
    assert_eq!(first.headers()["ratelimit-remaining"], "0");
    assert_eq!(first.headers()["ratelimit-reset"], "0");

    let second = call(app.clone()).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers()["ratelimit-remaining"], "0");
    assert_eq!(second.headers()["ratelimit-reset"], "1");
    assert_eq!(
        second.headers()["retry-after"],
        "1",
        "a client that reads only Retry-After still waits the right time"
    );
}

/// The forwarded-for header is written by the proxy in front, and a client that sends one
/// itself only prepends to its own value, so the entry read is never the spoofed one.
#[tokio::test]
async fn a_client_cannot_spend_another_addresss_quota_by_forging_forwarded_for() {
    let gateway = Gateway::new(
        Broker::new("http://127.0.0.1:1".to_owned()),
        Box::new(PolicyPdp),
        "banskabystrica.sk",
    )
    .serve([endpoint(Some(limits(60, Some(1))))]);
    let app = router(Arc::new(gateway));

    let spoofer = |app: axum::Router| async move {
        app.oneshot(
            Request::builder()
                .uri(format!("/api/endpoint/{SLUG}/schema/index.json"))
                // "the victim, then what the proxy saw": the proxy appends, so the last
                // entry is the real peer.
                .header("x-forwarded-for", "198.51.100.5, 203.0.113.9")
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the stack answers")
    };

    assert_ne!(
        spoofer(app.clone()).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        spoofer(app.clone()).await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the spoofer spends their own bucket"
    );

    let victim = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/endpoint/{SLUG}/schema/index.json"))
                .header("x-forwarded-for", "198.51.100.5")
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the stack answers");
    assert_ne!(
        victim.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the address the spoofer named still has its full bucket"
    );
}

/// A liveness probe must never be refused because a caller emptied a bucket, and an
/// endpoint that declares no limits is not limited by this layer at all.
#[tokio::test]
async fn probes_and_unlimited_endpoints_are_never_throttled() {
    let gateway = Gateway::new(
        Broker::new("http://127.0.0.1:1".to_owned()),
        Box::new(PolicyPdp),
        "banskabystrica.sk",
    )
    .serve([endpoint(None)]);
    let app = router(Arc::new(gateway));

    for _ in 0..5 {
        let probe = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("the stack answers");
        assert_eq!(probe.status(), StatusCode::OK);
        assert!(probe.headers().get("ratelimit-limit").is_none());

        let unlimited = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/endpoint/{SLUG}/schema/index.json"))
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("the stack answers");
        assert_ne!(unlimited.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
