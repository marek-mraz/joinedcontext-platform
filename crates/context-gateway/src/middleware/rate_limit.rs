//! Token-bucket rate limiting per endpoint and caller (T-0154, EP-20, MIM0-R7, OPS-35).
//!
//! One bucket per `(slug, caller)`: the presented credential when there is one, the client
//! address when there is not. Keying an anonymous caller by address is the only thing a
//! public endpoint can key on, and keying a credentialed one by its digest is what stops
//! two clients behind one NAT from spending each other's quota.
//!
//! `spec.rateLimits.requestsPerMinute` is the steady rate and `burst` the bucket size, so
//! a caller may spend a burst at once and then goes at the steady rate. An endpoint that
//! declares no limits is not limited here; APISIX in front still has its own.
//!
//! The counter is in this process. Two replicas therefore allow up to twice the configured
//! rate, which is the honest trade for a limiter that costs a mutex and no round trip.
// ponytail: in-process buckets, one lock. A shared counter (Redis, the mesh) is a
// different component, and worth it only when a measurement says the per-replica bound
// is too loose.

use crate::app::Gateway;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Response};
use axum::middleware::Next;
use axum::response::IntoResponse;
use jc_core::kinds::RateLimits;
use jc_core::ProblemDetails;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Buckets are dropped once they have been full and untouched for this long: a caller that
/// stopped calling has nothing left to remember, and the map must not grow with every
/// address that ever appeared.
const IDLE_EVICTION: Duration = Duration::from_secs(300);

/// What the limiter decided, and everything the response headers need (EP-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Whether the request may proceed.
    pub allowed: bool,
    /// The steady quota, in requests per minute: `RateLimit-Limit`.
    pub limit: u32,
    /// Whole requests still available right now: `RateLimit-Remaining`.
    pub remaining: u32,
    /// Seconds until the caller may spend again: `RateLimit-Reset`, and `Retry-After`
    /// when the answer is 429. Zero while requests are still available.
    pub reset: u64,
}

/// One caller's bucket.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// The buckets of every caller of every endpoint (EP-20).
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<(String, String), Bucket>>,
}

impl RateLimiter {
    /// A limiter with no buckets yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spends one request of `caller`'s quota on `slug`, at `now`.
    ///
    /// `now` is a parameter so a test can drive the clock instead of sleeping through a
    /// minute of refill.
    pub fn check(&self, slug: &str, caller: &str, limits: &RateLimits, now: Instant) -> Decision {
        let rate = f64::from(limits.requests_per_minute) / 60.0;
        let capacity = f64::from(limits.burst.unwrap_or(limits.requests_per_minute)).max(1.0);
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            // A panicking holder poisoned the lock; the counters are just numbers and
            // refusing every request afterwards would be a worse failure than continuing.
            Err(poisoned) => poisoned.into_inner(),
        };
        evict_idle(&mut buckets, capacity, now);

        let bucket = buckets
            .entry((slug.to_owned(), caller.to_owned()))
            .or_insert(Bucket {
                tokens: capacity,
                last: now,
            });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Decision {
                allowed: true,
                limit: limits.requests_per_minute,
                remaining: bucket.tokens as u32,
                reset: 0,
            }
        } else {
            // Seconds until one whole token exists again, rounded up: a client that waits
            // exactly this long is never refused for being a fraction early.
            let missing = 1.0 - bucket.tokens;
            let wait = if rate > 0.0 { missing / rate } else { 60.0 };
            Decision {
                allowed: false,
                limit: limits.requests_per_minute,
                remaining: 0,
                reset: wait.ceil() as u64,
            }
        }
    }

    /// How many buckets are held, which is what an eviction test looks at.
    pub fn len(&self) -> usize {
        match self.buckets.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Whether no caller has been seen yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Drops buckets that have been idle long enough to be full again: they would hand out a
/// full burst anyway, so remembering them changes nothing but the memory.
fn evict_idle(buckets: &mut HashMap<(String, String), Bucket>, capacity: f64, now: Instant) {
    if buckets.len() < 1024 {
        return;
    }
    buckets.retain(|_, bucket| {
        now.saturating_duration_since(bucket.last) < IDLE_EVICTION || bucket.tokens < capacity
    });
}

/// The layer every endpoint surface passes: one bucket spent, the headers of the standard
/// `RateLimit` field set on the answer, 429 when the bucket is empty (EP-20, MIM0-R7).
pub async fn enforce(
    State(gateway): State<Arc<Gateway>>,
    request: Request,
    next: Next,
) -> Response<Body> {
    let Some(endpoint) = slug_of(request.uri().path()).and_then(|s| gateway.resolver.resolve(s))
    else {
        // An unknown slug costs nobody quota: the handler answers 404 (EP-03).
        return next.run(request).await;
    };
    let Some(limits) = endpoint.rate_limit.clone() else {
        return next.run(request).await;
    };

    let caller = caller_key(&request);
    let decision = gateway
        .rate_limiter
        .check(&endpoint.slug, &caller, &limits, Instant::now());
    if !decision.allowed {
        tracing::info!(slug = %endpoint.slug, "rate limit reached");
        let mut refusal = ProblemDetails::new(429, "too-many-requests", "Too Many Requests")
            .with_detail("the endpoint's rate limit is spent; retry after the seconds the RateLimit-Reset header names")
            .into_response();
        set_headers(refusal.headers_mut(), &decision);
        if let Ok(value) = HeaderValue::from_str(&decision.reset.to_string()) {
            refusal.headers_mut().insert("retry-after", value);
        }
        return refusal;
    }

    let mut response = next.run(request).await;
    set_headers(response.headers_mut(), &decision);
    response
}

/// The slug in `/api/endpoint/{slug}/…`, or nothing off the endpoint surface.
fn slug_of(path: &str) -> Option<&str> {
    path.strip_prefix("/api/endpoint/")?
        .split('/')
        .next()
        .filter(|slug| !slug.is_empty())
}

/// Who is spending the quota: the presented credential when there is one, the client
/// address otherwise (EP-20).
///
/// The credential is keyed by digest, never stored or logged, and the token is not
/// verified here — this is a counter, not a decision, and the handler still rejects a
/// forged token with 401. Keying it means two callers behind one NAT do not spend each
/// other's quota, which keying by address alone cannot give them.
///
/// The address comes from the LAST `X-Forwarded-For` entry, which is the peer the gateway's
/// own proxy saw. A client that sends the header itself only prepends to its own value,
/// so a spoofed entry is never the one read.
fn caller_key(request: &Request) -> String {
    if let Some(credential) = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        let digest = ring::digest::digest(&ring::digest::SHA256, credential.as_bytes());
        let hex: String = digest.as_ref()[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        return format!("credential:{hex}");
    }
    let address = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    format!("address:{address}")
}

/// The three standard fields of the answer (EP-20, MIM0-R7).
fn set_headers(headers: &mut axum::http::HeaderMap, decision: &Decision) {
    for (name, value) in [
        ("ratelimit-limit", decision.limit.to_string()),
        ("ratelimit-remaining", decision.remaining.to_string()),
        ("ratelimit-reset", decision.reset.to_string()),
    ] {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(name, value);
        }
    }
}
