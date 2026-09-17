//! What the gateway concluded internally never leaves in a header the caller did not ask
//! for (SP-05, R22).
//!
//! The counterpart of [`super::tenancy::strip_client_headers`]: that one removes what a
//! client said on the way in, this one removes what the gateway said on the way out. One
//! layer rather than a line at every place that builds an answer, so a handler added later
//! cannot forget it.

use axum::extract::Request;
use axum::http::HeaderName;
use axum::middleware::Next;
use axum::response::Response;

/// The narrowing signal. Opt-in: a caller who sends it on the request is told when an answer
/// was narrowed, and a caller who does not ask is answered as if the result were simply what
/// it is (R22, GW12). It tells a prober that something was there to hide.
pub const RESULTS_RESTRICTED: HeaderName = HeaderName::from_static("ngsild-results-restricted");

/// Whether the request asked to be told about narrowing (R22).
pub fn asked_about_narrowing(request: &Request) -> bool {
    request
        .headers()
        .get_all(&RESULTS_RESTRICTED)
        .iter()
        .any(|value| value.as_bytes().eq_ignore_ascii_case(b"true"))
}

/// Removes the tenant from every answer, and the narrowing signal from every answer nobody
/// asked for it in.
pub async fn scrub(request: Request, next: Next) -> Response {
    let asked = asked_about_narrowing(&request);
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // The tenant is an internal name and a probe for which spaces exist. It is pinned on the
    // hop to the broker and it never comes back out, on either surface (SP-05).
    while headers.remove(&super::tenancy::TENANT).is_some() {}
    if !asked {
        while headers.remove(&RESULTS_RESTRICTED).is_some() {}
    }
    response
}
