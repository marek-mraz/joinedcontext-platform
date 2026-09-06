//! Forwarding a request to the broker behind an endpoint (T-0005, EP-01, GW20).
//!
//! The upstream is fixed at start-up and the forwarded path is built from the route the
//! router matched, so nothing a client sends can point the gateway at a different host or
//! a different resource tree.
//!
//! Hop-by-hop headers are dropped in both directions: they describe one TCP connection,
//! and this is two.

use axum::body::Body;
use axum::http::header::{HeaderName, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use jc_core::ProblemDetails;

/// Headers that belong to one connection and must not be relayed to the next (RFC 9110
/// section 7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The broker the gateway forwards to.
#[derive(Debug, Clone)]
pub struct Broker {
    client: Client<HttpConnector, Body>,
    base: String,
}

/// Why a forwarded request produced no answer.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// The gateway could not build a legal upstream URI from the matched route.
    #[error("cannot address the broker: {0}")]
    Uri(String),
    /// The broker did not answer.
    #[error("the broker did not answer: {0}")]
    Unreachable(String),
}

impl From<ProxyError> for ProblemDetails {
    fn from(error: ProxyError) -> Self {
        // The caller learns that the platform, not their request, is at fault, and nothing
        // about the topology behind the endpoint.
        tracing::error!(%error, "forwarding failed");
        ProblemDetails::new(502, "upstream-unavailable", "Broker Unavailable")
    }
}

impl Broker {
    /// A client for the broker at `base`, which is scheme and authority only.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            base: base.into(),
        }
    }

    /// The upstream this gateway forwards to.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Forwards one request and returns the broker's answer.
    ///
    /// `path_and_query` is absolute and already percent-encoded, as it came off the wire:
    /// re-encoding it would corrupt the URN in an entity path.
    pub async fn send(
        &self,
        method: Method,
        path_and_query: &str,
        headers: HeaderMap,
        body: Body,
    ) -> Result<Response<Body>, ProxyError> {
        let uri: Uri = format!("{}{path_and_query}", self.base)
            .parse()
            .map_err(|e: axum::http::uri::InvalidUri| ProxyError::Uri(e.to_string()))?;

        let mut upstream = axum::http::Request::builder().method(method).uri(&uri);
        let out = upstream.headers_mut().expect("a fresh builder has headers");
        copy_relayable(&headers, out);
        // The upstream authority is ours, not the client's.
        out.remove(HOST);

        let request = upstream
            .body(body)
            .map_err(|e| ProxyError::Uri(e.to_string()))?;

        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| ProxyError::Unreachable(e.to_string()))?;

        let (parts, body) = response.into_parts();
        let mut answer = Response::builder().status(parts.status);
        let out = answer.headers_mut().expect("a fresh builder has headers");
        copy_relayable(&parts.headers, out);
        answer
            .body(Body::new(body))
            .map_err(|e| ProxyError::Uri(e.to_string()))
    }
}

/// Copies every header that describes the message rather than the connection.
fn copy_relayable(from: &HeaderMap, to: &mut HeaderMap) {
    // A `Connection: x` header names further headers that are hop-by-hop for this hop.
    let named: Vec<HeaderName> = from
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::try_from(name.trim()).ok())
        .collect();

    for (name, value) in from {
        if HOP_BY_HOP.contains(&name.as_str()) || named.contains(name) {
            continue;
        }
        to.append(name.clone(), value.clone());
    }
}

/// Replaces a buffered body, so the length the broker or the client reads is the length of
/// what it is actually given.
pub fn with_body(mut parts: axum::http::response::Parts, bytes: Vec<u8>) -> Response<Body> {
    parts.headers.remove(CONTENT_LENGTH);
    parts.headers.remove(TRANSFER_ENCODING);
    parts.headers.insert(
        CONTENT_LENGTH,
        axum::http::HeaderValue::from(bytes.len() as u64),
    );
    if parts.status == StatusCode::NO_CONTENT {
        return Response::from_parts(parts, Body::empty());
    }
    Response::from_parts(parts, Body::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn hop_by_hop_headers_do_not_cross_the_gateway() {
        let mut from = HeaderMap::new();
        from.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret-hop"),
        );
        from.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        from.insert("x-secret-hop", HeaderValue::from_static("leaked"));
        from.insert(
            "content-type",
            HeaderValue::from_static("application/ld+json"),
        );

        let mut to = HeaderMap::new();
        copy_relayable(&from, &mut to);

        assert_eq!(
            to.get("content-type").expect("relayed"),
            "application/ld+json"
        );
        for dropped in ["connection", "keep-alive", "x-secret-hop"] {
            assert!(!to.contains_key(dropped), "{dropped} crossed the gateway");
        }
    }
}
