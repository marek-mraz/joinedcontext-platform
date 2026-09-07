//! Forwarding a request to the broker behind an endpoint (T-0005, EP-01, GW20).
//!
//! The upstream is fixed at start-up and the forwarded path is built from the route the
//! router matched, so nothing a client sends can point the gateway at a different host or
//! a different resource tree.
//!
//! Hop-by-hop headers are dropped in both directions: they describe one TCP connection,
//! and this is two.
//!
//! The same client carries the notification egress (R46), where the target is a subscriber's
//! own webhook rather than the broker, so it speaks TLS when the URL asks for it. The broker
//! hop stays plain `http://` in the cluster, where Linkerd carries the mTLS.

use axum::body::Body;
use axum::http::header::{HeaderName, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use jc_core::ProblemDetails;
use rustls::RootCertStore;

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
    client: Client<HttpsConnector<HttpConnector>, Body>,
    base: String,
}

/// Why a forwarded request produced no answer.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// The gateway could not build a legal upstream URI from the matched route.
    #[error("cannot address the broker: {0}")]
    Uri(String),
    /// The extra trust anchors the deployment named cannot be used. Never an answer to a
    /// request: the gateway refuses to start rather than deliver to an unverified peer.
    #[error("the egress CA bundle holds no usable certificate: {0}")]
    Trust(String),
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
    ///
    /// TLS is verified against the public roots compiled into the binary, so the image needs
    /// no CA bundle of its own.
    pub fn new(base: impl Into<String>) -> Self {
        Self::with(base, public_roots())
    }

    /// The same, trusting the certificates in `bundle` (PEM) on top of the public roots.
    ///
    /// This is `JC_GATEWAY_EGRESS_CA_BUNDLE`: an installation whose subscribers sit behind its
    /// own CA. A bundle that parses to nothing is an error rather than a silent fallback to
    /// the public roots, because a delivery that lost a trust anchor is a delivery to
    /// somebody else (R46).
    pub fn trusting(base: impl Into<String>, bundle: &[u8]) -> Result<Self, ProxyError> {
        let mut roots = public_roots();
        let mut added = 0usize;
        for certificate in rustls_pemfile::certs(&mut std::io::BufReader::new(bundle)) {
            let certificate = certificate.map_err(|e| ProxyError::Trust(e.to_string()))?;
            roots
                .add(certificate)
                .map_err(|e| ProxyError::Trust(e.to_string()))?;
            added += 1;
        }
        match added {
            0 => Err(ProxyError::Trust(
                "no CERTIFICATE block in the bundle".to_owned(),
            )),
            _ => Ok(Self::with(base, roots)),
        }
    }

    /// The same client aimed at another origin (the egress dispatcher's target, R46).
    ///
    /// The connection pool and the trust anchors are shared: a delivery reuses the
    /// connection to a subscriber it already spoke to, and cannot trust more than the
    /// gateway was configured to.
    pub fn aimed_at(&self, origin: impl Into<String>) -> Self {
        Self {
            client: self.client.clone(),
            base: origin.into(),
        }
    }

    fn with(base: impl Into<String>, roots: RootCertStore) -> Self {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            // Plain HTTP stays available: the broker hop is in-cluster and never TLS.
            .https_or_http()
            .enable_http1()
            .build();
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
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

/// The public trust anchors, compiled in rather than read from the image (R46).
fn public_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
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
