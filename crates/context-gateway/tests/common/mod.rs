//! A throwaway realm, so no signing key is ever written into the repository.
//!
//! One P-256 key is generated per test run and published as a JWKS exactly the way
//! Keycloak publishes one, which means the verifier is exercised through the path it uses
//! in production rather than through a back door built for the test.

#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use context_gateway::auth::token::Verifier;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

/// The realm the gateway is configured with in every test.
pub const ISSUER: &str = "https://2.28.67.127.sslip.io/realms/joinedcontext";
/// The key id the realm publishes.
pub const KID: &str = "realm-key-1";

/// A realm: one signing key, its JWKS, and the ability to mint a token.
pub struct Realm {
    signing: EncodingKey,
    jwks: JwkSet,
}

impl Realm {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("a key pair");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("the pair round-trips");

        // An uncompressed P-256 point: 0x04 || x(32) || y(32), which is exactly what a
        // JWK's `x` and `y` carry, base64url without padding.
        let point = pair.public_key().as_ref();
        assert_eq!(point.len(), 65, "an uncompressed P-256 point");
        let jwks = serde_json::from_value(json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "kid": KID,
                "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&point[33..]),
            }]
        }))
        .expect("a JWKS");

        Self {
            signing: EncodingKey::from_ec_der(pkcs8.as_ref()),
            jwks,
        }
    }

    /// A verifier that trusts this realm and nothing else.
    pub fn verifier(&self) -> Verifier {
        let verifier = Verifier::new(ISSUER);
        assert_eq!(verifier.replace_keys(&self.jwks), 1, "one usable key");
        verifier
    }

    /// Signs any claim set, so a test can mint the malformed ones too.
    pub fn mint(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(KID.to_owned());
        encode(&header, claims, &self.signing).expect("the realm signs")
    }

    /// Signs with a key id the realm does not publish.
    pub fn mint_with_kid(&self, kid: &str, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_owned());
        encode(&header, claims, &self.signing).expect("the realm signs")
    }

    /// Signs without naming a key at all.
    pub fn mint_without_kid(&self, claims: &Value) -> String {
        encode(&Header::new(Algorithm::ES256), claims, &self.signing).expect("the realm signs")
    }

    /// The `client_credentials` token of one workload, bound to one resource.
    pub fn workload_token(&self, azp: &str, audience: Value) -> String {
        self.mint(&json!({
            "iss": ISSUER,
            "sub": format!("service-account-{azp}"),
            "aud": audience,
            "azp": azp,
            "exp": in_seconds(300),
            "iat": in_seconds(-10),
        }))
    }
}

/// A Unix timestamp `offset` seconds from now.
pub fn in_seconds(offset: i64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs() as i64;
    now + offset
}

/// Base64url without padding, for the tokens a test forges by hand.
pub fn b64(raw: &str) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

/// What the broker was asked for on one hop.
#[derive(Debug, Clone, Default)]
pub struct Hop {
    /// The path, which must be the plain CIM 009 tree with no surface prefix left on it.
    pub path: String,
    /// The query string as the gateway rewrote it.
    pub query: String,
    /// The tenant the gateway pinned (GW25).
    pub tenant: String,
    /// Whether any value the client forged survived the hop.
    pub forged: bool,
}

/// A broker on a real socket, because the gateway forwards over HTTP and what these tests
/// assert is what comes out of the other end.
///
/// `pages` are answered in order and the last one repeats, so a test can hand back one
/// full page followed by a short one and watch the gateway page through them (EP-44).
pub struct BrokerStub {
    /// The base URL to build a [`context_gateway::proxy::Broker`] from.
    pub url: String,
    /// Every hop the gateway made, in order.
    pub hops: std::sync::Arc<std::sync::Mutex<Vec<Hop>>>,
}

impl BrokerStub {
    /// Starts the stub and answers `pages` in order.
    pub async fn start(pages: Vec<Value>) -> Self {
        let hops = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let served = std::sync::Arc::new(std::sync::Mutex::new(pages));
        let recorder = std::sync::Arc::clone(&hops);

        let app = axum::Router::new().fallback(axum::routing::any(
            move |request: axum::extract::Request| {
                let (recorder, served) = (
                    std::sync::Arc::clone(&recorder),
                    std::sync::Arc::clone(&served),
                );
                async move {
                    let headers = request.headers().clone();
                    let mut hops = recorder.lock().expect("no poisoned lock");
                    hops.push(Hop {
                        path: request.uri().path().to_owned(),
                        query: request.uri().query().unwrap_or_default().to_owned(),
                        tenant: headers
                            .get("NGSILD-Tenant")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned(),
                        forged: headers
                            .get_all("NGSILD-Tenant")
                            .iter()
                            .any(|value| value.as_bytes() == b"somebody-elses-space"),
                    });
                    let pages = served.lock().expect("no poisoned lock");
                    let index = (hops.len() - 1).min(pages.len().saturating_sub(1));
                    axum::Json(pages.get(index).cloned().unwrap_or_else(|| json!([])))
                }
            },
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let port = listener.local_addr().expect("an address").port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://127.0.0.1:{port}"),
            hops,
        }
    }

    /// The hops the gateway made, cloned out of the recorder.
    pub fn hops(&self) -> Vec<Hop> {
        self.hops.lock().expect("no poisoned lock").clone()
    }
}
