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
