//! Where the gateway listens, what it forwards to, and where it reads its endpoints from
//! (T-0005, OPS-12).
//!
//! Everything comes from the environment, because the deployment sets it and no request
//! can. The broker URL in particular is never derived from anything a client sends: the
//! gateway forwards to exactly one upstream, chosen before the first request arrives.

use std::net::SocketAddr;
use std::path::PathBuf;

/// The gateway's runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The address to listen on (`JC_GATEWAY_BIND`, default `0.0.0.0:8080`).
    pub bind: SocketAddr,
    /// The broker to forward to, scheme and authority only (`JC_GATEWAY_BROKER_URL`).
    pub broker_url: String,
    /// The manifest repository the endpoint table is built from
    /// (`JC_GATEWAY_REPO_DIR`); absent means an empty table until one is loaded.
    pub repo_dir: Option<PathBuf>,
    /// The organization's verified domain, the middle segment of every entity URN
    /// (`JC_GATEWAY_ORG_DOMAIN`).
    pub org_domain: String,
    /// The realm every token must be issued by (`JC_OIDC_ISSUER`); absent means the
    /// gateway serves public endpoints only and refuses every presented token.
    pub oidc_issuer: Option<String>,
    /// The realm's JWKS, fetched in the background (`JC_OIDC_JWKS_URL`).
    pub oidc_jwks_url: Option<String>,
    /// The gateway's own public base URL (`JC_GATEWAY_PUBLIC_URL`), which makes the full
    /// RFC 8707 resource URI an acceptable token audience alongside the endpoint slug.
    pub public_url: Option<String>,
    /// The base a rewritten `notification.endpoint.uri` carries
    /// (`JC_GATEWAY_EGRESS_URL`), which is the address the broker dials to deliver; the
    /// public URL when the deployment names none. An in-cluster Service URL keeps the
    /// delivery hop inside the cluster, where a NetworkPolicy governs it (R46).
    pub egress_url: Option<String>,
    /// A PEM file of extra trust anchors the notification egress trusts on top of the
    /// public roots (`JC_GATEWAY_EGRESS_CA_BUNDLE`), for subscribers behind the
    /// installation's own CA (R46).
    pub egress_ca_bundle: Option<PathBuf>,
}

/// Why the environment does not describe a runnable gateway.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A variable the gateway cannot invent a default for is missing.
    #[error("{0} is not set")]
    Missing(&'static str),
    /// A variable is set to something the gateway cannot use.
    #[error("{name} is not usable: {reason}")]
    Invalid {
        /// The variable.
        name: &'static str,
        /// What is wrong with it.
        reason: String,
    },
}

impl Config {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = match std::env::var("JC_GATEWAY_BIND") {
            Err(_) => "0.0.0.0:8080".to_owned(),
            Ok(value) => value,
        };
        let bind = bind
            .parse()
            .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                name: "JC_GATEWAY_BIND",
                reason: e.to_string(),
            })?;

        let broker_url = std::env::var("JC_GATEWAY_BROKER_URL")
            .map_err(|_| ConfigError::Missing("JC_GATEWAY_BROKER_URL"))?;
        let broker_url = normalize_broker_url(&broker_url)?;

        let org_domain = std::env::var("JC_GATEWAY_ORG_DOMAIN")
            .map_err(|_| ConfigError::Missing("JC_GATEWAY_ORG_DOMAIN"))?;

        let oidc_issuer = std::env::var("JC_OIDC_ISSUER").ok();
        let oidc_jwks_url = std::env::var("JC_OIDC_JWKS_URL").ok();
        if oidc_issuer.is_some() != oidc_jwks_url.is_some() {
            return Err(ConfigError::Invalid {
                name: "JC_OIDC_ISSUER",
                reason: "an issuer without a JWKS URL verifies nothing, and a JWKS URL without an issuer accepts any realm; set both or neither".to_owned(),
            });
        }

        Ok(Self {
            bind,
            broker_url,
            repo_dir: std::env::var("JC_GATEWAY_REPO_DIR").ok().map(PathBuf::from),
            org_domain,
            oidc_issuer,
            oidc_jwks_url,
            public_url: std::env::var("JC_GATEWAY_PUBLIC_URL")
                .ok()
                .map(|url| url.trim_end_matches('/').to_owned()),
            egress_url: std::env::var("JC_GATEWAY_EGRESS_URL")
                .ok()
                .map(|url| url.trim_end_matches('/').to_owned()),
            egress_ca_bundle: std::env::var("JC_GATEWAY_EGRESS_CA_BUNDLE")
                .ok()
                .filter(|path| !path.trim().is_empty())
                .map(PathBuf::from),
        })
    }
}

/// Reduces the configured broker URL to `scheme://authority`, with no trailing slash.
///
/// The forwarded path is always built by the gateway from the route it matched, so a base
/// that carried a path of its own would silently prefix every request; refusing it here is
/// cheaper than debugging it later.
fn normalize_broker_url(raw: &str) -> Result<String, ConfigError> {
    let invalid = |reason: &str| ConfigError::Invalid {
        name: "JC_GATEWAY_BROKER_URL",
        reason: reason.to_owned(),
    };
    let trimmed = raw.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .ok_or_else(|| invalid("must start with http:// or https://"))?;

    if rest.is_empty() {
        return Err(invalid("has no host"));
    }
    if rest.contains('/') {
        return Err(invalid("must be scheme and authority only, with no path"));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_url_is_reduced_to_scheme_and_authority() {
        assert_eq!(
            normalize_broker_url("http://antares:9090/"),
            Ok("http://antares:9090".to_owned())
        );
        assert_eq!(
            normalize_broker_url("  https://broker.example  "),
            Ok("https://broker.example".to_owned())
        );
        for bad in [
            "antares:9090",
            "http://",
            "http://antares:9090/ngsi-ld/v1",
            "",
        ] {
            assert!(normalize_broker_url(bad).is_err(), "{bad:?} was accepted");
        }
    }
}
