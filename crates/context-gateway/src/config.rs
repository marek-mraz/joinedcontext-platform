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

        Ok(Self {
            bind,
            broker_url,
            repo_dir: std::env::var("JC_GATEWAY_REPO_DIR").ok().map(PathBuf::from),
            org_domain,
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
