//! Credential management and dynamic bearer token acquisition.

use crate::config::Config;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct CredentialManager {
    config: Arc<Config>,
    http: reqwest::Client,
    endpoint_tokens: Arc<Mutex<HashMap<String, (Instant, String)>>>,
}

impl CredentialManager {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            endpoint_tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_endpoint_token(&self, endpoint_slug: &str) -> Result<String, String> {
        let now = Instant::now();
        {
            let cache = self.endpoint_tokens.lock().await;
            if let Some((exp, token)) = cache.get(endpoint_slug) {
                if *exp > now + Duration::from_secs(30) {
                    return Ok(token.clone());
                }
            }
        }

        // Only reachable in tests: `Config::require_secrets` makes an empty secret a startup
        // failure, so a deployed proxy never mints a stub token.
        if self.config.oidc_client_secret.is_empty() {
            return Ok(format!("mock-token-for-{endpoint_slug}"));
        }

        let mut token_url = self.config.oidc_issuer.clone();
        token_url.set_path(&format!(
            "{}/protocol/openid-connect/token",
            token_url.path().trim_end_matches('/')
        ));

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.config.oidc_client_id),
            ("client_secret", &self.config.oidc_client_secret),
            ("audience", endpoint_slug),
        ];

        let resp = self
            .http
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            return Err(format!("token endpoint rejected grant: {}", resp.status()));
        }

        #[derive(serde::Deserialize)]
        struct TokenResp {
            access_token: String,
            expires_in: u64,
        }

        let data: TokenResp = resp.json().await.map_err(|e| e.to_string())?;
        let ttl = Duration::from_secs(data.expires_in.min(300));

        let mut cache = self.endpoint_tokens.lock().await;
        cache.insert(
            endpoint_slug.to_string(),
            (now + ttl, data.access_token.clone()),
        );

        Ok(data.access_token)
    }

    pub fn get_forge_token(&self) -> &str {
        &self.config.forge_token
    }

    pub fn get_model_key(&self) -> &str {
        &self.config.model_key
    }

    pub fn get_proxy_token(&self) -> &str {
        &self.config.proxy_token
    }
}
