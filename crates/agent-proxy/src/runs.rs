//! Resolves run parameters and permissions from Portal backend.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunContext {
    pub id: String,
    pub project: String,
    pub app_name: String,
    pub endpoint_slug: String,
    pub allows_write: bool,
    pub branch: String,
    pub path_prefix: String,
    pub status: String,
    pub ticket_hash: String,
    pub max_tokens: u64,
    pub allowed_hosts: Vec<String>,
    pub requests_per_minute: u32,
    pub max_response_bytes: u64,
    pub created_by: String,
    pub model_name: String,
}

/// Run records the proxy has fetched, with the moment each was fetched.
type RunCache = Arc<RwLock<HashMap<String, (Instant, Arc<RunContext>)>>>;

#[derive(Debug, Clone)]
pub struct RunResolver {
    http: reqwest::Client,
    portal_base: Url,
    proxy_token: String,
    cache: RunCache,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("run not found: {0}")]
    NotFound(String),
    #[error("run is in terminal state '{0}' and cannot execute")]
    NotActive(String),
    #[error("portal communication failure: {0}")]
    Transport(String),
}

impl RunResolver {
    pub fn new(portal_base: Url, proxy_token: String) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            portal_base,
            proxy_token,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_cached(run: RunContext) -> Self {
        let mut map = HashMap::new();
        map.insert(
            run.id.clone(),
            (Instant::now() + Duration::from_secs(3600), Arc::new(run)),
        );
        Self {
            http: reqwest::Client::new(),
            portal_base: Url::parse("http://portal").unwrap(),
            proxy_token: "test".to_string(),
            cache: Arc::new(RwLock::new(map)),
        }
    }

    pub async fn resolve(&self, run_id: &str) -> Result<Arc<RunContext>, RunError> {
        let now = Instant::now();
        {
            let cache = self.cache.read().await;
            if let Some((exp, run)) = cache.get(run_id) {
                if *exp > now {
                    Self::check_status(run)?;
                    return Ok(Arc::clone(run));
                }
            }
        }

        let mut url = self.portal_base.clone();
        url.set_path(&format!("internal/agent-runs/{run_id}"));

        let mut req = self.http.get(url);
        if !self.proxy_token.is_empty() {
            req = req.bearer_auth(&self.proxy_token);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| RunError::Transport(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RunError::NotFound(run_id.to_string()));
        }
        if !resp.status().is_success() {
            return Err(RunError::Transport(format!("status {}", resp.status())));
        }

        let run: RunContext = resp
            .json()
            .await
            .map_err(|e| RunError::Transport(e.to_string()))?;
        Self::check_status(&run)?;

        let arc = Arc::new(run);
        let mut cache = self.cache.write().await;
        cache.insert(
            run_id.to_string(),
            (now + Duration::from_secs(5), Arc::clone(&arc)),
        );

        Ok(arc)
    }

    fn check_status(run: &RunContext) -> Result<(), RunError> {
        match run.status.as_str() {
            "failed" | "cancelled" | "expired" | "published" => {
                Err(RunError::NotActive(run.status.clone()))
            }
            _ => Ok(()),
        }
    }
}
