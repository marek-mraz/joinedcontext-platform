//! Main binary entry point for `jc-agent-proxy`.

use agent_proxy::{
    config::Config, inject::CredentialManager, limits::LimitManager, router, runs::RunResolver,
    ProxyState,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Config::from_env()?;
    config.require_secrets()?;
    tracing::info!(bind = %config.bind, "starting jc-agent-proxy daemon");

    let runs = RunResolver::new(config.portal_base.clone(), config.proxy_token.clone());
    let config_arc = Arc::new(config.clone());
    let credentials = CredentialManager::new(config_arc.clone());
    let limits = LimitManager::default();
    let http = reqwest::Client::new();

    let state = Arc::new(ProxyState {
        config: config_arc,
        runs,
        credentials,
        limits,
        http,
    });

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}
