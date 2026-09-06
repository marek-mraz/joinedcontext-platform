//! The Context Gateway binary: one listener, one broker, one endpoint table (T-0005).

use context_gateway::app::{router, Gateway};
use context_gateway::config::Config;
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::store;
use std::process::ExitCode;
use std::sync::Arc;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "context_gateway=info,tower_http=info".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "the gateway is not configured");
            return ExitCode::FAILURE;
        }
    };

    let gateway = Gateway::new(
        Broker::new(config.broker_url.clone()),
        Box::new(PolicyPdp),
        config.org_domain.clone(),
    );
    let gateway = match &config.repo_dir {
        None => gateway,
        Some(dir) => match store::load(dir) {
            Ok(endpoints) => {
                tracing::info!(count = endpoints.len(), dir = %dir.display(), "endpoints loaded");
                gateway.serve(endpoints)
            }
            Err(error) => {
                // An unreadable repository is a deployment fault, not a request fault:
                // serving an empty table would answer 404 for endpoints that exist.
                tracing::error!(%error, dir = %dir.display(), "cannot read the manifest repository");
                return ExitCode::FAILURE;
            }
        },
    };

    let app = router(Arc::new(gateway)).layer(tower_http::trace::TraceLayer::new_for_http());
    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, bind = %config.bind, "cannot listen");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(bind = %config.bind, broker = %config.broker_url, "context-gateway listening");

    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
    {
        tracing::error!(%error, "the server stopped");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Stops on SIGTERM, which is how Kubernetes asks (OPS-12).
async fn shutdown() {
    let interrupt = async {
        tokio::signal::ctrl_c()
            .await
            .expect("a process can always listen for an interrupt");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("a process can always listen for SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}
