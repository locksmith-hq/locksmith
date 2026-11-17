use std::process::ExitCode;
use std::sync::Arc;

use ls_control_plane::app::{self, AppState};
use ls_control_plane::config::Config;
use ls_control_plane::readiness::ReadyFlag;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };

    if config.dev_auth {
        tracing::warn!(
            bind = %config.bind,
            "LOCKSMITH_DEV_AUTH=1: dev org header authentication is ENABLED; never use outside local development"
        );
    }

    // Section 2 replaces this flag with a migration/database-backed readiness check.
    let readiness = Arc::new(ReadyFlag::new(false));
    let router = app::build(AppState::new(config.dev_auth, readiness));

    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "failed to bind listen address ({})", ls_control_plane::config::ENV_BIND);
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addr = %config.bind, "locksmith-api listening");

    let served = axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "server error");
            ExitCode::FAILURE
        }
    }
}
