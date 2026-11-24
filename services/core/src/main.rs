use std::process::ExitCode;

use ls_core_service::app::{self, AppState};
use ls_core_service::auth::ServiceToken;
use ls_core_service::config::Config;
use ls_core_service::telemetry;
use tracing_subscriber::EnvFilter;

fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter())
                .init();
            tracing::error!(error = %e, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };
    let options = telemetry::Options {
        service_name: "locksmith-core",
        ..telemetry::Options::default()
    };
    let _telemetry = match telemetry::init(
        config.otlp_endpoint.as_deref(),
        env_filter(),
        std::io::stdout,
        &options,
    ) {
        Ok(t) => t,
        Err(_) => return ExitCode::FAILURE,
    };
    let state = AppState::new(ServiceToken::new(config.service_token));
    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "cannot bind");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(bind = %config.bind, "core service listening");
    if axum::serve(listener, app::router(state)).await.is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
