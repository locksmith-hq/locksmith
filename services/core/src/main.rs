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
    let mut state = AppState::new(ServiceToken::new(config.service_token));
    if let Some(url) = &config.database_url {
        use secrecy::ExposeSecret as _;
        let Ok(options) = url
            .expose_secret()
            .parse::<sqlx_postgres::PgConnectOptions>()
        else {
            tracing::error!("invalid database url");
            return ExitCode::FAILURE;
        };
        state = state.with_pool(
            sqlx_postgres::PgPoolOptions::new()
                .max_connections(8)
                .connect_lazy_with(options),
        );
    }
    if let Some(kms) = &config.checkpoint_kms {
        match ls_core_service::checkpoint_api::openbao(kms) {
            Ok(signer) => state = state.with_signer(signer),
            Err(_) => {
                tracing::error!("invalid checkpoint signing configuration");
                return ExitCode::FAILURE;
            }
        }
    }
    if let Some(seed) = &config.agent_signing_key {
        use secrecy::ExposeSecret as _;
        match ls_agent_token::AgentTokenSigner::from_base64_seed(seed.expose_secret()) {
            Ok(signer) => state = state.with_agent_signer(std::sync::Arc::new(signer)),
            Err(_) => {
                tracing::error!("invalid agent signing key");
                return ExitCode::FAILURE;
            }
        }
    }
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
