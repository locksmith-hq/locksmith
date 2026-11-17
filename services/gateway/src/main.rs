use std::process::ExitCode;
use std::sync::Arc;

use ls_control_plane::db::{self, Database, DbReadiness, PROBE_INTERVAL, PoolSettings};
use ls_control_plane::telemetry;
use ls_gateway::app::{self, AppState};
use ls_gateway::config::{self, Config};
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

    let telemetry = match telemetry::init(
        config.otlp_endpoint.as_deref(),
        env_filter(),
        std::io::stdout,
        &telemetry::Options::default(),
    ) {
        Ok(t) => t,
        Err(_) => return ExitCode::FAILURE,
    };

    let Ok(options) = db::connect_options(&config.database_url) else {
        tracing::error!(
            "environment variable {} has an invalid value",
            config::ENV_DATABASE_URL
        );
        return ExitCode::FAILURE;
    };
    // The gateway never migrates: the control plane owns the schema (it creates
    // `gateway_audit`). It is ready while Postgres answers.
    let database = Database::connect_lazy(options, PoolSettings::default());
    let readiness = Arc::new(DbReadiness::new());
    readiness.set_migrated();
    let probe = database.spawn_readiness_probe(readiness.clone(), PROBE_INTERVAL);

    let router = app::build(AppState::new(readiness));
    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "failed to bind listen address ({})", config::ENV_BIND);
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addr = %config.bind, bindings = config.bindings.bindings.len(), "locksmith-gateway listening");

    let served = axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    probe.abort();
    database.close().await;
    let _ = tokio::task::spawn_blocking(move || telemetry.shutdown()).await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "server error");
            ExitCode::FAILURE
        }
    }
}
