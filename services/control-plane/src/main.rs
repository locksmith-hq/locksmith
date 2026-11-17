use std::process::ExitCode;
use std::sync::Arc;

use ls_control_plane::app::{self, AppState};
use ls_control_plane::config::{self, Config};
use ls_control_plane::db::{self, Database, DbReadiness, PROBE_INTERVAL, PoolSettings};
use ls_control_plane::migrate;
use ls_control_plane::telemetry;
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
    if telemetry.exporting() {
        tracing::info!("OTLP telemetry export enabled");
    }

    if config.dev_auth {
        tracing::warn!(
            bind = %config.bind,
            "LOCKSMITH_DEV_AUTH=1: dev org header authentication is ENABLED; never use outside local development"
        );
    }

    let Ok(app_options) = db::connect_options(&config.database_url) else {
        tracing::error!(
            "environment variable {} has an invalid value",
            config::ENV_DATABASE_URL
        );
        return ExitCode::FAILURE;
    };
    let Ok(owner_options) = db::connect_options(&config.database_owner_url) else {
        tracing::error!(
            "environment variable {} has an invalid value",
            config::ENV_DATABASE_OWNER_URL
        );
        return ExitCode::FAILURE;
    };

    // Requests use only the app-role pool. Migrations run through a separate owner pool in the
    // background (retrying until Postgres is up), which is closed once they are applied;
    // /readyz stays 503 until then and whenever Postgres stops answering.
    let database = Database::connect_lazy(app_options, PoolSettings::default());
    let readiness = Arc::new(DbReadiness::new());
    let probe = database.spawn_readiness_probe(readiness.clone(), PROBE_INTERVAL);
    let migrations = tokio::spawn(migrate::run_until_done(owner_options, readiness.clone()));

    let router = app::build(AppState::new(config.dev_auth, readiness, database.clone()));

    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "failed to bind listen address ({})", config::ENV_BIND);
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addr = %config.bind, "locksmith-api listening");

    let served = axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    migrations.abort();
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
