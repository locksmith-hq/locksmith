use std::process::ExitCode;
use std::sync::Arc;

use ls_control_plane::agent_token::AgentTokenSigner;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::checkpoint::{self, CheckpointJob, Schedule};
use ls_control_plane::config::{self, Config};
use ls_control_plane::db::{self, Database, DbReadiness, PROBE_INTERVAL, PoolSettings};
use ls_control_plane::kms;
use ls_control_plane::migrate;
use ls_control_plane::telemetry;
use secrecy::ExposeSecret;
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

    let mut state = AppState::new(config.dev_auth, readiness.clone(), database.clone());
    match config.kms.as_ref().map(kms::openbao) {
        Some(Ok(wrapper)) => {
            tracing::info!("OpenBao transit configured for secret version DEK wrapping");
            state = state.with_kms(wrapper);
        }
        Some(Err(e)) => {
            tracing::error!(error = %e, "invalid OpenBao transit configuration");
            return ExitCode::FAILURE;
        }
        None => tracing::warn!(
            "{} is not set: secret version writes are disabled (503)",
            config::ENV_OPENBAO_ADDR
        ),
    }
    // S5: the audit checkpoint job signs through OpenBao transit with a sign-only token.
    let checkpoints = match config.audit_checkpoint.as_ref().map(checkpoint::openbao) {
        Some(Ok(signer)) => {
            tracing::info!("OpenBao transit configured for audit checkpoint signing");
            Some(
                CheckpointJob::new(database.clone(), signer, Schedule::default())
                    .spawn(readiness.clone()),
            )
        }
        Some(Err(e)) => {
            tracing::error!(error = %e, "invalid OpenBao audit checkpoint configuration");
            return ExitCode::FAILURE;
        }
        None => {
            tracing::warn!(
                "{} is not set: audit checkpoints are not signed",
                config::ENV_AUDIT_CHECKPOINT_TOKEN
            );
            None
        }
    };
    match config.gateway_service_token {
        Some(token) => state = state.with_service_token(ServiceToken::new(token)),
        None => tracing::warn!(
            "{} is not set: the internal gateway routes refuse every request (401)",
            config::ENV_GATEWAY_SERVICE_TOKEN
        ),
    }
    match config.agent_signing_key.as_ref() {
        Some(seed) => match AgentTokenSigner::from_base64_seed(seed.expose_secret()) {
            Ok(signer) => {
                tracing::info!(kid = %signer.jwk().kid, "agent token signing key configured");
                state = state.with_agent_signer(signer);
            }
            Err(e) => {
                tracing::error!(error = %e, "invalid {}", config::ENV_AGENT_SIGNING_KEY);
                return ExitCode::FAILURE;
            }
        },
        None if config.dev_auth => match AgentTokenSigner::generate() {
            Ok(signer) => {
                tracing::warn!(
                    kid = %signer.jwk().kid,
                    "{} is not set: using an ephemeral dev signing key; agent tokens stop verifying on restart",
                    config::ENV_AGENT_SIGNING_KEY
                );
                state = state.with_agent_signer(signer);
            }
            Err(e) => {
                tracing::error!(error = %e, "could not generate an agent signing key");
                return ExitCode::FAILURE;
            }
        },
        None => tracing::warn!(
            "{} is not set: agent token requests are refused (503) and the JWKS is empty",
            config::ENV_AGENT_SIGNING_KEY
        ),
    }
    let router = app::build(state);

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
    if let Some(job) = checkpoints {
        job.abort();
    }
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
