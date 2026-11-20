use std::process::ExitCode;
use std::sync::Arc;

use std::time::Duration;

use ls_control_plane::db::{self, Database, DbReadiness, PROBE_INTERVAL, PoolSettings};
use ls_control_plane::telemetry;
use ls_envelope::{BaoToken, OpenBaoTransit, WrapKeyId};
use ls_gateway::app::{self, AppState};
use ls_gateway::audit::HttpAudit;
use ls_gateway::auth::{AgentAuth, HttpJwks, JwksSettings};
use ls_gateway::config::{self, Config};
use ls_gateway::decrypt::{CacheSettings, ControlPlane, Decryptor, DekCache};
use ls_gateway::egress::SystemResolver;
use ls_gateway::grants::{GrantCache, GrantCacheSettings};
use ls_gateway::mcp_clients::{ClientsCache, MAX_REVOKED_TTL};
use ls_gateway::mcp_endpoint::McpEndpoint;
use ls_gateway::mcp_settings::{MAX_SETTINGS_TTL, SettingsCache};
use ls_gateway::relay::{Relay, RelayOptions};
use secrecy::ExposeSecret;
use tracing_subscriber::EnvFilter;

/// OTel `service.name` for the gateway's spans and logs.
const SERVICE_NAME: &str = "locksmith-gateway";
/// How often expired DEKs are purged from the cache (the TTL is 60 s).
const CACHE_SWEEP: Duration = Duration::from_secs(10);

fn env_filter() -> EnvFilter {
    // rmcp logs whole tool results at debug; capped so a short-lived credential never reaches a
    // log line whatever `RUST_LOG` says (m1-remote-mcp task 3.3).
    ls_gateway::mcp_endpoint::cap_rmcp_logs(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    )
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
        &telemetry::Options {
            service_name: SERVICE_NAME,
            ..telemetry::Options::default()
        },
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
    // The gateway never migrates: the control plane owns the schema. It is ready while Postgres
    // answers. Relay audit goes to the control plane's ledger endpoint, not to this database.
    let database = Database::connect_lazy(options, PoolSettings::default());
    let readiness = Arc::new(DbReadiness::new());
    readiness.set_migrated();
    let probe = database.spawn_readiness_probe(readiness.clone(), PROBE_INTERVAL);

    // Decrypt path (S3 design decision 3): the gateway's OpenBao token may decrypt. Unwrap
    // accepts any version of the configured key name, so the version here is only nominal.
    let Ok(key) = WrapKeyId::new(&config.openbao.key, 1) else {
        tracing::error!(
            "environment variable {} has an invalid value",
            config::ENV_OPENBAO_KEY
        );
        return ExitCode::FAILURE;
    };
    let token = BaoToken::new(config.openbao.token.expose_secret().to_owned());
    let Ok(transit) = OpenBaoTransit::new(&config.openbao.addr, key, token) else {
        tracing::error!(
            "OpenBao client could not be configured ({})",
            config::ENV_OPENBAO_ADDR
        );
        return ExitCode::FAILURE;
    };
    let Ok(control_plane) = ControlPlane::new(
        config.control_plane_url.clone(),
        config.bindings.org_id,
        config.service_token,
    ) else {
        tracing::error!("control-plane client could not be configured");
        return ExitCode::FAILURE;
    };
    // Agent tokens (S4 task 2.1): verified through the control plane's JWKS, cached by kid.
    let Ok(jwks) = HttpJwks::new(&config.control_plane_url) else {
        tracing::error!("JWKS client could not be configured");
        return ExitCode::FAILURE;
    };
    let auth = Arc::new(AgentAuth::new(
        config.bindings.org_id,
        Arc::new(jwks),
        JwksSettings::default(),
    ));
    // Warm the key cache; a failure here is retried on the first request.
    auth.refresh().await;
    let cache = Arc::new(DekCache::new(CacheSettings::default()));
    let sweeper = cache.spawn_sweeper(CACHE_SWEEP);
    let control_plane = Arc::new(control_plane);
    let decryptor = Decryptor::new(
        config.bindings.org_id,
        control_plane.clone(),
        Arc::new(transit),
        cache,
    );
    // Grants (S4 task 2.2): read through the internal endpoint with the service token, cached for
    // at most 10 s so a revocation takes effect within that time.
    let grants = Arc::new(GrantCache::new(
        control_plane.clone(),
        GrantCacheSettings::default(),
    ));
    // Audit (S5 task 3.1): relay events go to the org's ledger through the control plane's
    // internal append endpoint, with the same service token.
    // The org's agent MCP tool switches (m1-remote-mcp task 3.4), cached for at most 10 s.
    let tool_settings = Arc::new(SettingsCache::new(control_plane.clone(), MAX_SETTINGS_TTL));
    // Agent MCP clients and their revoke (task 4.2): recorded on initialize, the revoked set
    // read on every `/mcp` request through a cache of at most 10 s, failing closed.
    let clients = Arc::new(ClientsCache::new(control_plane.clone(), MAX_REVOKED_TTL));
    let audit = Arc::new(HttpAudit::new(control_plane));
    // `/mcp` verifies with the same AgentAuth as `/v1` (one token, one verifier).
    let mcp = McpEndpoint::new(auth.clone(), &config.mcp_allowed_hosts)
        .with_settings_source(tool_settings)
        .with_clients(clients);
    let binding_count = config.bindings.bindings.len();
    let relay = Relay::new(
        auth,
        grants,
        config.bindings,
        decryptor,
        Arc::new(SystemResolver),
        audit,
        RelayOptions::default(),
    );

    let router = app::build(
        AppState::new(readiness)
            .with_relay(Arc::new(relay))
            .with_mcp(mcp),
    );
    let listener = match tokio::net::TcpListener::bind(config.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "failed to bind listen address ({})", config::ENV_BIND);
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addr = %config.bind, bindings = binding_count, "locksmith-gateway listening");

    let served = axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    probe.abort();
    sweeper.abort();
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
