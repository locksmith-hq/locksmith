//! Publish the gateway's binding inventory to the control plane (D3 task 6.2, decision 10, D3-1).
//!
//! At startup the gateway sends the non-secret facts of each binding with
//! `PUT /internal/v1/gateway/bindings` (service token, the gateway's org), so the console can
//! list them. The wire type [`BindingSummary`] has no field for a secret id, a header template, a
//! password or a version: [`summaries`] copies only names, hosts, ports, users, databases, TLS
//! modes, header names, MCP upstream origins and tool rules, Git repository prefixes and AWS role, region, `vend` and maximum duration
//! (never the external id). An AWS row alone also carries its base-credential secret id (an id,
//! never a value): the control plane's join key to the org's `delegate` grants, stored and never
//! served (d2 design decision 8). A failure is retried a few times, then
//! logged (status class only, never a body); it never blocks or fails the relay.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::config::{Bindings, PgTls};
use crate::decrypt::{ControlPlane, Internal};
use ls_mcp_server::upstream::ToolDecision;

const PATH: &str = "internal/v1/gateway/bindings";
const MAX_RESPONSE: usize = 16 * 1024;

/// Tries, and the wait before the second (doubled for each further one).
#[derive(Debug, Clone, Copy)]
pub struct PublishOptions {
    pub retries: u32,
    pub backoff: Duration,
}

impl Default for PublishOptions {
    fn default() -> Self {
        Self {
            retries: 3,
            backoff: Duration::from_millis(500),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Http,
    Git,
    Pg,
    Aws,
    Mcp,
}

/// One per-tool rule of an `mcp` row: the upstream's tool name and the decision (never a value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolRule {
    pub name: String,
    pub decision: ToolDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Tls {
    Require,
    VerifyFull,
    Disable,
}

/// One binding, non-secret fields only (the control plane's `BindingSummary`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindingSummary {
    pub kind: Kind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<Tls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vend: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u32>,
    /// `aws` only: the base-credential secret id, the join key to delegate grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<uuid::Uuid>,
    /// `mcp` only: the per-tool rules, in name order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolRule>>,
    /// `mcp` only: the decision for a tool without a rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_decision: Option<ToolDecision>,
}

impl BindingSummary {
    fn new(kind: Kind, name: String) -> Self {
        Self {
            kind,
            name,
            origin: None,
            header: None,
            repo: None,
            host: None,
            port: None,
            user: None,
            database: None,
            tls: None,
            role: None,
            region: None,
            vend: None,
            max_duration_secs: None,
            secret_id: None,
            tools: None,
            default_decision: None,
        }
    }
}

/// The inventory of `bindings`: HTTP, Git, Postgres, AWS, then MCP upstreams, each in file order.
pub fn summaries(bindings: &Bindings) -> Vec<BindingSummary> {
    let mut out = Vec::new();
    for b in &bindings.bindings {
        let mut s = BindingSummary::new(Kind::Http, b.origin.clone());
        s.origin = Some(b.origin.clone());
        s.header = Some(b.header.clone());
        out.push(s);
    }
    for g in &bindings.git_bindings {
        let mut s = BindingSummary::new(Kind::Git, g.host.clone());
        s.host = Some(g.host.clone());
        s.repo = Some(g.repo_prefix.clone());
        s.port = g.port;
        out.push(s);
    }
    for p in &bindings.pg {
        let mut s = BindingSummary::new(Kind::Pg, p.name.clone());
        s.host = Some(p.host.clone());
        s.port = Some(p.port);
        s.user = Some(p.user.clone());
        s.database = Some(p.database.clone());
        s.tls = Some(match p.tls {
            PgTls::Require => Tls::Require,
            PgTls::VerifyFull => Tls::VerifyFull,
            PgTls::Disable => Tls::Disable,
        });
        out.push(s);
    }
    for a in &bindings.aws_bindings {
        let mut s = BindingSummary::new(Kind::Aws, a.role_arn.clone());
        s.role = Some(a.role_arn.clone());
        s.region = Some(a.region.clone());
        s.vend = Some(a.vend);
        s.max_duration_secs = Some(a.max_duration_secs);
        s.secret_id = Some(a.secret_id);
        out.push(s);
    }
    for u in &bindings.mcp_upstreams {
        let mut s = BindingSummary::new(Kind::Mcp, u.name.clone());
        s.origin = Some(u.url.clone());
        s.header = Some(u.header.clone());
        s.default_decision = Some(u.default);
        // `tools` is a BTreeMap: name order. The template, secret id and version stay behind.
        s.tools = Some(
            u.tools
                .iter()
                .map(|(name, decision)| ToolRule {
                    name: name.clone(),
                    decision: *decision,
                })
                .collect(),
        );
        out.push(s);
    }
    out
}

#[derive(Serialize)]
struct Snapshot<'a> {
    items: &'a [BindingSummary],
}

/// `PUT` the snapshot, retrying an unreachable or failing (`5xx`) control plane. Returns whether
/// it was stored. A refusal (`4xx`) is not retried.
pub async fn publish(
    control_plane: &ControlPlane,
    items: &[BindingSummary],
    options: PublishOptions,
) -> bool {
    let Ok(body) = serde_json::to_vec(&Snapshot { items }) else {
        tracing::error!("binding inventory could not be serialized");
        return false;
    };
    let mut wait = options.backoff;
    for try_no in 0..=options.retries {
        match control_plane
            .internal_put_json(PATH, body.clone(), MAX_RESPONSE)
            .await
        {
            Ok((200 | 204, _)) => {
                tracing::info!(bindings = items.len(), "binding inventory published");
                return true;
            }
            Ok((status, _)) if !(500..=599).contains(&status) => {
                tracing::error!(status, "binding inventory refused by the control plane");
                return false;
            }
            Ok(_) | Err(Internal::Unavailable) => {
                tracing::warn!(attempt = try_no + 1, "binding inventory not published");
                if try_no < options.retries {
                    tokio::time::sleep(wait).await;
                    wait = wait.saturating_mul(2);
                }
            }
            Err(_) => {
                tracing::error!("binding inventory request failed");
                return false;
            }
        }
    }
    false
}

/// Publish once in the background; the relay does not wait for it and a failure only logs.
pub fn spawn_publish(
    control_plane: Arc<ControlPlane>,
    items: Vec<BindingSummary>,
) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move { publish(&control_plane, &items, PublishOptions::default()).await })
}

#[cfg(test)]
mod bindings_publish_tests {
    use super::*;
    use serde_json::Value;
    use url::Url;
    use uuid::Uuid;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ORG: Uuid = Uuid::from_u128(7);
    const TOKEN: &str = "test-only-service-token-bindings-publish";
    const SECRET_ID: &str = "0197c1f0-0000-7000-8000-0000000000aa";
    const GIT_SECRET_ID: &str = "0197c1f0-0000-7000-8000-0000000000ab";
    const PG_SECRET_ID: &str = "0197c1f0-0000-7000-8000-0000000000ac";
    const AWS_SECRET_ID: &str = "0197c1f0-0000-7000-8000-0000000000ad";
    const EXTERNAL_ID: &str = "planted-external-id-marker";
    const MCP_SECRET_ID: &str = "0197c1f0-0000-7000-8000-0000000000ae";
    const MCP_TEMPLATE: &str = "Bearer {secret} planted-mcp-template-marker";
    const TEMPLATE: &str = "Bearer {secret} planted-template-marker";

    fn cp(base: &str) -> ControlPlane {
        ControlPlane::new(Url::parse(base).unwrap(), ORG, TOKEN.to_owned().into()).unwrap()
    }

    fn fast() -> PublishOptions {
        PublishOptions {
            retries: 2,
            backoff: Duration::from_millis(1),
        }
    }

    fn config() -> Bindings {
        Bindings::parse(&format!(
            r#"
org_id = "{ORG}"

[[binding]]
secret_id = "{SECRET_ID}"
origin = "https://api.example.com"
header = "Authorization"
template = "{TEMPLATE}"

[[git_binding]]
secret_id = "{GIT_SECRET_ID}"
host = "github.com"
repo_prefix = "acme/widgets"
services = ["fetch"]

[[pg]]
name = "app"
secret_id = "{PG_SECRET_ID}"
host = "db.example.com"
user = "svc"
database = "appdb"
tls = "verify-full"

[[aws_binding]]
secret_id = "{AWS_SECRET_ID}"
role_arn = "arn:aws:iam::123456789012:role/deploy"
region = "eu-west-1"
external_id = "{EXTERNAL_ID}"
vend = true
max_duration_secs = 1800

[[mcp_upstream]]
name = "github"
url = "https://api.githubcopilot.com/mcp/"
secret_id = "{MCP_SECRET_ID}"
header = "Authorization"
template = "{MCP_TEMPLATE}"
default = "hide"

[mcp_upstream.tools]
list_issues = "allow"
create_issue = "hold"
delete_repository = "deny"
"#
        ))
        .expect("valid bindings")
    }

    #[test]
    fn bindings_publish_summaries_carry_non_secret_fields_only() {
        let items = summaries(&config());
        let text = serde_json::to_string(&Snapshot { items: &items }).unwrap();
        // Only the AWS row carries a secret id (the grant join key); judge the rest without it.
        let non_aws = serde_json::to_string(
            &items
                .iter()
                .filter(|i| i.kind != Kind::Aws)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        for secret in [
            SECRET_ID,
            MCP_SECRET_ID,
            MCP_TEMPLATE,
            "planted-mcp-template-marker",
            TEMPLATE,
            "{secret}",
            "template",
            "secret_id",
            "password",
            "version",
            EXTERNAL_ID,
            "external_id",
        ] {
            assert!(!non_aws.contains(secret), "{secret} in {non_aws}");
        }
        for secret in [
            TEMPLATE,
            MCP_SECRET_ID,
            MCP_TEMPLATE,
            "planted-mcp-template-marker",
            "{secret}",
            "password",
            "version",
            EXTERNAL_ID,
            "external_id",
        ] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["items"],
            serde_json::json!([
                {"kind": "http", "name": "https://api.example.com",
                 "origin": "https://api.example.com", "header": "Authorization"},
                {"kind": "git", "name": "github.com", "host": "github.com", "repo": "acme/widgets"},
                {"kind": "pg", "name": "app", "host": "db.example.com", "port": 5432,
                 "user": "svc", "database": "appdb", "tls": "verify-full"},
                {"kind": "aws", "name": "arn:aws:iam::123456789012:role/deploy",
                 "role": "arn:aws:iam::123456789012:role/deploy", "region": "eu-west-1",
                 "vend": true, "max_duration_secs": 1800, "secret_id": AWS_SECRET_ID},
                {"kind": "mcp", "name": "github", "origin": "https://api.githubcopilot.com/mcp/",
                 "header": "Authorization", "default_decision": "hide",
                 "tools": [
                    {"name": "create_issue", "decision": "hold"},
                    {"name": "delete_repository", "decision": "deny"},
                    {"name": "list_issues", "decision": "allow"},
                 ]},
            ])
        );
    }

    #[tokio::test]
    async fn bindings_publish_sends_token_org_and_non_secret_body() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/internal/v1/gateway/bindings"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(header("x-locksmith-org", ORG.to_string().as_str()))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let c = cp(&format!("{}/", server.uri()));
        assert!(publish(&c, &summaries(&config()), fast()).await);
        let reqs = server.received_requests().await.unwrap();
        let body = String::from_utf8(reqs[0].body.clone()).unwrap();
        for secret in [
            SECRET_ID,
            GIT_SECRET_ID,
            PG_SECRET_ID,
            MCP_SECRET_ID,
            MCP_TEMPLATE,
            TEMPLATE,
            "{secret}",
            "template",
            "password",
        ] {
            assert!(!body.contains(secret), "{secret} in {body}");
        }
        assert!(body.contains("appdb") && body.contains("Authorization"));
        assert!(body.contains("delete_repository") && body.contains("\"mcp\""));
    }

    #[tokio::test]
    async fn bindings_publish_retries_server_errors_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let c = cp(&format!("{}/", server.uri()));
        assert!(publish(&c, &summaries(&config()), fast()).await);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn bindings_publish_failure_returns_false_without_panicking() {
        // Refused: tried once.
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(400).set_body_string("secret-looking body"))
            .mount(&server)
            .await;
        let c = cp(&format!("{}/", server.uri()));
        assert!(!publish(&c, &summaries(&config()), fast()).await);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);

        // Persistent 5xx: every try, then give up.
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let c = cp(&format!("{}/", server.uri()));
        assert!(!publish(&c, &summaries(&config()), fast()).await);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);

        // Unreachable control plane.
        let c = cp("http://127.0.0.1:1/");
        assert!(!publish(&c, &summaries(&config()), fast()).await);
    }
}
