//! Contract for the gateway's MCP upstream proxy (change m2-mcp-gateway, task 1.1).
//!
//! The proxy holds an `Arc<dyn ToolPolicy>` and asks it, once per catalogue, what to do with each
//! tool; it never reads a rule table itself, so a later change can swap in a remote evaluator
//! without touching the proxy. An evaluator error fails closed.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// What the proxy does with one upstream tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolDecision {
    /// Listed and callable.
    Allow,
    /// Not in `tools/list`; a call gets the same error as an unknown name.
    Hide,
    /// Listed; a call is refused as denied.
    Deny,
    /// Listed; a call needs approval and is refused until an approver exists (fail closed).
    Hold,
}

impl ToolDecision {
    /// The stable lower-case name (config value, ledger attribute).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Hide => "hide",
            Self::Deny => "deny",
            Self::Hold => "hold",
        }
    }
}

/// One tool of an upstream catalogue, as far as a policy may look at it. The hints are the
/// upstream's own claim (`readOnlyHint`, `destructiveHint`); a policy must not trust them alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueEntry {
    pub name: String,
    pub read_only_hint: Option<bool>,
    pub destructive_hint: Option<bool>,
}

/// A batched question: who is calling which upstream, and what the whole catalogue holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolQuery {
    pub org: String,
    pub agent: String,
    pub upstream: String,
    pub catalogue: Vec<CatalogueEntry>,
}

/// The evaluator could not decide. The proxy treats it as "hide everything and refuse the call".
/// The reason is a fixed slug, never upstream text or a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub code: &'static str,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tool policy unavailable: {}", self.code)
    }
}

impl std::error::Error for PolicyError {}

/// A boxed future, so the trait stays object safe without a macro dependency.
pub type PolicyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HashMap<String, ToolDecision>, PolicyError>> + Send + 'a>>;

/// Decides every tool of a catalogue in one call (one round trip for a remote evaluator). A tool
/// missing from the answer is treated as hidden by the caller.
pub trait ToolPolicy: Send + Sync {
    fn decide<'a>(&'a self, query: &'a ToolQuery) -> PolicyFuture<'a>;
}

/// The MCP tool-name rule the proxy applies to upstream tools: `[A-Za-z0-9_.-]{1,128}`.
pub fn valid_tool_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_name_rule() {
        for ok in ["a", "list_issues", "a.b-c_D9", &"x".repeat(128)] {
            assert!(valid_tool_name(ok), "{ok}");
        }
        for bad in [
            "",
            &"x".repeat(129),
            "has space",
            "slash/name",
            "caf\u{e9}",
            "tab\t",
            "nul\0",
            "new\nline",
            "a:b",
        ] {
            assert!(!valid_tool_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn decision_serde_round_trip() {
        for (d, text) in [
            (ToolDecision::Allow, "allow"),
            (ToolDecision::Hide, "hide"),
            (ToolDecision::Deny, "deny"),
            (ToolDecision::Hold, "hold"),
        ] {
            let json = serde_json::to_string(&d).unwrap();
            assert_eq!(json, format!("\"{text}\""));
            assert_eq!(d.as_str(), text);
            assert_eq!(serde_json::from_str::<ToolDecision>(&json).unwrap(), d);
        }
        for bad in ["\"Allow\"", "\"ALLOW\"", "\"permit\"", "\"\"", "1", "null"] {
            assert!(serde_json::from_str::<ToolDecision>(bad).is_err(), "{bad}");
        }
    }

    struct Fixed(Result<HashMap<String, ToolDecision>, PolicyError>);
    impl ToolPolicy for Fixed {
        fn decide<'a>(&'a self, _q: &'a ToolQuery) -> PolicyFuture<'a> {
            let r = self.0.clone();
            Box::pin(async move { r })
        }
    }

    fn query() -> ToolQuery {
        ToolQuery {
            org: "o".into(),
            agent: "a".into(),
            upstream: "github".into(),
            catalogue: vec![CatalogueEntry {
                name: "list_issues".into(),
                read_only_hint: Some(true),
                destructive_hint: None,
            }],
        }
    }

    #[tokio::test]
    async fn policy_trait_is_object_safe_and_batched() {
        let ok: std::sync::Arc<dyn ToolPolicy> = std::sync::Arc::new(Fixed(Ok(HashMap::from([(
            "list_issues".to_owned(),
            ToolDecision::Allow,
        )]))));
        let got = ok.decide(&query()).await.unwrap();
        assert_eq!(got["list_issues"], ToolDecision::Allow);

        let err: std::sync::Arc<dyn ToolPolicy> =
            std::sync::Arc::new(Fixed(Err(PolicyError { code: "unavailable" })));
        let e = err.decide(&query()).await.unwrap_err();
        assert_eq!(e.to_string(), "tool policy unavailable: unavailable");
    }
}
