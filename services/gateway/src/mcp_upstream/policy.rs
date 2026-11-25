//! Task 3.1 of m2-mcp-gateway: the static tool policy (design decisions 5 and 6).
//!
//! [`StaticToolPolicy`] is the M2 implementation of [`ToolPolicy`]: it answers from each
//! `[[mcp_upstream]]` binding's `tools` table and `default`. The handler holds it as an
//! `Arc<dyn ToolPolicy>` (set in `main.rs`) and never reads the table itself, so a later change
//! swaps in another evaluator without touching the proxy.
//!
//! Rule keys match the catalogue name exactly (case-sensitive, no normalisation), so a case
//! variant or a look-alike of a hidden name is just another name and takes the default. A rule
//! for a tool the upstream does not offer is never consulted: only catalogue names are decided.

use std::collections::{BTreeMap, HashMap};

use ls_mcp_server::upstream::{PolicyError, PolicyFuture, ToolDecision, ToolPolicy, ToolQuery};

use crate::config::McpUpstream;

/// One upstream's table and default.
#[derive(Debug, Clone)]
struct Rules {
    default: ToolDecision,
    tools: BTreeMap<String, ToolDecision>,
}

/// The decisions of every upstream binding, keyed by the upstream's name.
#[derive(Debug, Clone, Default)]
pub struct StaticToolPolicy {
    upstreams: HashMap<String, Rules>,
}

impl StaticToolPolicy {
    /// The policy of the configured upstreams.
    pub fn new(upstreams: &[McpUpstream]) -> Self {
        Self {
            upstreams: upstreams
                .iter()
                .map(|u| {
                    (
                        u.name.clone(),
                        Rules {
                            default: u.default,
                            tools: u.tools.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn decide_now(&self, query: &ToolQuery) -> Result<HashMap<String, ToolDecision>, PolicyError> {
        // An upstream with no table is unknown to this policy: fail closed.
        let rules = self.upstreams.get(&query.upstream).ok_or(PolicyError {
            code: "unknown_upstream",
        })?;
        Ok(query
            .catalogue
            .iter()
            .map(|t| {
                let d = rules.tools.get(&t.name).copied().unwrap_or(rules.default);
                (t.name.clone(), d)
            })
            .collect())
    }
}

impl ToolPolicy for StaticToolPolicy {
    fn decide<'a>(&'a self, query: &'a ToolQuery) -> PolicyFuture<'a> {
        Box::pin(std::future::ready(self.decide_now(query)))
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
pub(in crate::mcp_upstream) mod tests;
