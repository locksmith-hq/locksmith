//! Task 3.2 of m2-mcp-gateway: the upstream's tool catalogue (design decision 7).
//!
//! The catalogue is the upstream's `tools/list` (every page, already redacted by the hop), with
//! tools whose name breaks the MCP name rule dropped and a repeated name kept once. The handler
//! caches it per upstream in a `TtlCell` of at most `MAX_CACHE_TTL`; a failed fetch is never
//! cached and an expired entry is never served, so the agent gets the hop's fixed error instead
//! of a stale list.

use std::collections::HashSet;

use ls_mcp_server::upstream::{CatalogueEntry, valid_tool_name};
use rmcp::model::{PaginatedRequestParams, Tool};

use super::hop::{self, HopDeps, HopError};
use crate::auth::AgentIdentity;
use crate::config::McpUpstream;

/// Most pages read for one catalogue; more is treated as an upstream fault (fail closed).
const MAX_PAGES: usize = 16;

/// The tools an upstream offers, with valid unique names.
#[derive(Debug, Default)]
pub struct Catalogue {
    tools: Vec<Tool>,
}

impl Catalogue {
    /// Keep the tools with a valid, first-seen name.
    pub fn from_tools(tools: Vec<Tool>) -> Self {
        let mut seen = HashSet::new();
        let tools = tools
            .into_iter()
            .filter(|t| valid_tool_name(&t.name) && seen.insert(t.name.to_string()))
            .collect();
        Self { tools }
    }

    pub fn tools(&self) -> &[Tool] {
        &self.tools
    }

    /// Whether `name` (exactly) is in the catalogue.
    pub fn contains(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t.name == name)
    }

    /// What a policy may look at, for the whole catalogue.
    pub fn entries(&self) -> Vec<CatalogueEntry> {
        self.tools
            .iter()
            .map(|t| CatalogueEntry {
                name: t.name.to_string(),
                read_only_hint: t.annotations.as_ref().and_then(|a| a.read_only_hint),
                destructive_hint: t.annotations.as_ref().and_then(|a| a.destructive_hint),
            })
            .collect()
    }
}

/// Read every page of the upstream's `tools/list`.
pub async fn fetch(
    deps: &HopDeps<'_>,
    upstream: &McpUpstream,
    agent: AgentIdentity,
) -> Result<Catalogue, HopError> {
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let params = cursor
            .take()
            .map(|c| PaginatedRequestParams::default().with_cursor(Some(c)));
        let page = hop::list_tools(deps, upstream, agent, params).await?;
        tools.extend(page.tools);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(Catalogue::from_tools(tools)),
        }
    }
    Err(HopError::Upstream)
}
