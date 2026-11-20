# Progress: M1 remote MCP (append-only)

- 2026-11-20 · planning only: proposal, spec, design and tasks written by a worker; no code. `x-depends_on` is t1-human-auth:contract (t1 is archived on main). Remote-MCP auth is unverified, so task 1.1 is a research note.
- 2026-11-20 · review follow-up: `x-depends_on: []` is deliberate because `t1-human-auth` is archived on main (the roadmap's `t1-human-auth:contract` is already satisfied). Design now states how a call is bound to an `mcp_clients` row (session id) and task 1.1 research covers it.
- 2026-11-20 · review follow-up 2: revoke now binds to the OAuth client_id (hub) or the agent (gateway), not the session id; task 4.2 test re-initializes after revoke.
- 2026-11-20 · review follow-up 3: spec revoke requirement now names the client_id/agent binding and adds a re-initialize-after-revoke scenario (maps to task 4.2).
- 2026-11-20 · lead: owner chose option A on [#493](https://github.com/locksmith-hq/locksmith/issues/493). Hub revoke refuses tokens whose `auth_time` is before `revoked_at` and revokes refresh tokens and consent at the issuer (refusing by `iat` is bypassed by a refresh). Design and spec updated; task 4.1 checks Keycloak keeps `auth_time` on refresh, else the strict rule applies. Task 1.1's note must use this rule.
- 2026-11-20 · rescue (lead, #493): host block worked around (MCP spec read from its GitHub source; Claude Code docs and Codex source reachable; Cursor docs unreachable and marked unverified). Wrote `docs/research/remote-mcp-auth.md`. Opus evaluator FAIL twice: attempt 1 unsourced client_id binding (fixed with Keycloak 26.0.8 source); attempt 2 the `iat < revoked_at` revoke rule is bypassed by refresh. Note now proposes `auth_time` (unverified on Keycloak) or design.md's strict rule. Task 1.1 stays unticked; needs-owner raised on #493. Tasks 1.2 and 1.3 do not depend on it.
- 2026-11-20 · lead (owner reply, #493): owner allowlisted `modelcontextprotocol.io` (verified HTTP 200 from the VM); `datatracker.ietf.org` is still blocked. The revoke rule (A: `auth_time` plus issuer revoke, B: strict) is still waiting on the owner; #493 body and Action are updated. Next worker: re-check the research note's MCP spec citations against the live site. Verified: curl modelcontextprotocol.io -> 200.

- 2026-11-20 · worker (event wake: #493 closed): owner chose option A. Re-checked the research note against the live MCP spec (all cited claims present) and recorded the decision; 1.1 NOT ticked yet: evaluator FAIL because the decision record (#503) and design.md update (#502) are not on this branch until they merge; tick 1.1 after merging main. Verified: curl + grep of the spec page; docs-only. Next: 1.2 (rmcp spike), 1.3 (ls-mcp-server crate).

## 2026-11-20 worker
- Task: m1-remote-mcp 1.3 - blocked (WIP crate `crates/ls-mcp-server` committed, task NOT ticked; two evaluator FAILs, see needs-rescue issue)
- Verified: `cargo nextest run -p ls-mcp-server` -> 8 passed; clippy clean; evaluator FAIL x2 (sonnet, opus)
- Notes for next session: the evaluators disagree on the Agent default table. Design section 6 "Agent MCP" column (list keys, start session, relay, request access, explain block on; issue_short_lived_credential off) vs the seven tools in `locksmith-mcp` vs task 3.2's smaller default-on set. Lead to decide. Also open: normalize field names (camelCase, separators, substrings) in `find_value_like_field`; real hub tool input schemas and output schemas so the output half of the no-value test runs on shipped tools.

- 2026-11-20 · rescue (lead, [#508](https://github.com/locksmith-hq/locksmith/issues/508)): task 1.3. Cause: three sources gave different Agent default tables (hub design section 6, the seven `locksmith-mcp` tools, task 3.2). Decision in design.md "Default tool tables": section 6 is the source; `locksmith-mcp`'s tools are the Local MCP column; the registry lists only the tools this change builds (Agent on: `list_my_keys`, `relay_http_request`, `explain_block`; off: `issue_short_lived_credential`. Hub on: `list_projects`, `list_secret_names`, `read_activity`, `list_agents`, `list_grants`, `explain_block`; off: `revoke_grant`, `pause_agents`). `start_session` and `request_access` join with t8 and t4. Fix: real input and output schemas for every tool (output schema required); names split on camelCase and separators, last word checked; open objects refused; short-lived `credential` exception is Agent-only and must be a plain string. Verified: `cargo nextest run -p ls-mcp-server` 13 passed, clippy clean, `just ci` exit 0; Opus evaluator PASS (twice, after hardening). Leftover for 6.1: unsplit or unlisted names the check misses (`passwd`, `apikey`, `authorization`, `cookie`, `dsn`, `connection_string`, `password_hash`, `apiKey1`) and annotation-only schemas (`{"description":"x"}`) that accept anything.

## 2026-11-20 lead
- Task: m1-remote-mcp 1.3 - done (rescue #508)
- Verified: `cargo nextest run -p ls-mcp-server` -> 13 passed; `just ci` -> exit 0; Opus evaluator PASS
- Notes for next session: next are 1.2 (rmcp spike) and 1.4 (migration and OpenAPI). Tools named in design section 6 but not built here (start_session, request_access, list_findings, list_waiting_requests, approve_or_deny_request, rotate_secret) join the registry with their own changes. Task 6.1 should also widen the name check (see the rescue entry above).

## 2026-11-20 worker (event wake: #508 closed)
- Task: m1-remote-mcp 1.1 - done. Decision record and design.md (option A, `auth_time`) are on this branch; the research note already states it and its MCP spec citations were re-checked against the live site earlier today.
- Verified: grep shows design.md, decisions.md M1-1 and the note agree; docs only.
- Notes for next session: 1.2 (rmcp spike) and 1.4 (migration and OpenAPI) are next.

## 2026-11-20 worker C
- Task: m1-remote-mcp 1.2 - done (rmcp spike: licence Apache-2.0, pin `=3.11.0`, released 2026-11-17; builds and mounts in axum 0.8 via `nest_service`; findings in design.md "OSS used")
- Verified: scratch crate `cargo build` -> Finished (not committed); crates.io API for licence and date; no repo code changed
- Notes for next session: 1.4 (migration and OpenAPI) next. Host allowlist must be set for public hostnames in 2.1/3.1. Spike did not send a live MCP request.
- 2026-11-20 · worker A: tasks 1.4 (migration 0012, /v1/mcp tools+clients API, OpenAPI, client types, fixtures) and 1.5 done; just ci green, independent evaluator PASS. Next: group 2 (/mcp route on control plane). Not built: audit events for switch/revoke changes (task 2.5), mcp_clients initialize upsert (2.3).

## 2026-11-20 07:25 worker
- Task: 1.4, 1.5 - done
- Verified: just ci -> green; cargo nextest -p ls-mcp-server -> 13 passed; npm test control-plane-client -> 5 passed
- Notes for next session: group 2 next (/mcp route, OIDC auth, read tools). initialize upsert of mcp_clients is task 2.3; audit for switch/revoke changes is task 2.5.

## 2026-11-20 worker B
- Task: m1-remote-mcp 2.1 - done (hub `/mcp` via rmcp =3.11.0 behind OIDC middleware; audience = MCP resource URL, 401 + `WWW-Authenticate` resource_metadata, protected-resource metadata, fail-closed when `LOCKSMITH_MCP_RESOURCE_URL` unset)
- Verified: `just ci` -> exit 0; `cargo nextest run -p ls-control-plane mcp` -> 11 passed; Sonnet evaluator PASS
- Notes for next session: 2.2 (read tools) next; `McpPrincipal` carries identity only, no client_id yet (4.x extends it); user/org resolution belongs to 2.2.

## 2026-11-20 worker B
- Task: m1-remote-mcp 2.2 - code done, NOT ticked: five hub read tools (list_projects, list_secret_names, list_agents, list_grants, read_activity) call the existing REST handlers as the person; `explain_block` returns a typed `not_available` (501) because the hub has no block-explanation service code. Sonnet evaluator PASS with that caveat.
- Verified: `just ci` -> exit 0; `cargo nextest run -p ls-control-plane mcp` -> 19 passed; `cargo nextest run -p ls-mcp-server` -> 13 passed
- Notes for next session: tick 2.2 once `explain_block` has a real hub handler (or the lead accepts the deferral). Then 2.3 (switch enforcement, mcp_clients upsert), 2.4, 2.5.

## 2026-11-20 worker A
- Task: m1-remote-mcp 2.3 - done (hub `/mcp` reads the org's `mcp_tool_settings` on every list and call; an off tool is hidden and refused like an unknown one; `initialize` upserts `mcp_clients` keyed by token `client_id`/`azp` and person, never clearing `revoked_at`; tokens with no client id record no row)
- Verified: `cargo nextest run -p ls-control-plane mcp` -> 21 passed; `just ci` -> exit 0; Sonnet evaluator PASS
- Notes for next session: 2.2 is still unticked (explain_block is a typed not-available; lead to accept the deferral or add a handler). Next 2.4 (mutating tools) and 2.5 (audit). Revoked-client refusal is 4.2; `HumanIdentity` now carries `client_id`.

## 2026-11-20 worker C
- Task: m1-remote-mcp 2.4 - done (hub `revoke_grant` calls the console's delete-grant handler as the person, org-scoped, audited by that handler; `pause_agents` returns a typed `not_available` error until T8 lands; both stay off by default)
- Verified: `cargo nextest run -p ls-control-plane mcp` -> 22 passed; `just ci` -> exit 0; Sonnet evaluator PASS
- Notes for next session: 2.2 still unticked (explain_block deferral); next 2.5 (audit event per call, which should also replace the DEV_AUTH_ACTOR attribution on MCP revoke), then 2.6.
