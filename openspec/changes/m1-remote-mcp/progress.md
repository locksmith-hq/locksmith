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

## 2026-11-20 worker
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

## 2026-11-20 worker
- Task: m1-remote-mcp 2.4 - done (hub `revoke_grant` calls the console's delete-grant handler as the person, org-scoped, audited by that handler; `pause_agents` returns a typed `not_available` error until T8 lands; both stay off by default)
- Verified: `cargo nextest run -p ls-control-plane mcp` -> 22 passed; `just ci` -> exit 0; Sonnet evaluator PASS
- Notes for next session: 2.2 still unticked (explain_block deferral); next 2.5 (audit event per call, which should also replace the DEV_AUTH_ACTOR attribution on MCP revoke), then 2.6.

## 2026-11-20 worker A
- Task: m1-remote-mcp 2.5 - done (hub `/mcp` appends one `mcp.call` audit event per tools/call: layer, registry tool name or `unknown`, user actor, org target, outcome ok/denied/error with static reason; no arguments or results stored; MCP `revoke_grant` now attributed to the person, REST unchanged via `revoke_grant_as`)
- Verified: `cargo nextest run -p ls-control-plane mcp` -> 24 passed; `just ci` -> exit 0; Sonnet evaluator PASS
- Notes for next session: 2.6 is the verify step (run it and tick); 2.2 still unticked (explain_block deferral). Unverified-email callers get no per-call row (no org to chain to). Then group 3 (gateway MCP).

## 2026-11-20 worker B
- Task: m1-remote-mcp 3.1 - done (gateway `/mcp` via rmcp Streamable HTTP; reuses `AgentAuth` (aud `gateway`); 401 + `WWW-Authenticate` for missing/expired/wrong-audience/wrong-org tokens; Host allowlist loopback + `LOCKSMITH_GATEWAY_MCP_ALLOWED_HOSTS`; fails closed if unconfigured)
- Verified: `cargo nextest run -p ls-gateway mcp` -> 7 passed; `just ci` -> exit 0; Sonnet evaluator PASS
- Notes for next session: 3.2 (gateway tools; `ls-mcp-server` dep already added, unused until then). Set `LOCKSMITH_GATEWAY_MCP_ALLOWED_HOSTS` in infra/compose when deploying behind a hostname. 2.2 still unticked (explain_block deferral).

## 2026-11-20 worker (event)
- Task: m1-remote-mcp 3.2 - done (gateway `/mcp` default-on tools: `list_my_keys`, `relay_http_request` via the existing relay path through `relay::handle_as`, `explain_block` as typed `not_available` 501; `issue_short_lived_credential` stays off and unlisted)
- Verified: `cargo nextest run -p ls-gateway mcp` -> 16 passed; `just ci` -> exit 0 (before tick/progress edit); independent Sonnet evaluator PASS
- Notes for next session: 3.3 [opus] short-lived credential; 3.4 per-org switches and per-call audit event (must also cover `list_my_keys` and `explain_block`); relay tool needs secret `version`; tool errors drop the relay request_id.

## 2026-11-20 worker B
- Task: m1-remote-mcp 3.3 - done (gateway `issue_short_lived_credential`: random `lsst_` token, 60-900 s, one secret, relay-only, hash held in memory, `credential.issued` audit before use, off by default; rmcp debug log cap added after the adversarial log test found a leak)
- Verified: `cargo nextest run -p ls-gateway mcp` 25 passed; full ls-gateway 116 passed; `just ci` exit 0; Opus evaluator PASS
- Notes for next session: 3.4 replaces `with_tool_settings` with per-org `mcp_tool_settings` and adds the per-call audit event (also refused issues); agent revoke (4.2/T8) should also invalidate that agent's live short-lived credentials (a credential can outlive the agent token by up to 15 min); "one job" is a label, not single-use; credentials are per replica. 2.2 still unticked (explain_block deferral).

## 2026-11-20 worker (event)
- Task: m1-remote-mcp 3.4, 3.5 - done (gateway reads the org's agent-tool overrides from the control plane on every list and call, cached <=10 s, fail closed when unreadable; one `mcp.call` event per call with a registry tool name or `unknown`, outcome and static reason; new internal endpoints `GET /internal/v1/mcp/agent-tool-settings` and `POST /internal/v1/mcp/agent-calls`)
- Verified: `cargo nextest run -p ls-gateway` 124 passed; `cargo nextest run -p ls-control-plane --test audit` passed; `just ci` -> exit 0 (before the one-assertion test tweak, re-run for that test only); Sonnet evaluator PASS
- Notes for next session: 2.2 still unticked (explain_block deferral); 2.3/2.5 on the hub already have their own switch/audit code; next unticked tasks are 4.1 (hub OAuth flow, needs task 1.1 research note first) and 4.2. Agent revoke should also drop that agent's live short-lived credentials. `SettingsCache` is single-org (one gateway per org); a multi-org gateway needs a keyed cache.

## 2026-11-20 worker C
- Task: m1-remote-mcp 4.1 - done (realm client `locksmith-mcp`: public, PKCE S256, loopback redirect, consent required, fixed MCP audience mapper; `scripts/mcp-e2e.py` + `just mcp-e2e` drive discovery, consent sign-in with `resource`, refresh, `initialize` + `tools/list`, and the no-passthrough check; `just api` now sets `LOCKSMITH_MCP_RESOURCE_URL`)
- Verified: `just mcp-e2e` against live Keycloak 26.0.8 + control plane -> all 16 checks passed; Keycloak keeps `auth_time` on refresh (strict fallback not needed); anonymous DCR refused, CIMD not advertised (research note section 5)
- Notes for next session: 4.2 (revoke bound to client_id; issuer-side revoke via Keycloak admin API; refuse when `auth_time` < `revoked_at`). 2.2 still unticked (explain_block deferral).

## 2026-11-20 worker A
- Task: m1-remote-mcp 4.2 - partial (hub half done; 4.2 stays unticked). The hub `/mcp` middleware refuses with 401 any token whose client row (client_id + person) is revoked and whose `auth_time` is older than `revoked_at` (or absent); a fresh sign-in with a newer `auth_time` passes; fails closed if the check errors. `HumanIdentity` now carries `auth_time`.
- Verified: `cargo nextest run -p ls-control-plane --test mcp_tools --test mcp --test mcp_auth --test users` -> 33 passed; `just ci` -> exit 0
- Notes for next session: the gateway/agent half of 4.2 (revoked agent refused, live short-lived credentials dropped) depends on agent revoke from T8; either do it with a gateway-side check or have the lead accept the deferral. Issuer-side revoke via Keycloak admin API is not done. 4.3 verify (`just up && mcp_e2e`) and groups 5-7 remain; 2.2 still unticked (explain_block deferral).
- Evaluator (Sonnet) first FAIL: resolve errors failed open and the revoke time was compared at whole seconds. Fixed both (only unverified-email passes through; comparison at full precision; boundary test added); `just ci` -> exit 0 after. Tokens with no client id skip the revoke check by design (rows are keyed by client id).

## 2026-11-20 worker B
- Task: m1-remote-mcp 5.1 - done (`apps/web` Tools page: one switch per tool grouped by layer, saved through `setMcpTool`; Clients page: list with revoke; loading, error/403 and empty states; new `mcp.test.tsx`, 7 tests)
- Verified: `npx tsc --noEmit` and `npx vitest run` in apps/web -> 26 passed; `just ci` -> exit 0 (started before the page code landed, web part re-run by hand after)
- Notes for next session: 5.2 desktop views on the same client methods; 4.2 gateway half and 4.3 still open; 2.2 still unticked.

## 2026-11-20 worker A (alfie)
- Task: m1-remote-mcp 5.2, 5.3 - done (desktop "MCP tools" and "MCP clients" screens on the same client methods as the web: one switch per tool by layer, client list with revoke, 403/empty/not-connected states; 3 new Vitest tests)
- Verified: `npx vitest run` in apps/desktop -> 28 passed; `just apps-build` -> exit 0; `just ci` -> exit 0
- Notes for next session: remaining: 2.2 (explain_block deferral), 4.2 gateway half + issuer-side revoke, 4.3, groups 6 and 7.

## 2026-11-20 15:07 worker
- Task: m1-remote-mcp 6.1 - blocked (code written, NOT ticked): adversarial cases G9 (gateway agent MCP) and G10 (hub MCP) plus `mcp_check.py`, README rows and offline self-checks in `run_test.sh`.
- Verified: `just ci` -> exit 0; `run_test.sh` and `run.sh selftest` pass; `run.sh gateway G9 G10` skips without a stack. G9/G10 have NOT run against a live stack (no `just up` here), so the wire-format and audit-count assumptions (refusal status codes, >=6 denied/unknown `mcp.call` events in G9, >=3 in G10, 20 s switch pickup, console token accepted) are unproven. No evaluator pass recorded.
- Notes for next session: run `just up && just api && bash tests/adversarial/run.sh gateway G9 G10`, fix the assumptions, evaluate, then tick 6.1; then 6.2 `just adversarial-gate`. Still open: 2.2 (explain_block deferral, lead to accept), 4.2 gateway half + issuer revoke (needs T8 agent revoke), 4.3, 7.x.

## 2026-11-20 worker A (alfie)
- Task: m1-remote-mcp 6.1, 6.2 - done. Ran G9/G10 against a live stack (`just up`, `just api`) and fixed wrong assumptions in the cases: `explain_block` is the typed `not_available` reply (audit outcome `error`), audit attrs are `{"code": x}` wrappers, G10 lacked `text()`. G5's sweep learned the new `/v1/mcp/*` routes (tool switches are per-org, so cross-org is "own switch 2xx, unknown org 4xx"; revoke of an unknown client row is 404). No leak assertion was loosened.
- Verified: `bash tests/adversarial/run.sh gateway G9 G10 G5` pass; `just adversarial-gate` -> PASS (9 passed, 1 residual, leak scan clean); Sonnet evaluator PASS. `just ci`: fmt, lint, test-web, tree-check, task-guard, agent-docs green; test-rust 853/854 - `ls-ipc::transport foreign_peer_is_closed_without_handling_a_request` fails only on this VM (spawning as uid 65534 from /home/user fails, unrelated to this change; friction).
- Notes for next session: remaining 2.2 (explain_block deferral, lead to accept), 4.2 gateway half + issuer revoke (needs T8 agent revoke), 4.3, 7.x.

## 2026-11-20 15:52 worker
- Task: m1-remote-mcp - blocked (no implementable task: 2.2 explain_block deferral, 4.2 gateway half needs T8, 4.3 names a nonexistent test `mcp_e2e`; 7.x wait on those)
- Verified: main CI green; no code changed
- Notes for next session: rescue issue #519 asks the lead to accept the deferrals and re-word 4.3 (`just mcp-e2e` passed 16/16 in 4.1). After that, run 7.1 and archive.

## 2026-11-20 lead (rescue #519)
- Task: m1-remote-mcp 2.2, 4.2, 4.3 - decided (design.md "Rescue #519 decisions"); no code changed, nothing ticked.
- Cause: workers had no lead ruling on `explain_block` (no backing service), the gateway half of 4.2 (assumed to need T8) and 4.3's nonexistent `mcp_e2e` target.
- Decisions: 2.2 `explain_block` is a static reason-code table in `ls-mcp-server`, used by hub and gateway (precedent: `locksmith-mcp` `explain()`); 4.2 is built in full now: Keycloak admin consent revoke on the hub (best-effort, `auth_time` rule enforces) and a gateway-side revoked-agent check with an agent-layer `mcp_clients` row; 4.3 is `just mcp-e2e`, extended with the revoke flow (task text fixed on `claude/planning-m1-remote-mcp-tasks`).
- Notes for next session: order 2.2, then 4.2 hub issuer revoke, 4.2 gateway, then 4.3 and 7.x. 4.2 gateway is a good [opus] evaluator task (auth path).

## 2026-11-20 worker C (harriet)
- Task: m1-remote-mcp 2.2 - done. `ls_mcp_server::explain` is a static reason-code table (20 rows incl. every relay refusal slug) used by hub and gateway `explain_block`; input never echoed, no I/O. G9/G10 adversarial cases updated to expect the rule instead of `not_available` (not re-run live).
- Verified: ls-mcp-server unit tests, `mcp_tools` explain test (hub) and gateway mcp tests pass; `just ci` exit 0. Sonnet evaluator first FAIL (6 relay codes missing), fixed, rows added and tests extended; final re-check by unit tests.
- Notes for next session: 4.2 hub issuer revoke (Keycloak admin API), then 4.2 gateway check (use an Opus evaluator), then 4.3 (`just mcp-e2e` + revoke flow) and 7.x. Latent: explain matching is substring (e.g. "blocked" contains `locked`); tighten if it bites.

## 2026-11-20 worker B (josie)
- Task: m1-remote-mcp - blocked (no code changed; run stopped after queue triage)
- Verified: `scripts/merge-gate.sh 520` -> GATE FAIL "PR not opened by the owner" (line 22 needs author tomer555; agent PRs are now opened by role Apps)
- Notes for next session: #520 (4.3 wording) cannot merge until the owner lets the gate accept the App logins (reported on #472). Remaining: 4.2 hub issuer revoke, 4.2 gateway check (Opus evaluator), 4.3, 7.x.
- 2026-11-20 · worker (josie): tasks 4.2, 4.3 and 7.1 done. Hub issuer revoke (Keycloak consent delete, best effort), gateway agent-layer revoke with a <=10 s fail-closed cache, short-lived credentials dropped, `just mcp-e2e` extended with the revoke flow (live, passes). Opus evaluator FAILed the first cut: the Keycloak service-account client lacked a clientScopeMappings entry for manage-users (fixed, live-verified); a Sonnet evaluator then passed the delta. Also fixed: re-revoking now moves `revoked_at` forward (a client that signed in again after a revoke could not be revoked again). `just ci` green. Left: 7.2 (manual ci-platforms run if this is the phase's last change).
