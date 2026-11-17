# Tasks: A0 data and cloud foundations

## 1. Owner decisions
- [x] 1.1 Owner reviews design.md decisions 1–18 and answers the open questions (first region, EU at launch). Record the answers in design.md. The worker must stop here with "Needs owner" until this is ticked by the owner.

## 2. Spikes on the F0 stack [opus]
- [x] 2.1 Pin compose to `postgres:18` (exact minor). Verify: `just reset && just up && just psql -c 'select uuidv7()'`.
- [x] 2.2 `tests/spikes/a0` crate: migration with owner role and app role, a tenant table with `org_id`, FORCE RLS and policy; sqlx tests for the three RLS scenarios in the spec, including pooled-connection reuse (pool size 1).
- [x] 2.3 A test or lint fails if a session-level `SET app.` or `set_config(..., false)` appears in non-test Rust code.
- [x] 2.4 Header format: KATs, round trip, and proptests that tamper with each AAD field and header field and expect a named error. Never print plaintext.
- [x] 2.5 Verify: `cargo nextest run -p a0-spikes` passes and `just leak-scan` is clean.

## 3. Record
- [x] 3.1 Copy each spike result (pass and versions) into the design.md evidence column and drop any **[verify]** tag that a spike resolved.
- [x] 3.2 Add the decisions to the `openspec/config.yaml` context as "Decided foundations" so later changes inherit them.

## 4. Local verification
- [x] 4.1 `just up && just harness-check && cargo nextest run -p a0-spikes && just ci`
