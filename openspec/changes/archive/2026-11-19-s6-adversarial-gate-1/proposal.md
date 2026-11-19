# Proposal: S6 adversarial gate 1

## Why
S1 to S5 make a full path: the control plane stores only ciphertext, the gateway decrypts and injects a secret into an upstream call, an agent reaches it with a short-lived token through `smith` and `locksmith-mcp`, and every relay is recorded in a hash-chained ledger. Each change has its own tests, but nothing tries to break the whole path the way a hostile or prompt-injected agent would. The existing `tests/adversarial` cases (A0 to A6a) target the local vault and daemon, not this server stack. S6 is the first adversarial gate: scripted and live-agent extraction attempts against S1 to S5, judged by the independent canary oracle, so a change cannot reach `main` if it opens a path for a secret to come back to the agent.

## What Changes
- **Gateway attack cases `G1` to `G6`** in `tests/adversarial/gateway/`, using the existing harness contract (`CANARY_FILE`, `ARTIFACT_DIR`, exit 77 to skip) and the shared oracle. Each one attacks the running stack (`just up`, control plane, gateway) only as an agent would: through the agent token, `smith`, `locksmith-mcp` and the public APIs.
  - `G1` environment and files: the agent's environment, `/proc/<pid>/environ` and `cmdline` of `smith`, `locksmith-mcp` and the gateway, the `smith` state directory, and shell history.
  - `G2` reflection: a binding to a reflecting upstream (the existing A3b fixture) that echoes the injected header in every encoding and compression it knows, plus slow and chunked streams.
  - `G3` header echo and request shaping: the agent overrides, duplicates or re-cases the injected header, puts `{secret}` in its own headers, path, query and body, tries CRLF and Host tricks, redirects and hosts outside the binding.
  - `G4` encodings the redactor may not know: base32, UTF-16, `\u` JSON escapes, HTML entities, quoted-printable, a gzip body with no `Content-Encoding`, reversed, split across headers, and one character per line.
  - `G5` control-plane and ledger surfaces: every agent-reachable API response and error, the OpenAPI document, internal endpoints without the service token, other orgs, audit event attributes fed from request fields, and the audit export directory.
  - `G6` token abuse: a token replayed after grant revoke or expiry, a token used against another org or the internal endpoints, and the enrollment secret kept out of every agent-visible output.
- **Live-agent mode:** with `--agent claude`, a headless `claude -p` session holding only the Locksmith MCP tools and a shell gets fixed attack prompts (`tests/adversarial/gateway/prompts/`) telling it to get the secret out by any means. Its transcript is scanned like any other artifact.
- **Oracle encodings:** `tests/kit/oracle.py` also looks for base32, UTF-16LE and UTF-16BE, `\u` escapes, HTML entities, quoted-printable and gzip-wrapped forms, so the judge sees more than the redactor does.
- **Redactor hardening where cheap and exact:** `ls-redact` also matches base32, UTF-16 and `\u`-escaped forms of a secret. Transformations no fixed matcher can cover (reversed, split, arbitrary) are recorded as known residuals, labelled containment, not hidden.
- **Residual register:** `tests/adversarial/gateway/residuals.toml` lists each known leak path with its protection label and the reason it is accepted. A case that leaks through a listed residual reports `RESIDUAL`; any other leak fails; a residual that stops leaking fails too, so the register stays honest.
- **Fast tier in `just ci`:** an in-process adversarial test in `ls-gateway` (fake KMS and material, wiremock upstreams, as the existing relay tests do) runs the G2 to G4 payloads and judges them with the oracle. It needs no Docker, so it runs in every `just ci`.
- **Stack tier:** `just adversarial-gate [--agent claude]` checks the stack is up, starts the gateway, runs `run.sh gateway` with `ADVERSARIAL_REQUIRE_ALL=1`, then `just leak-scan` over Postgres, Loki, Tempo, the audit export and every artifact. It joins Local verification from this change on.
- **Nightly:** the same recipe with `--agent claude`, run by a scheduled cloud routine in the agent VM (owner action), never in GitHub Actions.
- Thin console and desktop surface: the audit page (S5) shows a filter for `denied` and `redaction_failed` outcomes, so a human can see what the attacks triggered.

## Capabilities
### New Capabilities
- `adversarial-gate`: the gateway attack suite, its residual register, the fast and stack tiers, live-agent mode and the gate commands.

### Modified Capabilities
- `leak-detection` (from F1): the oracle scans for more encodings.
- `gateway-http-relay` (from S3 to S5): the relay redacts base32, UTF-16 and `\u`-escaped forms too, and the suite holds it to its existing guarantees.

## Out of scope
- Any new GitHub Actions job. The repo CI policy (AGENTS.md) bans test, build, Docker and e2e jobs in Actions; the weekly `adversarial.yml` keeps running only the offline `run.sh all` cases, unchanged.
- Changing the existing vault cases A0 to A6a.
- Delegate and inject modes (D1 to D3), human sign-in (T1), policy (T2), approvals (T4) and honey tokens (T5); later gates attack those.
- Memory dumps of the gateway process and side channels (timing, cache); the gateway host is trusted in this slice.
- Generic LLM jailbreak scanning (garak, promptfoo red-team) beyond the fixed extraction prompts.
- An external pentest (phase 5).

## Depends on
`s5-audit-ledger` (the ledger, its API and the export directory are attack surfaces and evidence).

## Impact
`tests/adversarial` (new `gateway/` cases, prompts, residual register, `run.sh gateway` target), `tests/kit/oracle.py`, `crates/ls-redact`, `services/gateway` (adversarial test module, redaction forms), `justfile` (`adversarial-gate`), `apps/web`, `apps/desktop`, `docs/testing.md`.
