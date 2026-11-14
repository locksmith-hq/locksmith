# Proposal: M11 Diagnostics and Support

## Why

A security tool that sits between agents and every credential will fail in confusing ways: proxies,
hooks, signing, kernel versions. Each support ticket without data costs hours, and users do not
trust a security tool that phones home. M0 created `smith doctor`. M11 completes the support story:
self-fixing doctor, privacy-safe support bundles, structured redacted logs, and **opt-in** telemetry
and crash reports.

## What Changes

- `smith doctor --fix`: checks marked fixable apply their fix after confirmation (permissions,
  hook reinstall, daemon restart, git include refresh). `--watch` re-runs every 2 s while the user
  fixes things.
- `smith doctor --agent`: an output mode for an agent to read. It is concise, lists remediation
  commands, and never includes paths under the vault dir.
- Logging: `tracing` JSON logs in the platform log dir, daily rotation, 7-day retention, and a
  redaction layer that drops any field whose type is a secret and runs the redactor on messages.
  `smith logs [--follow] [--level]`.
- `smith diag bundle`: a `.zip` of version info, doctor JSON, a config allowlist, the last 2000 log
  lines, audit verify **results** (never rows), platform facts. It is scanned by the redactor plus
  generic secret rules before writing, and the user previews the manifest. `smith diag upload`
  sends it to support only on explicit command, with a ticket id.
- Crash reports: a panic hook writes a local report (redacted message and symbolicated backtrace, no
  memory, no env). The next `smith` invocation asks whether to include it in a bundle.
- Telemetry: **off by default**. `smith telemetry enable` sends daily aggregate counters (commands
  used, blocks by rule id, doctor failures by id, versions, OS) with a random install id. The schema
  is published in docs, and `smith telemetry preview` shows the exact payload.
- `smith diag selftest`: crypto KATs, redactor corpus, IPC round-trip, relay loopback.

## Usable outcome

When something breaks, a user runs `smith doctor --fix`. If that does not fix it, they attach
`smith diag bundle` to a ticket, knowing it contains no secrets.

## Capabilities

### New Capabilities
- `support-bundle`: Collecting privacy-safe diagnostics for support.
- `telemetry`: Opt-in aggregate usage and crash reporting.

### Modified Capabilities
- `diagnostics`: Adds fix, watch and agent modes, plus logging. Delivered as ADDED requirements in
  this delta because the base spec is archived from M0.

## Out of scope

- A support desk or ticketing integration (email to support@ with the bundle id).

## Impact

`ls-diag`. A telemetry ingest endpoint in `services/license-server` (a separate route, a separate
table, no join to licensing data).
