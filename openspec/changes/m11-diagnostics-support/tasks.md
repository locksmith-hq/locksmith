# Tasks

## 1. Doctor completion

- [ ] 1.1 Add `fixable` to the check trait, plus `--fix` with confirm, `--watch` and `--agent`. Retro-fit the fixes for M0–M10 checks. Verify: e2e for the permission fix and an agent-mode snapshot.

## 2. Logging

- [ ] 2.1 tracing JSON file layer with rotation and retention, the redaction layer, and `smith logs`. Verify: the trace-level canary test.

## 3. Bundle and crash

- [ ] 3.1 Collector, three-layer scrubbing and abort-on-finding (design D1), the manifest preview. Verify: the canary-everywhere test, and an assertion of no network calls.
- [ ] 3.2 `smith diag upload` to a presigned URL from the license server with a ticket id. Verify: an integration test against a local server.
- [ ] 3.3 Panic hook and crash report (design D3), `smith diag symbolicate`, and debug symbols published by `release.yml`. Verify: a forced-panic test leaves a redacted report.
- [ ] 3.4 `smith diag selftest`. Verify: it runs in CI on all platforms.

## 4. Telemetry

- [ ] 4.1 Client: enable, disable, preview, the daily sender with backoff, and a published JSON schema in `apps/docs`. Verify: schema tests, and a fresh-install no-network test.
- [ ] 4.2 Ingest route in `services/license-server`: separate table, IP truncation, 13-month retention job. Verify: an integration test.

## 5. Adversarial

- [ ] 5.1 **Gate A8**: bundle, logs, crash report and telemetry with canaries. Verify: `run.sh A8` passes.
