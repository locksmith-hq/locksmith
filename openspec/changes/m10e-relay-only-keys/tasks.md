# Tasks

## 1. Policy and enforcement (daemon: authorization path)
- [ ] 1.1 Extend `Policy`/`Project` with `inject` and `http.<KEY>.hosts` (deny_unknown_fields kept; clear parse errors). Verify: unit tests for parse, defaults, unknown keys.
- [ ] 1.2 Enforce relay-only in the run path for agent leases on the final key set, audited `BLOCKED relay_only`. Verify: tests for binding keys, `--only`, `--all`, mixed allowed/denied (deny wins, nothing injected), human lease unaffected.
- [ ] 1.3 Compute relay hosts from policy for agent leases; drop binding-only hosts; audited `BLOCKED relay_host`. Verify: test that an agent-edited binding adding an attacker host cannot receive the key (the TEST canary through a local echo server).

## 2. Relay hardening (ls-proxy)
- [ ] 2.1 Network guard with resolve-then-dial on the checked IP, metadata always blocked, policy allowlist. Verify: unit tests (IPv4/6 ranges, mapped addresses, rebinding stub resolver returning public then private).
- [ ] 2.2 Response redaction tests with an echo upstream (header, body, gzip, chunk split). Verify: oracle finds no value.

## 3. Surface and docs
- [ ] 3.1 `locksmith_status`/Sessions detail show injectable keys count and "relay-only" for the rest (names only). Verify: MCP schema test (no value fields), Vitest.
- [ ] 3.2 Update locksmith, locksmith-sessions and http-api skills, the policy example, and docs. Verify: skill/doc lint, drift test.

## 4. Extraction suite
- [ ] 4.1 E2E: agent lease with `TEST` not in `inject`: `smith run` refuses; the relay refuses a non-policy host; token calls to a policy host never return the value; the encoding probe script finds nothing. Verify: test passes in CI with a local echo server.
