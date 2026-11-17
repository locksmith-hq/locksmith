# Tasks: F1 test kit

## 1. Leak scanner [opus]
- [x] 1.1 Move `tests/adversarial/oracle.py` to `tests/kit/oracle.py`. Update `tests/adversarial/run.sh`, and confirm `python3 -I tests/kit/oracle.py selftest` passes.
- [x] 1.2 Add sources: postgres (via `psql`), loki and tempo (via the Grafana/Loki/Tempo HTTP APIs on localhost), dir and transcript. Unreachable source → `SOURCE-UNREACHABLE`, non-zero.
- [x] 1.3 Add `just canary new|list` (canaries stored in gitignored `infra/compose/.canaries`, mode 0600) and `just leak-scan [--explain] [--dir P] [--transcript P]`.
- [x] 1.4 Verify: `tests/kit/leak_scan_test.sh` plants a canary in each source in turn and expects a hit, then a clean stack expects exit 0. The output is grepped to prove no canary encoding appears.

## 2. Rust test tooling
- [x] 2.1 Add `cargo-nextest` config (`.config/nextest.toml`, CI profile with JUnit). Switch `just test-rust` to nextest.
- [x] 2.2 Add `insta`, `wiremock`, `testcontainers` (postgres module) and `proptest` as workspace dev-dependencies. Record versions in design.md.
- [x] 2.3 Add `tests/e2e` crate skeleton with one test: connects to the F0 Postgres and WireMock and asserts the WireMock journal.
- [x] 2.4 Verify: `just test-rust` and `just test-e2e` (requires `just up`) pass.

## 3. Local verification
- [ ] 3.1 `just up && just harness-check && just test-e2e && just leak-scan && just ci`
