# Design: F1 test kit

## Leak scanner
- Reuses the existing `tests/adversarial/oracle.py`. It already generates encoding variants (utf8, percent, JSON, hex, base64 at every alignment) and never prints the canary.
- It stays Python stdlib-only, run with `python3 -I`, so it adds no new dependency.
- New sources:
  - **Postgres:** `psql --csv` dumps text-castable columns of all user tables.
  - **Loki:** `query_range` for the last N minutes across all streams.
  - **Tempo:** a search, then fetch each trace's JSON.
  - **Files:** a path argument.
  - **Transcript:** a JSONL path.
- Output is one line per hit: `LEAK <encoding> <source>:<locator>`. The exit code is the number of hits, capped at 1.

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| Reuse in-repo oracle | gitleaks / trufflehog for canaries | Pattern scanners find *known secret formats*. We need *a specific random value in any encoding*, which the oracle already does, with a self-test (`oracle.py selftest`). gitleaks stays for repo scanning (already in `.gitleaksignore` flow). |
| `cargo-nextest` | `cargo test` | Faster, per-test process isolation, retries, JUnit for CI. Apache/MIT. https://nexte.st |
| `insta` snapshots | hand-written asserts on JSON | Apache-2.0, widely used, reviewable snapshots. https://insta.rs |
| `wiremock` crate (in-process) + WireMock container (e2e) | mockito | Async, per-test isolation. https://github.com/LukeMathWalker/wiremock-rs |
| `testcontainers` crate for isolated DB tests | one shared DB | Tests that mutate schema get their own Postgres. Shared F0 DB for e2e only. https://github.com/testcontainers/testcontainers-rs |
| `proptest` for encoders and parsers | quickcheck | Already used in repo (redactor property tests). |

The implementer records the exact version and release date of each crate in the OSS table at implementation time (`cargo search` / crates.io API).

## OSS used
| Package | Licence | Use |
|---|---|---|
| cargo-nextest | Apache-2.0/MIT | runner |
| insta | Apache-2.0 | snapshots |
| wiremock | Apache-2.0/MIT | HTTP mocks |
| testcontainers | Apache-2.0/MIT | isolated Postgres |
| proptest | Apache-2.0/MIT | property tests |

## Versions (recorded 2026-11-17, crates.io)
| Crate | Version | Released |
|---|---|---|
| insta | 1.49.0 | 2026-10-03 |
| wiremock | 0.6.5 | 2025-08-24 |
| testcontainers | 0.28.0 | 2026-08-06 |
| testcontainers-modules (postgres) | 0.15.0 | 2026-02-21 |
| proptest | 1.12.0 | 2026-10-10 |

They are declared in `[workspace.dependencies]` in the root `Cargo.toml`; crates opt in as dev-dependencies.

## How an agent debugs this
- `just leak-scan --explain` lists the sources it covered and the row and line counts for each, so a scan that covered nothing is obvious.
- `just canary list` shows canary ids and never their values.
- Test failures: `cargo nextest run --no-capture -E 'test(name)'`. Snapshots: `cargo insta review`.
