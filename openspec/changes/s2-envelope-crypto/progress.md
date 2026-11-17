# Progress: S2 envelope crypto

## 2026-11-17 10:37 worker
- Task: planning (proposal, specs, design, tasks) - done
- Verified: openspec validate s2-envelope-crypto -> valid
- Notes for next session: depends on S1 (PR #106, parked on rescue #108). Record exact crate versions in design.md OSS table when implementing.

## 2026-11-17 worker (tasks 1.1, 1.2)
- Task: 1.1 `crates/ls-envelope` (header codec promoted from `a0-spikes`, `seal_version`/`open_version`, `DataKey`/`SealedVersion` without Debug/Display/Clone) - implemented; 1.2 committed KAT vectors (`vectors/v1.json`, generated independently with pyca/cryptography; vector 1 equals the A0-7 spike KAT) and proptests - implemented. Tasks not ticked.
- Verified: `cargo nextest run -p ls-envelope` 20/20 pass; `cargo clippy -p ls-envelope --all-targets -- -D warnings` clean; `cargo fmt --check` clean; tree-check OK.
- Not run: `cargo deny check` (not installed), gitleaks (not run locally; `vectors/v1.json` holds fixed hex test keys).
- Notes for next session: `a0-spikes` still has its own copy of the header code; the payload header `key_id` is a random per-DEK id, and the `dek-wrap` key_id for task 2.1 is the transit key name plus version.
