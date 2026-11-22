# Progress: n1-notifications

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-22 worker
- Task: none - planning
- Verified: `openspec validate n1-notifications --strict`, `bash scripts/tree-check.sh` -> ok
- Notes for next session: pin `lettre` (and `wiremock` if not already a dev-dependency) and record version and release date; pick the next free migration number at apply (T6 and D2 also claim 0014); Mailpit is currently in compose profile `auth` only. Roadmap `Needs` is t3-console-mvp, so groups 5-7 stack on it; group 1 is the contract T5 builds on.
