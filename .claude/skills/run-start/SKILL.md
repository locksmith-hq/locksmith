---
name: run-start
description: Start of every scheduled Locksmith agent run. Runs preflight (docker, toolchain, registries, npm, disk, network), starts run metadata, prints active lessons, and brings the change branch up to date. Use first, before any other work.
---

# Run start

1. Run `bash scripts/agent-start.sh <kind>`, where `<kind>` is one of worker, lead, review, health or research. It switches to the routine's GitHub App when the environment holds `AGENT_APP_KEY_<PERSONA>`, and otherwise acts as the owner account.
   - It prints one line per check: `OK`, `FIXED`, `WARN` or `FAIL`.
   - Fix every `FAIL` before doing real work.
   - Record each `WARN` or `FAIL` line, and each `FIXED` except docker (expected), as `friction` (format: `run-log` skill).
2. Read the active lessons the script prints at the end, and follow them. Also read `docs/agents/owner.md`: those are the owner's standing decisions.
3. If you work on an existing `claude/change-<id>` branch and `git rev-list --count HEAD..origin/main` is not 0, run `git merge --no-edit origin/main` before the baseline `just ci`. Never rebase a pushed branch. If the merge conflicts in a way you can't resolve cleanly, run `git merge --abort` and record it as friction.

## Gotchas (cloud VM, observed 2026-11-16)
- `ghcr.io` returns 403 even though the docs allow it. Use Docker Hub images, for example `openbao/openbao:2.7.2`.
- `service docker start` fails. Preflight falls back to `dockerd &`, so don't start Docker by hand.
- The VM runs as root. A test that relies on non-root behaviour may skip itself, which is expected.
- `test-web` needs `node_modules`. If preflight warns about it, start `npm ci` with the `long-commands` skill.
