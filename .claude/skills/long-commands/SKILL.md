---
name: long-commands
description: Run anything that may take over 2 minutes (cold cargo build/test, docker compose pull, npm ci, cargo install) in the background with a hard timeout and poll it, so the run never sits blocked. Also rules for retries and non-interactive commands.
---

# Long commands

1. Start the command in the background: `bash scripts/bg.sh start <name> <timeout-s> -- <command...>`.
2. Meanwhile, do other work.
3. To check on it, run `bash scripts/bg.sh wait <name>` (at most 110 s). It prints the tail of the log and the exit code. Exit 124: still running.

## Rules
- **Wait for state, not time.** Foreground `sleep` is blocked: use `bg.sh wait`, or `until <check>; do sleep 2; done` inside a timeout. Never sleep for a subagent; run it in the foreground (`evaluate-escalate`).
- **No prompts.** Use `-y`, `CI=1`, `--no-pager`, `GIT_EDITOR=true` and `</dev/null`.
- **Stop retrying identical failures.** If the same command fails twice with the same error, stop and treat it as a task failure (see the `evaluate-escalate` skill).
- **A failing test run gets one rerun.** If it fails once, rerun it once before treating the failure as real, and record both results. A known flaky test exists (lesson L0, not yet identified).

## Gotchas
- **`docker run -i` processes:** for example, MCP servers over stdio. Check the image's `--help` for its transport flag first, since grafana's MCP server defaults to SSE. Always wrap the command as `timeout -s KILL 60 docker run -i --rm --init --name <n> ...` and run `docker rm -f <n>` afterwards. A plain TERM signal does not stop the docker client (lesson L4).
