---
name: long-commands
description: Run anything that may take over 2 minutes (cold cargo build/test, just ci, docker compose pull, npm ci, cargo install) in the background with a hard timeout and poll it, so the run never sits blocked. Also rules for retries and non-interactive commands.
---

# Long commands

1. Start the command in the background: `bash scripts/bg.sh start <name> <timeout-s> -- <command...>`.
2. While it runs, do other useful work, such as reading code or preparing the next step.
3. To check on it, run `bash scripts/bg.sh wait <name> <max-s>`. It prints the tail of the log and the exit code. Exit code 137 means the timeout killed the command; exit code 124 means it is still running.

## Rules
- **Wait for state, not time.** Poll the thing you need, for example `until docker info >/dev/null 2>&1; do sleep 2; done`, inside a timeout. Never use fixed long sleeps.
- **No prompts.** Use `-y` or `--yes`, set `CI=1`, and use `--no-pager` and `GIT_EDITOR=true`.
- **Stop retrying identical failures.** If the same command fails twice with the same error, stop and treat it as a task failure (see the `evaluate-escalate` skill).
- **`just ci` gets one rerun.** If it fails once, rerun it once before treating the failure as real, and record both results. A known flaky test exists (lesson L0, not yet identified).

## Gotchas
- **`docker run -i` processes:** for example, MCP servers over stdio. Check the image's `--help` for its transport flag first, since grafana's MCP server defaults to SSE. Always wrap the command as `timeout -s KILL 60 docker run -i --rm --init --name <n> ...` and run `docker rm -f <n>` afterwards. A plain TERM signal does not stop the docker client (lesson L4).
