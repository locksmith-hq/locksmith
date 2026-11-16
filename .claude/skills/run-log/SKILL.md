---
name: run-log
description: End-of-run logging for Locksmith scheduled agents — the run-metadata block, friction entries, the change's progress.md entry, and the agent-log issue comment. Use before your final commit and push.
---

# Run log

## 1. progress.md entry
Append one entry to `openspec/changes/<id>/progress.md`, even if the run failed. The file is append-only. Use this format:
```
## <UTC date time> <worker|rescue|review|learning>
- Task: <id> - <done|failed|blocked|ci-fix>
- Verified: <command> -> <result>
- Notes for next session: <traps, what to try next>
```

## 2. Metadata block
Build the block with the script, passing only your own fields on stdin:
```
bash scripts/run-meta.sh block <<'EOF'
  orchestrator: <model>
  outcome: done|failed|rescue|blocked|idle|ci-fix|merged|learned|no-fix|healthy
  change: <id|none>
  task: <ids|none>
  attempts: <n>
  evaluator: PASS|FAIL|n/a
  just_ci_s: <s|n/a>
  ci_run: <url|none>
  subagents:
    - {role: implementer|evaluator|reviewer|research, tier: <t>, duration_ms: <n|unknown>, tokens: <n|unknown>, tool_uses: <n|unknown>, result: ok|fail}
  escalations: <none|sonnet->opus>
  friction:
    - {what: "<anything that cost more than about 2 min>", lost_s: <n>, fix_idea: "<one line>"}
EOF
```
The script prints one complete fenced block, so don't wrap it in another fence. Take subagent numbers from each Agent result's usage, and write `unknown` instead of guessing. Never put secrets in it.

## 3. agent-log comment
Post one comment on the open issue labelled `agent-log`: first the line `<!-- agent -->`, then 1–3 lines of summary, then the block. Every comment you post anywhere starts with `<!-- agent -->`. Use `gh api repos/locksmith-hq/locksmith/issues/<n>/comments -f body=...`, because `gh issue` is blocked in cloud runs.
