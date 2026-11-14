# Tasks

## 1. Site

- [ ] 1.1 Starlight app in `apps/docs` with `packages/ui` tokens, Pagefind, versioning, and a Pages deploy. Verify: a preview deploy per PR.
- [ ] 1.2 `xtask docs-ref` generating the CLI, schema, doctor and MCP references. Verify: the docs build fails when xtask fails (CI test).
- [ ] 1.3 Link checker over the rule and doctor docs URLs, plus `llms.txt` generation. Verify: CI job green, and a broken anchor fails it.

## 2. Content (grows per milestone)

- [ ] 2.1 Quickstart and Concepts (vault, sessions, delegation labels). Verify: a new user completes the quickstart in under 10 minutes (timed test with 3 people).
- [ ] 2.2 Per-agent guides, written as each P1 plugin ships. Verify: each guide's commands are run in CI where possible.
