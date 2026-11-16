# Monthly research refresh (Sonnet, 1st of the month)

The project rule is to decide from evidence and to reuse maintained OSS. This run keeps that evidence current.

1. Run `bash scripts/run-meta.sh start research`. Read `docs/research/oss-building-blocks.md`, `docs/research/infisical.md`, and the "OSS used" tables in `openspec/changes/*/design.md`.
2. Check every listed package and MCP server against primary sources: `gh api repos/<o>/<r>`, `.../releases/latest`, and the crates.io, npm and PyPI APIs. Use haiku subagents in batches. For each one, record:
   - latest version and release date
   - licence, flagging any change to AGPL, SSPL or BSL
   - archived status
   - no release in more than 12 months
3. Run `cargo audit` (installing it with `cargo install cargo-audit --locked` if needed) and `npm audit --omit=dev`.
4. Look for new or better-maintained MCP servers for our stack: Postgres, Grafana/Loki/Tempo, OpenBao, Docker, AWS and Playwright.
5. Check Infisical for changes since the date in `infisical.md`: releases, pricing, the `ee/` services list, and Agent Vault.
6. If anything changed:
   - Create the branch `claude/research-<YYYY-MM>`.
   - Update the docs, keeping their format, with source URLs and the check date. Mark anything unverified.
   - Push once, open a PR, and mark it ready as described in `merge.md`.

   If nothing changed, don't create a branch.
7. Raise an owner decision only for:
   - a licence change to a non-compatible licence
   - an archived dependency
   - a high or critical advisory that affects us
   - an Infisical change that changes the roadmap
8. Post an agent-log comment with the metadata.
