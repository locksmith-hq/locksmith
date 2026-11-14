# Locksmith

Credential broker for AI coding agents: agents perform authenticated operations (Git, HTTP APIs,
databases, AWS) without ever holding the real credential.

This is the product monorepo: Rust core (`crates/`), backend services (`services/`), apps
(`apps/web`, `apps/docs`, `apps/desktop`), shared TS (`packages/`), agent/IDE/CI plugins
(`integrations/`), infra and tests. Layout rules: [openspec/config.yaml](openspec/config.yaml).

## Planning (OpenSpec)

- [docs/roadmap.md](docs/roadmap.md): milestones M0–M16 plus the parallel tracks W1, W2, P1
- [docs/v6-review.md](docs/v6-review.md): what changed from the original v5 plan, and why
- [docs/product/subscription-plans.md](docs/product/subscription-plans.md): Free / Pro / Team / Enterprise
- `openspec/changes/<id>/`: proposal, design, delta specs and tasks per milestone

Workflow: `openspec list` → `/opsx:apply m0-foundation` → when its gate passes, `/opsx:archive m0-foundation`.
