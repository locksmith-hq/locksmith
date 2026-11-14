# Proposal: W1 Landing Site (parallel track)

## Why

The private beta (M5) needs a place to explain the product, collect waitlist signups and qualify
design partners. Paid launch (M13) needs pricing, a changelog and trust pages. The site lives in
this monorepo (`apps/web`), so pricing and features come from the same `features.toml` the product
enforces and cannot drift.

## What Changes

- `apps/web`: Astro (static output, React islands only where interactive), using `packages/ui`.
  Deployed to Cloudflare Pages via `infra/`.
- Pages: home (problem → how it works → the agent-never-sees-the-secret demo), how it works
  (delegation diagrams), security (threat model summary, honest guarantee labels, audits),
  pricing (generated from `features.toml`), changelog (generated from release notes), docs link,
  waitlist and design-partner form, legal (privacy, terms, DPA, subprocessors).
- Waitlist backend: a POST route on `services/license-server` (email, agent used, team size) with
  double opt-in. Plausible-style cookieless analytics, no third-party trackers.
- Install page: per-OS commands, verification instructions (minisign/TUF, provenance).
- Performance and accessibility budgets: Lighthouse ≥ 95 in all categories, WCAG 2.2 AA.

## Usable outcome

From week 2, the public can read what Locksmith does and join the waitlist. At launch they can
compare plans and buy.

## Capabilities

### New Capabilities
- `marketing-site`: Public website content, waitlist and pricing presentation.

### Modified Capabilities

## Out of scope

- A blog CMS. Posts are markdown in the repo.

## Impact

`apps/web`, `packages/ui`, `infra/` (Pages project, DNS), a waitlist route in the license server.
Depends on M0 (workspace). The pricing page depends on M13's `features.toml`. Until then it shows
"coming soon".
