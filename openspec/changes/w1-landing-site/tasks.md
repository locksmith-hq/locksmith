# Tasks

## 1. Foundation

- [ ] 1.1 `packages/ui` design tokens (light/dark), typography, core components (Button, Card, CodeBlock with copy, Callout with guarantee-label variants). Verify: Storybook or Ladle builds, and Vitest snapshot tests pass.
- [ ] 1.2 Astro app in `apps/web` with layout, nav, footer, SEO meta, sitemap, and Cloudflare Pages deploy via `infra/`. Verify: a preview deploy per PR.

## 2. Content

- [ ] 2.1 Home with the animated "agent pushes, token never appears" terminal demo (recorded asciinema of a real M5 run), plus How it works and Security pages. Verify: content review by a second person against docs/v6-review.md.
- [ ] 2.2 Install page and the changelog generated from GitHub release notes at build time. Verify: the build renders the latest release.
- [ ] 2.3 Legal pages (privacy, terms, DPA, subprocessors). Verify: legal review checklist ticked.

## 3. Conversion

- [ ] 3.1 Waitlist and design-partner forms, plus the double opt-in route in the license server. Verify: e2e Playwright test against staging.
- [ ] 3.2 Pricing page generated from `features.toml` (placeholder until M13). Verify: a test that changing the fixture moves the feature.
- [ ] 3.3 Cookieless analytics (self-hosted Plausible or Umami). Verify: the cookie and tracker audit test.

## 4. Quality gates

- [ ] 4.1 Lighthouse CI and axe in the web CI job with the budgets. Verify: CI fails on an injected violation.
