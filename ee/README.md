# ee/ (source-available)

Paid, self-host features live here, in the open, under [LICENSE](LICENSE): you can read, build and test them for free; production use needs a subscription. The same pattern is used by Infisical, PostHog, n8n, Metabase and Mattermost.

| What | Where |
|---|---|
| The seam: plan, features, limits, `EntitlementSource` (Apache-2.0, in core) | `crates/ls-entitlements` |
| Offline license verification into entitlements (this license) | `ee/crates/ls-ee-license` |
| License server, billing, plan catalog, SaaS operations | private `locksmith-cloud`, never here |

Rules
- Core never depends on `ee/`: `deny.toml` bans it. Core asks `ls-entitlements`; an enterprise build injects the `ee/` source. Do not link `ee/` into the AGPL services.
- Licensing never blocks unlock or export. `Entitlements::allows(CoreOp)` is always true, a lapsed or bad license falls back to the free tier, and tests assert both.
- Add a `Feature` variant only together with the code that checks it (`Entitlements::require`).
- The signing key stays with the maintainers; a deployment supplies the public key and the signed license file.

Status: the license text is a draft and must be reviewed by counsel before the first sale. No paid feature exists yet, so the free tier is today's whole product.
