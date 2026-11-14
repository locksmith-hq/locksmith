# Locksmith Subscription Plans

Status: proposal. Treat prices as hypotheses to validate with the first 50 beta users. The behaviour
is specified in `openspec/changes/m13-subscription-licensing`.

## Principles

1. **Free must be good on its own.** Most adoption starts with a solo developer and one agent. Free
   covers the core promise: the agent never sees the secret.
2. **Never hold secrets hostage.** Expired, revoked or unverifiable licenses downgrade to Free.
   Unlock, `smith export` and every Free capability keep working, offline, forever.
3. **Charge for convenience, breadth and organisations, never for basic safety.** Redaction,
   guardrails and Git delegation stay free.
4. **Licenses verify offline.** A license is a signed document. Online checks only refresh it.

## Tiers

| | **Free** | **Pro** | **Team** | **Enterprise** |
|---|---|---|---|---|
| Price | $0 | $12 /user/mo, or $120/yr | $24 /user/mo, or $240/yr, min 3 seats | from $45 /user/mo, annual, custom |
| Users / devices | 1 user, 2 devices | 1 user, 5 devices | per seat, 5 devices each | per seat, custom |
| Projects | 3 | unlimited | unlimited | unlimited |
| Local encrypted vault, recovery phrase | ✓ | ✓ | ✓ | ✓ |
| `smith run` + streaming redactor | ✓ | ✓ | ✓ | ✓ |
| Agent guardrails (hooks, pre-commit, prompt scan) | ✓ | ✓ | ✓ | ✓ |
| Git delegation | ✓ | ✓ | ✓ | ✓ |
| HTTP opaque-token proxy | 2 upstreams | unlimited | unlimited | unlimited |
| DB relay (Postgres/MySQL/Redis) | n/a | ✓ | ✓ | ✓ |
| AWS SigV4 delegation + scoped STS | n/a | ✓ | ✓ | ✓ |
| Process containment and capability tokens | basic (process group) | full | full | full |
| Touch ID / Windows Hello unlock | n/a | ✓ | ✓ | ✓ |
| MCP server (blind create/rotate) | list only | ✓ | ✓ | ✓ |
| Desktop app | read-only | ✓ | ✓ | ✓ |
| Cloud connectors (1Password, AWS SM, GCP SM, Vault) | n/a | ✓ | ✓ | ✓ |
| Update channels | stable | stable, beta | stable, beta | rings, pinning, private mirror |
| Shared E2EE vaults, invites | n/a | n/a | ✓ | ✓ |
| Policy as code (org-wide `locksmith.policy.toml`) | n/a | n/a | ✓ | ✓ |
| Central audit stream + admin revoke | n/a | n/a | ✓ | ✓ |
| SSO (OIDC) | n/a | n/a | ✓ | ✓ |
| SAML, SCIM, SIEM export (Splunk, Datadog, S3) | n/a | n/a | n/a | ✓ |
| Self-hosted sync and license server, air-gapped updates | n/a | n/a | n/a | ✓ |
| Support | community | email, 2 business days | email, 1 business day | SLA, named contact, security review pack |

## Trials and discounts

- 14-day Pro trial with no card, started by `smith license trial`. Once per email.
- Annual billing gets 2 months free.
- Pro is free for maintainers of open-source projects (manual approval).
- Startups (<$5M raised): 50% off Team for the first year.

## Billing mechanics

- **Stripe Checkout** for purchase and **Stripe Customer Portal** for card changes, invoices and
  cancellation. We host no payment UI.
- **Stripe Tax** for VAT and sales tax. Team and Enterprise can pay by invoice.
- Seat changes are prorated. Team admins add seats from the desktop app or `smith team seats`.
- **Dunning:** Stripe Smart Retries, then 7 days `past_due` with full features, then downgrade to
  Free. The never-hostage rule applies throughout.

## Revenue model sanity check (assumptions to validate)

| Metric | Assumption |
|---|---|
| Free → Pro conversion | 3–5% of monthly active Free users |
| Team ACV | 8 seats × $240 = ~$1.9k |
| Gross margin | >90%: no secret hosting on Free/Pro, sync storage is ciphertext only |
| Infra cost driver | sync storage + CDN egress for updates, about $0.02 per active device per month |

## What is *not* sold

- Access to your own secrets.
- Basic leak prevention.
- Telemetry or data about users. Telemetry is opt-in, aggregate, and never sold.
