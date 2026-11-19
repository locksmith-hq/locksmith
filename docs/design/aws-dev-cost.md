# AWS dev environment: cost brief (owner approval needed, P1-1)

**Status: draft for owner approval. Nothing is applied until `openspec/decisions.md` records P1-1.**

**Price caveat.** The agent VM cannot reach `aws.amazon.com` (blocked by the network policy), so the unit prices below are us-east-1 list prices from the worker's knowledge, not fetched today. Each row cites its pricing page. Before approval, a person or an online session must check every row against its page. The totals are recomputed from `aws-dev-cost.csv` by `bash scripts/aws-cost-check.sh`.

## Assumptions
- Region us-east-1 (A0-9); one `dev` account; 5 GB in S3, 2 GB in ECR, 1 GB of Aurora storage, 0.2 GB of logs a month.
- A session is 2 hours with two ARM Fargate tasks (0.25 vCPU, 0.5 GB each) and two public IPv4 addresses; Aurora wakes for those 2 hours at 1 ACU.
- Four sessions a month. Cognito stays inside its free tier of monthly active users; the first two Budgets are free.

## Table
Prices, quantities and sources are in `docs/design/aws-dev-cost.csv` (one row per resource):
KMS key, Aurora storage and ACU hours, S3, ECR, Cognito, Budgets, Fargate vCPU and memory, public IPv4, CloudWatch logs.

## Totals
- Idle per month: $1.52
- Per session: $0.40
- Total per month (4 sessions): $3.12

This is under the $5 budget with about $1.88 of headroom. The headroom is thin if sessions are forgotten, so the design has a 2-hour auto-destroy timer, a $5 Budget with $1 and $3 alerts and a deny-create action, and SCPs.

## Options for the owner
| Option | Effect | Recommendation |
|---|---|---|
| Aurora Serverless v2 PostgreSQL 18, min 0 ACU auto-pause | Matches A0-1 and A0-8. Resume takes seconds to tens of seconds. | **Yes**, if PG18 and scale-to-zero are offered in us-east-1 (check at apply). |
| Fallback: newest supported PG major, same settings | Same cost; engine differs from A0-1 until PG18 lands. | Only if PG18 is missing; record it. |
| Fallback: RDS `db.t4g.micro` | About $12 a month always on, so it breaks the $5 budget. | No. |
| Cognito hosted domain prefix (Essentials) | Free inside the free tier; no custom domain, so no Route 53. | **Yes.** |
| Banned: NAT gateway (~$32/mo), ALB (~$16/mo), interface endpoints, Secrets Manager, Route 53 zones | Each would alone break the budget. The plan policy rejects them. | Keep banned. |

## Owner action
Reply `approved` on the needs-owner issue (or record P1-1 in `openspec/decisions.md`) after verifying the prices. Declining or changing a limit is also fine; the lead will discuss alternatives.

## Artifact brief draft
One page: the totals above, the three options table, and the ban list. Lead to publish with the approval request.
