# Design: A0 data and cloud foundations

Evidence was gathered on 2026-11-16. Items marked **[verify]** were not confirmed from a primary source; each has a spike or P1 check that confirms it.

## Decisions and evidence

| # | Decision | Alternatives rejected | Evidence | Cost to change |
|---|---|---|---|---|
| 1 | **PostgreSQL 18**, with the same major version locally (compose `postgres:18`), on RDS and Aurora, and for self-hosters. | PG 17: no built-in UUIDv7. | PG 18 GA 2025-09-25; community EOL 2030-11-14; current minor 18.7 (https://www.postgresql.org/support/versioning/). RDS: PG 18 since 2025-11-14, latest 18.6, standard support to 2031-02-28 (https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-release-calendar.html). Aurora PG 18 GA 2026-06-11 (https://aws.amazon.com/about-aws/whats-new/2026/06/amazon-aurora-postgresql-major-version-18). | High |
| 2 | **Vanilla Postgres features only.** The only extension allowed is `pgcrypto`, and only if a spike needs it. **No pgmq.** Jobs use a `FOR UPDATE SKIP LOCKED` table (later `apalis`, which uses the same method). | pgmq; pg_cron for app logic. | pgmq is not in the RDS PG 17/18 extension list (https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-extensions.html). Self-hosters run plain Postgres. | High |
| 3 | **Aurora DSQL is rejected.** | DSQL | It has no triggers and no extensions. Isolation is fixed at Repeatable Read with optimistic retries, and transactions are capped at 3,000 rows. SKIP LOCKED and LISTEN/NOTIFY are not listed. **Correction to the earlier chat claim: DSQL now supports foreign keys** (announced 2026-08-27). Sources: https://docs.aws.amazon.com/aurora-dsql/latest/userguide/CHAP_quotas.html, https://aws.amazon.com/about-aws/whats-new/2026/08/aurora-dsql-foreign-key-constraints/ | n/a |
| 4 | **Multi-tenancy uses shared tables with `org_id` on every tenant row and Postgres RLS** (`FORCE ROW LEVEL SECURITY`). The app connects as a role that is neither table owner nor `BYPASSRLS`. Migrations run as a separate owner role. Enterprise customers can get a dedicated database with the same schema. | Schema per tenant; database per tenant by default. | AWS RLS multi-tenant guidance: owners and `BYPASSRLS` skip policies unless FORCE is set, and a shared login with a session variable scales better than a role per tenant (https://aws.amazon.com/blogs/database/multi-tenant-data-isolation-with-postgresql-row-level-security/). | Very high |
| 5 | **Tenant context is set per transaction** with `set_config('app.org_id', $1, true)` inside the same sqlx transaction as the queries. Session-level `SET` is banned, and a lint or test enforces this. | Session `SET`; a role per tenant. | Session settings leak to the next pooled checkout. Transaction-local settings reset at COMMIT (AWS blog above; https://www.bytebase.com/blog/postgres-row-level-security-footguns/). Spike task 2.x proves it with sqlx. | High |
| 6 | **Primary keys are UUIDv7 from `uuidv7()`**, and the app may also generate v7 IDs. No serial IDs are exposed. | bigserial (guessable, leaks counts, breaks merges); UUIDv4 (poor index locality). | `uuidv7()` is built into PG 18 (PG 18 release notes, https://www.postgresql.org/about/news/). | Very high |
| 7 | **Every encrypted value carries a versioned header:** `magic(2) ‖ format_ver(1) ‖ alg_id(1) ‖ key_id(16) ‖ nonce ‖ ciphertext ‖ tag`. The AEAD binds AAD = `org_id ‖ secret_id ‖ version ‖ purpose`. The DEK wrap uses the same header. [opus] | Raw AEAD output without a header. | Without an algorithm ID and key ID we cannot rotate keys or move to FIPS (aws-lc-rs) without re-encrypting everything blind. Binding AAD stops a ciphertext from being moved between rows or orgs. Proven by KATs and swap tests. | Very high |
| 8 | **AWS DB service: no RDS Proxy at first.** Services use their own sqlx pool. Dev uses **Aurora Serverless v2 with auto-pause (min 0 ACU)**. The prod choice between RDS and Aurora Multi-AZ is made in P1 from load numbers. | RDS Proxy now; DSQL. | RDS Proxy pins sessions on any `SET`/`set_config` and on `LISTEN`, and an attached proxy stops Serverless v2 from auto-pausing (https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-pinning.html). Serverless v2 scales to 0 with auto-pause. Resume takes about 15 s, and storage is still billed while paused (https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2-auto-pause.html). Whether a transaction-local `set_config` pins under the proxy is **[verify]**, checked in P1. | Low, as long as decisions 1–2 hold (both run plain PG). |
| 9 | **Regions:** every org row has a `region` from day one. Start with one US region and add an EU cell later. Regions are separate deployments (cells) with no cross-region database. | A global single database. | Data residency requests are standard in B2B security sales. A `region` column costs nothing now, while moving data between regions later is a migration. KMS quota is per region (row 10). | High |
| 10 | **KMS:** one customer-managed key per environment per region wraps the gateway keys. A customer-supplied key is an enterprise option. Gateways cache unwrapped DEKs for a short time to stay within the KMS rate limit. | One key per tenant by default; multi-Region keys. | $1 per key per month, $0.03 per 10k symmetric requests, 100k keys per region quota. The shared crypto request quota is 10k–100k/s depending on region and is counted across all callers (https://aws.amazon.com/kms/pricing/, https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html). Multi-Region keys share key material across regions, which conflicts with the cell model (row 9). Their caveats are **[verify]** in P1. | High |
| 11 | **Audit storage:** the hash chain lives in Postgres (S5). Signed checkpoints are exported to S3 with Object Lock in **compliance mode** for prod and **governance mode** for dev. | Postgres only (an attacker who owns the DB rewrites history); a public log (Rekor). | In compliance mode no one, including root, can delete or shorten retention. Object Lock needs versioning (https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html). | Medium |
| 12 | **Account layout:** AWS Organizations plus IAM Identity Center now, both free. OUs: Security (Log Archive, Audit), Infrastructure, Workloads (`control-plane-{dev,prod}`, `gateway-{dev,prod}`), Sandbox. Control Tower is optional later, since its cost is mostly AWS Config. | One account for everything. | AWS multi-account whitepaper OU model (https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/recommended-ous-and-accounts.html). Control Tower pricing: no charge itself, AWS Config is the main cost (https://aws.amazon.com/controltower/pricing/). Splitting the gateways into their own account enforces the zero-knowledge model (control plane ≠ gateway trust domain). | Very high once live |
| 13 | **Compute: ECS Fargate first**, with Helm kept for self-host. | EKS. | EKS costs $0.10 per cluster-hour (about $73/month) per environment. ECS and Fargate have no control-plane fee (https://aws.amazon.com/eks/pricing/). Containers keep this easy to change. | Low |

## OSS used
| Package | Licence | Version | Last release | Note |
|---|---|---|---|---|
| PostgreSQL | PostgreSQL | 18.7 (RDS 18.6) | 2026 | `postgres:18` image |
| sqlx | Apache/MIT | 0.9.0 | 2026-05-21 | already chosen |
| uuid (Rust, `v7` feature) | Apache/MIT | implementer records | n/a | app-side v7 |
| chacha20poly1305 / aes-gcm | Apache/MIT | 0.11.x | 2026-08 | header format KATs |

## Built in-house
- The 20-odd-byte ciphertext header: no standard envelope format fits gateway wrapping plus AAD binding. Before designing it, `age` and HPKE were considered. `age` remains the format for export files.
- The RLS policies, which are plain SQL.

## How an agent debugs this
- The `postgres` MCP shows policies with `SELECT * FROM pg_policies`, and `just psql` with `SET ROLE app` reproduces a cross-tenant read.
- Spike output: `cargo nextest run -p a0-spikes`.
- Header failures print the field that failed (magic, version, alg, key_id, AAD) and never the plaintext.

## Open questions for the owner
1. First region: us-east-1 (largest quotas) or eu-west-1?
2. Is EU data residency needed at launch?
