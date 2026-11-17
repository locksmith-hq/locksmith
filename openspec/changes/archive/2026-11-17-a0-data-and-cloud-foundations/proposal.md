# Proposal: A0 data and cloud foundations

## Why
Some choices get expensive to change once real data exists:
- the database engine and version
- how customers are separated
- the row ID format
- the format of every encrypted value
- regions
- the AWS account layout
- KMS keys
- where the audit log is stored
- who manages users, how every AWS service is tested locally, and what `dev` may cost

S1 creates the first schema and S2 the first ciphertext. So these are decided and proven here, before S1 starts, from sourced evidence rather than memory.

## Usable outcome
- Every decision in design.md is backed by a source or a spike.
- Spikes run on the F0 stack and prove the choices that bear load:
  - Row-level security isolates orgs when queried through `sqlx`.
  - `uuidv7()` works on Postgres 18.
  - The encrypted-value header round-trips, and tampering with its fields is rejected.
- The F0 stack is pinned to the same Postgres major version as RDS.

## Out of scope
Building AWS resources (phase 4, P1). Choosing between ECS and EKS beyond the default recorded here. Billing.

## Depends on
F0 (spikes run on its Postgres). Owner approval of design.md before S1 starts.

## Impact
- `openspec/specs/data-foundations` (after archive).
- Spike tests in `tests/spikes/a0/`.
- F0 compose bumped from `postgres:17` to `postgres:18`.
- S1, S2, S5, T1 and P1 must follow these decisions.
- T1 uses Cognito in our cloud and Keycloak locally, behind generic OIDC. P1 builds the $5/month `dev` account with its budget guardrails.
