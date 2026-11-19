## Why
AWS is the second most common authenticated surface an agent touches after Git, and the AWS CLI and SDKs cannot use the JSON relay. Today the only AWS paths are local-daemon ones (M7: the SigV4 re-signing relay and `smith aws creds --contained`, `crates/ls-proxy/src/aws/`). A hosted-org agent has no way to run `aws s3 ls` without a long-lived key on its machine. Owner decision H1-2 allows exactly one credential in an agent's hands: a short-lived, scoped one, issued by a tool that is off by default.

## What changes (usable outcome)
An enrolled agent runs `smith aws setup` once, then plain `aws s3 ls`, `aws sts get-caller-identity` or any SDK call works with **no long-lived key anywhere on the agent host**. The AWS profile uses `credential_process = smith aws credential-process`; each call asks the gateway, which assumes the bound role with an STS session policy that narrows it to the grant, and returns credentials that expire in 15 to 60 minutes. The long-lived base credential or role trust stays in the gateway. Every issue writes a ledger event. Tested end to end against moto first; AWS-only behaviour is left to a named P1 smoke check.

Protection is labelled honestly: the agent does see the temporary credentials (containment by scope and expiry, not prevention), and the tool that vends them is off by default.

## Out of scope
- Re-signing relay in the hosted gateway (the M7 local relay stays as is); S3 streaming signing.
- Revoking already issued sessions in AWS beyond the existing `revoke_older_sessions` deny policy (T8 owns console revoke).
- Per-action policy language (T2 Cedar); the grant carries a plain allow-list of actions and resource ARNs.
- IAM Identity Center and web-identity federation (D4), cross-account setup automation, the P1 cloud dev account.

## Depends on
none (builds on the shipped S3 gateway, S4 connector, S5 ledger and M7 `ls-proxy::aws::sts`). Nothing in the roadmap lists D2 in `Needs`, so there is no Contract task group.
