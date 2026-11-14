# Proposal: M7 AWS Delegation

## Why

AWS keys are the highest-blast-radius credential most developers hold. v5 relies on
`credential_process` lineage checks, which `aws configure export-credentials` bypasses
(docs/v6-review.md §1.3). v6 signs AWS requests inside Locksmith, so no AWS key reaches the agent.
A scoped STS fallback, honestly labelled, covers tools that cannot use the signing proxy.

## What Changes

- **SigV4 re-signing relay:** `smith run --aws <profile>` sets `AWS_ENDPOINT_URL=http://127.0.0.1:<port>`,
  dummy `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, and the region. The relay checks the incoming
  dummy signature against the session, evaluates policy (service, action, resource ARN), re-signs with
  the real credentials (or STS from an assumed role), and forwards to the real regional endpoint.
- **Scoped STS fallback (contained):** `smith aws creds --contained` mints 15-minute STS credentials
  with an inline session policy limited to the project's declared resources, delivered through Mode C
  plus redaction. Docs and `--explain` call this "disclosed but contained".
- **Policy:** `.locksmith.toml` `[aws]` declares allowed services, actions and resource patterns.
  The defaults are read-only.
- **Revocation:** revoking a session that minted STS credentials attaches a deny-all policy keyed on
  `aws:TokenIssueTime` (the standard revoke-older-sessions pattern) when the user enables it.
- Doctor checks: `aws.relay`, `aws.policy`, `aws.upstream_identity`.

## Usable outcome

The agent runs `aws s3 ls s3://my-bucket` and the SDK calls in the app, inside a session, with no
AWS key present anywhere it can read.

## Capabilities

### New Capabilities
- `aws-delegation`: Signing and authorising AWS API calls on the agent's behalf.

### Modified Capabilities

## Out of scope

- S3 presigned URL generation by clients. Presigned URLs carry signatures, not keys, but they would be
  signed by the dummy key. Documented: use `smith aws presign`.
- GCP and Azure (backlog: GCP via the `CLOUDSDK_API_ENDPOINT_OVERRIDES` relay, Azure via MSAL proxy).

## Impact

`ls-proxy::aws` (the `aws-sigv4` crate for signing, `aws-sdk-sts` for STS). Pro feature.
