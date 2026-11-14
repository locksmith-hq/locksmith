# Tasks

## 1. Relay

- [ ] 1.1 Per-session dummy credentials and inbound SigV4 verification with a nonce cache (design D2). Verify: unit tests with AWS's published SigV4 test suite.
- [ ] 1.2 Service and region resolution, then upstream re-signing and forwarding for JSON, query and REST-XML protocols (design D1). Verify: integration against LocalStack for STS, S3, DynamoDB, SQS, Lambda and SSM.
- [ ] 1.3 Policy model in `.locksmith.toml` and action mapping from the vendored service models (design D3). Verify: a table test for allow, deny and unknown→deny.
- [ ] 1.4 S3 streaming chunked re-signing (design D4), or the documented fallback. Verify: an LocalStack e2e for `aws s3 cp` of a 200 MB file.

## 2. Contained fallback and revoke

- [ ] 2.1 `smith aws creds --contained` with an STS AssumeRole session policy generated from the project policy. Verify: e2e against a real sandbox AWS account (manual workflow), and the 15-minute expiry is asserted.
- [ ] 2.2 Optional revoke-older-sessions deny policy on revoke. Verify: a manual test in the sandbox account.

## 3. Diagnostics and adversarial

- [ ] 3.1 Doctor checks `aws.relay`, `aws.policy`, `aws.upstream_identity` (sts get-caller-identity via the relay). Verify: snapshots.
- [ ] 3.2 **Gate A2**: scripted plus live Claude (export-credentials, env, `~/.aws`, the CLI cache, a memory dump attempt, replay after revoke). Verify: `run.sh A2 --agent claude` shows that only dummy keys or contained STS are found.
