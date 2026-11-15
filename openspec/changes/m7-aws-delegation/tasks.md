# Tasks

## 1. Relay

- [x] 1.1 Per-session dummy credentials and inbound SigV4 verification with a nonce cache (design D2). Verify: unit tests with AWS's published SigV4 test suite. Done: all 38 header-signing cases of the AWS v4 suite plus the documented S3 streaming example (`ls-proxy/tests/sigv4_suite.rs`); replay cache tests.
- [x] 1.2 Service and region resolution, then upstream re-signing and forwarding for JSON, query and REST-XML protocols (design D1). Verify: integration against LocalStack for STS, S3, DynamoDB, SQS, Lambda and SSM. Done: LocalStack 3.8 through the relay with the AWS CLI: STS, S3, DynamoDB, SQS, Lambda, SSM (`aws_relay.rs`, ignored test run locally). A fake AWS upstream verifies every re-signed request in CI.
- [x] 1.3 Policy model in `.locksmith.toml` and action mapping from the vendored service models (design D3). Verify: a table test for allow, deny and unknown→deny. Done: 16 services / 1,656 operations from botocore; ≥40-row decision table; secret-returning reads need an explicit allow (design D5).
- [x] 1.4 S3 streaming chunked re-signing (design D4), or the documented fallback. Verify: an LocalStack e2e for `aws s3 cp` of a 200 MB file. Done: `aws s3 cp` of 200 MB through LocalStack (CLI 2.15.6 used hashed multipart over plain HTTP); signed `aws-chunked` re-signing is covered by a raw-request test. Signed trailers are refused with a pointer to the contained fallback.

## 2. Contained fallback and revoke

- [ ] 2.1 `smith aws creds --contained` with an STS AssumeRole session policy generated from the project policy. Verify: e2e against a real sandbox AWS account (manual workflow), and the 15-minute expiry is asserted. Partial: `smith aws creds --contained` mints 900-second AssumeRole credentials with the policy as session policy (mock STS and e2e). The real sandbox-account run is still to do.
- [ ] 2.2 Optional revoke-older-sessions deny policy on revoke. Verify: a manual test in the sandbox account. Partial: `revoke_older_sessions` puts the deny policy via IAM PutRolePolicy on `smith revoke` (mock-verified). The manual sandbox test is still to do.

## 3. Diagnostics and adversarial

- [x] 3.1 Doctor checks `aws.relay`, `aws.policy`, `aws.upstream_identity` (sts get-caller-identity via the relay). Verify: snapshots. Done: `doctor_m7` tests pin every branch; `smith --json doctor` checked in `tests/aws.rs`.
- [ ] 3.2 **Gate A2**: scripted plus live Claude (export-credentials, env, `~/.aws`, the CLI cache, a memory dump attempt, replay after revoke). Verify: `run.sh A2 --agent claude` shows that only dummy keys or contained STS are found. Partial: `run.sh A2` passes scripted (export-credentials, env, ~/.aws, daemon memory, revoke replay, contained, outsider). The live Claude half needs the `ANTHROPIC_API_KEY` repo secret.
