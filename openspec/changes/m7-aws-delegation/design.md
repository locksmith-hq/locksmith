# Design: M7 AWS Delegation

## Decisions

### D1. Endpoint override
Current AWS CLI v2 and SDKs honour `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_<SERVICE>`. The relay uses
the request's `Host`/path plus the `X-Amz-*` headers and its signing scope to work out the service and
region, then sends to `https://<service>.<region>.amazonaws.com` (or the virtual-hosted S3 form).
S3 path-style is forced with `AWS_S3_FORCE_PATH_STYLE`-equivalent config when needed.

### D2. Inbound verification
The dummy credentials are per session: `AKIALOCKSMITH<lease-hash>` plus a random secret known to the
daemon. The relay verifies the inbound SigV4 with that secret. Requests from outside the session
cannot produce a valid signature, and replay is bounded by SigV4's 15-minute window plus a nonce
cache.

### D3. Policy evaluation
Map each request to `(service, action, resource)` using the botocore service models, which are
vendored as a compressed JSON table. Unknown actions are denied by default. The policy language
reuses IAM-style globbing so users can copy the patterns into real IAM.

### D4. Streaming payloads
S3 `UNSIGNED-PAYLOAD` and `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` chunked uploads are re-signed
chunk by chunk. That is the hardest part. If it is not done in M7, multipart uploads fall back to
contained STS with a clear message.

### D5. Implementation notes (as built)
- **No AWS SDK crates.** SigV4 (`ls-proxy::aws::sigv4`) and STS/IAM calls (`aws::sts`) use
  `ring` and `ureq`, synchronous like the other relays. The signer passes all 38 header-signing
  cases of AWS's v4 test suite and the documented S3 streaming example.
- **Dummy credentials (D2).** `smith run --aws <profile>` mints `AKIALOCKSMITH` + 7 random
  chars and a random 40-char secret per run, bound to {lease, project, env, profile, policy}, in
  daemon memory only. Every request also passes the peer-to-PID check (every owner of the client
  socket in that lease, scope `aws`), and a 100k-entry signature replay cache. Revoke prunes the
  keys, so the next request is refused. The child also gets `AWS_ENDPOINT_URL`, the region,
  `AWS_EC2_METADATA_DISABLED=true`, an empty `AWS_SESSION_TOKEN`, and
  `AWS_REQUEST_CHECKSUM_CALCULATION`/`AWS_RESPONSE_CHECKSUM_VALIDATION=when_required` (newer
  SDKs would otherwise send signed trailers).
- **Credentials.** `[aws.profiles.<name>]` = `key` (vault JSON
  `{"access_key_id","secret_access_key","session_token"?}`), `region`, optional `role_arn`,
  `external_id`, `revoke_older_sessions`. With `role_arn`, the relay signs with AssumeRole
  credentials (1 h, cached per lease until 5 minutes before expiry).
- **Model and policy (D3).** A 56 KB table generated from botocore (AWS CLI 2.15.6) covers 16
  services and 1,656 operations (`scripts/gen-aws-model.py`). Unknown operations, ambiguous
  matches and credential-minting STS actions are always denied. The default policy is read-only
  (Get/List/Describe/Head/BatchGet/Query/Scan) minus reads that return secret material
  (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `ecr:GetAuthorizationToken`), which
  need an explicit `allow`.
- **Streaming (D4).** Signed `aws-chunked` uploads are verified chunk by chunk and re-signed.
  Unsigned payloads pass through. Signed trailers are refused with a pointer to
  `smith aws creds --contained`. Hashed bodies are capped at 64 MiB; multipart parts are fine
  (a 200 MB `aws s3 cp` through LocalStack passes).
- **S3 addressing.** Path-style requests from the SDK (endpoint on 127.0.0.1) are sent upstream
  virtual-hosted when the bucket is DNS-compatible.
- **Contained fallback.** `smith aws creds --contained [--profile] -- cmd` requires `role_arn`,
  mints 900-second AssumeRole credentials with the policy as session policy, prints
  `CONTAINED_NOTICE`, and redacts the secret and token in output.
  `revoke_older_sessions = true` makes `smith revoke` attach `LocksmithRevokeOlderSessions`
  (deny all for `aws:TokenIssueTime` before now) to the role, in the background, audited.
- **Not done.** Presigned URLs, signed streaming trailers, real-account tests (2.1/2.2 manual),
  live A2 with Claude. CopyObject checks only `s3:PutObject` on the destination.

## Risks / Trade-offs
- Some tools hardcode endpoints (old SDKs, Terraform providers before endpoint support). Those use
  the contained STS fallback.
