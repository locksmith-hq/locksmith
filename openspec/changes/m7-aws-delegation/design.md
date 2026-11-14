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

## Risks / Trade-offs
- Some tools hardcode endpoints (old SDKs, Terraform providers before endpoint support). Those use
  the contained STS fallback.
