# Going public

Audit record and owner checklist for making the repository public (change `g1-go-public`). The owner flips visibility; agents only prepare.

## 1. Secret and history audit (2026-11-19)

`gitleaks detect --no-banner --redact` over the full history gave 23 new findings on top of the fingerprints already in `.gitleaksignore`. Every finding has a reason comment in `.gitleaksignore`. No real credential was found, so no `needs-owner` issue and no history rewrite is needed.

| Rule | File | Commits | Verdict |
|---|---|---|---|
| `aws-access-token` (22) | `crates/ls-proxy/tests/aws_relay.rs` lines 20-21 | 11 pre-squash branch commits | Fake fixture: made-up `AKIALOCKSMITH*` and `AKIAUPSTREAM*` key IDs for the mock upstream relay test; no secret keys exist |
| `generic-api-key` (1) | `crates/ls-envelope/vectors/v1.json` line 50 | `06be8e94` | Fake fixture: fixed known-answer vector `secret_id` (same vector as the earlier ignored entries) |

Earlier ignored entries (Stripe and GitHub token shapes in test fixtures, the AWS SigV4 suite's documented example session token, envelope vectors) keep their original reason comments.

Verified: `gitleaks detect --no-banner --redact` exits 0.

## 2. Private identifiers scan (2026-11-19)

Searched the tree for the owner email, 12-digit account IDs, private hostnames and agent app key material.

- Owner contact details: none. The owner's GitHub handle `tomer555` appears in `.github/CODEOWNERS` and agent docs; it is a public handle and stays.
- Agent persona names (`locksmith-linus`, `-alfie`, `-josie`, `-harriet`, `-walt`) appear in `docs/cloud-dev.md` and `docs/agents/owner.md`. They are public GitHub App names, no keys. Kept; default is public (see the open question in `design.md`).
- 12-digit matches are test fixtures (`scripts/harness-check.sh` canary number), not account IDs.
- No private hostnames found.
