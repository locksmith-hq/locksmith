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
- 12-digit matches are test fixtures (`scripts/harness-check.sh` canary number) or placeholders. Two made-up-looking AWS account IDs in `apps/desktop/src/mock.ts` role ARNs were replaced with placeholders (`111122223333`, `444455556666`) to be safe.
- No private hostnames found.

## 3. Owner flip checklist

Only the owner does these, in this order. Agents never change repository, Actions or account settings. Replace `OWNER/REPO` with `locksmith-hq/locksmith`.

1. **Re-check the tree.** On a fresh clone of `main`:
   ```sh
   bash scripts/public-check.sh
   gitleaks detect --no-banner --redact
   ```
   Both must pass. If you want `.claude/` and `docs/agents/` hidden, decide that now (open question in `openspec/changes/g1-go-public/design.md`); the default is to keep them public.
2. **Rotate anything flagged.** The audit (section 1) found only fake fixtures, so nothing needs rotating. If a later scan flags a real value, rotate it at the provider first, then decide on a history rewrite.
3. **Flip visibility:**
   ```sh
   gh repo edit OWNER/REPO --visibility public --accept-visibility-change-consequences
   ```
4. **Re-enable the paused workflows** (owner decision #307: re-enable `ci` once the repo is public):
   ```sh
   gh workflow enable ci -R OWNER/REPO
   gh workflow enable claude-review -R OWNER/REPO
   ```
   `change-sync` stays off until you decide otherwise; `merge-on-green`, `owner-alert` and `wake-agents` stay on. `merge-gate.sh` stops skipping gates 4 and 6 once the workflows are enabled again.
5. **Turn on secret scanning and push protection:**
   ```sh
   gh api -X PATCH repos/OWNER/REPO -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
   ```
6. **Enable private vulnerability reporting** (used by `SECURITY.md`):
   ```sh
   gh api -X PUT repos/OWNER/REPO/private-vulnerability-reporting
   ```
7. **Branch rules.** Branch protection on `main` is off by owner decision (2026-11-16). Revisit with the merge workflow before inviting outside contributors.

### Coverage of owner decision #307
| #307 item | Step |
|---|---|
| `ci` re-enabled once the repo is public | 4 |
| `claude-review` re-enabled with it | 4 |
| `change-sync` stays off, cheap workflows stay on | 4 |
| `merge-gate.sh` skips gates 4/6 only while workflows are disabled | 4 |
| agents run `just ci` locally before pushing | unchanged; `just ci` now includes `public-check` |
