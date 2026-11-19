# Tasks: G1 go public

## 1. Secret and history audit [opus]
- [x] 1.1 Triage all `gitleaks detect` findings: for each, record file, commit, rule and verdict (fake fixture, revoked, real) in `docs/going-public.md`; add a reason comment to every `.gitleaksignore` entry. Raise a `needs-owner` issue for any real one (fingerprint only).
- [x] 1.2 Scan the tree for private identifiers (agent app key names, account IDs, private hostnames, owner contact details) and fix or list each in the denylist decision.
- [x] 1.3 Verify: `gitleaks detect --no-banner --redact` over the full history exits 0.

## 2. Licences [sonnet]
- [x] 2.1 Add `LICENSE` (AGPL-3.0) and `LICENSE-APACHE` files, set each manifest's `license`, replace `UNLICENSED`, and write `THIRD_PARTY.md` for vendored data.
- [x] 2.2 Extend `deny.toml` so an AGPL dependency cannot enter an Apache-2.0 crate.
- [x] 2.3 Verify: `cargo deny check licenses` passes and fails on a planted AGPL dependency in a scratch crate.

## 3. Public docs [sonnet]
- [x] 3.1 Rewrite `README.md` (product, security promise with honest protection labels, `just up` quick start, layout, licences); retire the M0–M16 text.
- [x] 3.2 Add `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and expand `SECURITY.md` (private reporting, supported versions, scope).
- [x] 3.3 Verify: every relative link in the root docs resolves (`bash scripts/public-check.sh links`).

## 4. Public check script [sonnet]
- [x] 4.1 Write `scripts/public-check.sh` (licence manifests, root docs and links, denylist, secret canary) with a test script, and wire it into `just ci`.
- [x] 4.2 Verify: `bash scripts/public-check.test.sh` plants a canary, an `UNLICENSED` manifest, a denylisted string and a broken link; each makes the check fail and the real tree passes.

## 5. Owner flip checklist [sonnet]
- [x] 5.1 Write `docs/going-public.md`: ordered owner steps with exact commands (visibility, `gh workflow enable ci` and `claude-review`, secret scanning and push protection, private advisories, branch rules, rotation of flagged values).
- [ ] 5.2 Open a `needs-owner` issue linking the checklist and an Artifact brief, and record the owner's approval line in `openspec/decisions.md` when given.
- [x] 5.3 Verify: `bash scripts/public-check.sh` passes and the checklist covers every item in #307.

## 6. Local verification [sonnet]
- [x] 6.1 Run `just up`, `bash scripts/public-check.sh`, `just apps-build`, then `just ci`.
