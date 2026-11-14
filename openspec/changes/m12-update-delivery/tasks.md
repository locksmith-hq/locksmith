# Tasks

## 1. Repository and keys

- [ ] 1.1 Root key ceremony with 3 YubiKeys, documented in `docs/security/update-keys.md`, and the initial TUF root committed. Verify: `tuftool` verifies root.json against the 2-of-3 threshold.
- [ ] 1.2 `infra/`: R2 bucket, CDN, KMS keys and IAM bound to the GitHub OIDC `release` environment. Verify: `tofu plan` is clean, and CI can sign with KMS only from the protected environment.
- [ ] 1.3 `release.yml` generates TUF targets (nightly on main, beta on tags), snapshot and timestamp. Add a `timestamp.yml` cron every 6 h. Verify: a fresh client fetches nightly metadata.

## 2. Client

- [ ] 2.1 `ls-update` TUF client via `tough`: channel selection, rollout bucket, policy (patch auto, minor ask), package-manager detection. Verify: tests with the TUF attack suite fixtures (rollback, freeze, mix-and-match, endless data, wrong hash).
- [ ] 2.2 Versioned install layout and atomic symlink swap with 2 versions kept (design D3). Verify: e2e update plus manual rollback.
- [ ] 2.3 Daemon hot-swap and auto-rollback (design D4). Verify: e2e where an intentionally broken build is rolled back within 60 s.
- [ ] 2.4 `min_secure_version` handling with the session warning and `--accept-risk`. Verify: e2e shows export unaffected.
- [ ] 2.5 Tauri updater feed generated from TUF targets. Verify: the desktop app (M14 placeholder build) updates from the feed.

## 3. Operations

- [ ] 3.1 `just promote` and the `promote.yml` health gate (design D5), plus a yank command. Verify: a dry run against a staging bucket.
- [ ] 3.2 Doctor checks `update.channel`, `update.metadata_fresh`, `update.layout`. Verify: snapshots.
- [ ] 3.3 **Gate A9**: run the TUF attack suite against a hostile mirror fixture. Verify: `run.sh A9` passes.
