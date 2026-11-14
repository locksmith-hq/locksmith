# Design: M12 Update Delivery

## Context
M0 shipped minisign-verified self-update from GitHub Releases on the private repo. TUF is the
standard way to cover key compromise, rollback, freeze and mix-and-match attacks, and the `tough`
crate (AWS, used by Bottlerocket) is production-proven in Rust.

## Decisions

### D1. Key custody
| Role | Threshold | Storage | Expiry |
|---|---|---|---|
| root | 2 of 3 | YubiKeys held by 3 people, offline ceremony | 1 year |
| targets | 1 (+ CI 2-person approval) | AWS KMS asymmetric key, `Sign` permission only from the `release` environment with required reviewers | 3 months |
| snapshot | 1 | KMS | 7 days |
| timestamp | 1 | KMS, cron re-sign every 6 h | 1 day |
A minisign key from M0 is kept for one transition release that ships the TUF root, then retired.

### D2. Rollout bucketing
The `install_id` is a random 128-bit value created at install, rotatable, and never sent anywhere
except inside telemetry when opted in. The bucket is computed locally, so the server learns nothing
about who updated.

### D3. Install layout
`~/.local/share/locksmith/versions/<ver>/{smith,locksmithd,locksmith-mcp}` with a `current` symlink
(atomic `rename` of a new symlink). Two versions are kept for rollback. On macOS the app bundle
`Locksmith.app` is swapped with the same pattern inside `~/Applications/Locksmith/`. When installed
by Homebrew or a package manager, the binaries live in the package prefix and the updater only
notifies.

### D4. Hot-swap protocol
1. New version staged and verified.
2. The daemon gets `prepare_update`: it stops issuing leases, waits up to 30 s for in-flight ops,
   tells the hooks and MCP clients "updating, retry in 5 s", and writes state (no secrets).
3. Swap the `current` symlink.
4. `launchctl kickstart -k` / `systemctl --user restart`.
5. The new daemon starts locked. The desktop app or CLI prompts for a single unlock.
6. Health check within 60 s, or roll back the symlink and restart the old version, then report.

### D5. Health-gated promotion
`promote.yml` reads the opt-in telemetry `update.<outcome>` counters and crash rates per version.
It refuses to raise the percent if the rollback rate is above 1% or the crash rate is above 2× the
previous version.

## Risks / Trade-offs
- Opt-in telemetry gives a small health sample. Beta-channel volunteers and internal dogfooding are
  the primary signal.
