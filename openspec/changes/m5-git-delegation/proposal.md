# Proposal: M5 Git Delegation

## Why

Pushing and pulling private repos is the first authenticated operation every coding agent needs.
v5's lineage-checked credential helper can be bypassed with `git credential fill`
(docs/v6-review.md §1.1). It also relied on 60-second tokens that GitHub does not offer (§1.2).
v6 makes sure the agent never holds a Git credential at all.

## What Changes

- A Git smart-HTTP forwarder inside `locksmithd` (crate `ls-proxy`) on a loopback port. It accepts
  plain HTTP from local Git, adds upstream auth, and forwards over TLS to GitHub, GitLab, Bitbucket or
  any configured host.
- `smith git setup [--global|--repo]` writes `url.<forwarder>.insteadOf` rules for HTTPS and SSH
  remote forms, plus a credential helper that hands Git only a session-scoped forwarder token, never
  the upstream credential.
- Upstream credentials: a fine-grained PAT (Free), or a GitHub App installation token minted per
  repository with minimal permissions, cached in the daemon for up to 1 hour (Pro).
- Git policy on push: deny force-push and deletion of protected branches, deny pushes to repos
  outside the session's project allowlist. The rules are read from `.locksmith.toml`.
- `smith gh -- <args>` runs the GitHub CLI with a short-lived installation token injected through
  `smith run` semantics and redaction. It is labelled "contained" (token visible to `gh`'s process
  only).
- Doctor checks: `git.forwarder`, `git.insteadof`, `git.upstream_auth`.

## Usable outcome

Inside `smith session start -- claude`, the agent clones, pulls, pushes and opens PRs on private
repos. No Git token exists anywhere the agent can read, and gate A1 proves it.

## Capabilities

### New Capabilities
- `git-delegation`: Authenticated Git transport and policy without exposing the upstream credential.

### Modified Capabilities

## Out of scope

- SSH agent forwarding of real SSH keys (the backlog has an `ssh-agent` emulation idea).
- Git LFS large-object endpoints. These go through the same forwarder and are tested, but no LFS
  policy is added.

## Impact

`ls-proxy` (hyper, hyper-util, rustls), `ls-broker` (token minting), `smith git|gh` commands.
GitHub App registration for Locksmith Pro (`infra/`).
