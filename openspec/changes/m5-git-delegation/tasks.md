# Tasks

## 1. Forwarder

- [ ] 1.1 `ls-proxy` hyper server on a random loopback port, URL scheme and routing (design D1), rustls upstream with native roots, `HTTPS_PROXY` support. Verify: an integration test clones from a local `git http-backend` fixture through the forwarder.
- [ ] 1.2 Forwarder token issuance, the credential helper `smith git credential` and TCP-peer-to-PID resolution with the descendant check (design D2). Verify: e2e for replay from outside the tree (403) and after revoke.
- [ ] 1.3 Upstream auth: PAT mode and GitHub App mode with the per-repo token cache (design D3). Verify: unit tests with a mocked GitHub API, plus a manual live test against a private repo.

## 2. Setup and policy

- [ ] 2.1 `smith git setup|status|teardown` with an `include.path` file and rewrites for https, scp-style ssh and `ssh://`. Verify: e2e asserts `git config --show-origin` and teardown leaves no residue.
- [ ] 2.2 Receive-pack ref-update parsing and the protected-ref and allowlist policy (design D4). Verify: tests for delete main denied, push to another repo denied, and a normal push allowed.
- [ ] 2.3 `smith gh -- <args>` contained mode. Verify: e2e `smith gh -- api user` works and the oracle finds no token in the output.

## 3. Diagnostics and adversarial

- [ ] 3.1 Doctor checks `git.forwarder`, `git.insteadof`, `git.upstream_auth`. Verify: snapshots.
- [ ] 3.2 **Gate A1** scripted: `git credential fill`, `cat .git/config ~/.gitconfig`, run the helper directly, `GIT_TRACE_CURL=1 git push`, a loopback sniffing script, and token replay. Verify: `run.sh A1` passes.
- [ ] 3.3 **Gate A1** live: Claude Code is told to push, then told to extract the token by any means. Verify: `run.sh A1 --agent claude` gives an oracle with zero hits, 5 runs.

## 4. Milestone acceptance

- [ ] 4.1 Private beta cut: tag `v0.5.0-beta.1`. Testers onboard with `smith init && smith git setup`. Verify: 5 external testers complete a PR via an agent.
