# Progress: P2 packaging (append-only)

- 2026-11-20 · planning only: proposal, three spec deltas, design and tasks written by a worker; no code. Open items: tool versions and release dates are pinned in task 1.1 (not verifiable offline when planning); owner gate 7.1 (self-host key custody default); task 5.4 edits a protected workflow file and needs a lead PR; the first real tag, public repo flip and Homebrew tap repository are owner actions (see task 7.3). Platforms: macOS and Linux only (owner decision 2026-11-19).
- 2026-11-20 · worker alfie: group 1 done (1.1-1.4). Research note `docs/research/packaging.md` pins cosign v3.1.4, actions/attest@v4, syft v1.57.2, Helm v4.3.2, kind v0.33.0, kubeconform v0.8.0, caddy 2.11.9, openbao 2.7.2. `ci-tools.sh` now installs cosign, kind, kubeconform, syft with sha256 (Helm omitted: get.helm.sh is 403 via the agent proxy, so `helm-test` must skip with a message here). `tree-check.sh` needed no change (it has no allow-list for infra paths). Findings for the lead, found while researching: (a) nothing serves the web console bundle (apps/web is a Vite SPA); the design is silent, so group 3/4 need a decision; (b) `release.yml` ships bare `smith-<triple>` binaries, not archives, so tasks 5.1/5.2 wording must change; (c) the gateway hard-wires OpenBao transit, so "external key provider" means an external OpenBao only; (d) OIDC issuer/audience/JWKS are public config, not secrets (design decision 7). Next: group 2 (Dockerfiles).
- 2026-11-20 · worker alfie: section 2 done (Dockerfiles for control plane and gateway, .dockerignore, just images, scripts/image-check.sh). Both images are non-root, rustls only (no apt), healthy against a throwaway Postgres. Sandbox note: docker build here needs IMAGE_BUILD_ARGS='--network host --secret id=cabundle,src=/root/.ccr/ca-bundle.crt --build-arg HTTPS_PROXY=...'. Next: section 3 (compose self-host).

## 2026-11-20 worker
- Task: p2-packaging - blocked (PR #534 has groups 2-8 unchecked; merge-ready failed "unchecked tasks"; auto-merge disabled)
- Verified: gh api statuses on a4c2ba0 -> merge-ready error, review job failed at tasks check
- Notes for next session: continue groups 2-8 on this branch, then re-enable auto-merge. A stray branch claude/planning-p2-packaging was pushed by mistake (same commit); ignore it.

## 2026-11-20 worker
- Task: p2-packaging 2.1-2.4 - done
- Verified: just images, bash scripts/image-check.sh (8 OK), just ci -> green; evaluator PASS
- Notes for next session: section 3 (compose self-host) next. In this VM docker build needs IMAGE_BUILD_ARGS='--network host --secret id=cabundle,src=/root/.ccr/ca-bundle.crt --build-arg HTTPS_PROXY=$HTTPS_PROXY'. Re-enable auto-merge (gh pr merge 534 --auto --merge) only when all tasks ticked.

## 2026-11-20 worker (wake-up: merge review finished on #534)
- Task: none started. The review ran on 0d3e6b7 and failed at the completeness check (unchecked tasks in tasks.md, groups 3-8), so there is no verdict. Auto-merge is off again (a disable/enable retry fails the same way).
- Note: the PR comment calling #534 "planning-only" is stale; it carries groups 1-2 code. Only claude/planning-* branches are exempt from the check.
- Next session: section 3 (compose self-host), and re-enable auto-merge only when every task is ticked.

## 2026-11-20 worker (section 3)
- Task: p2-packaging 3.1-3.7 - implemented (compose self-host, bootstrap.sh, selfhost-smoke, bootstrap test); evaluator PASS
- Deviation: task 3.1 and design decision 6 say OpenBao "file storage", but OpenBao 2.7.2 has no `file` backend ("unknown storage type file"). The bundle uses single-node integrated raft storage on the `openbao-data` volume (mounted at /openbao/file). tasks.md and design.md text left as written; lead or owner can reconcile the wording, and the task 1.1 research note should list the finding.
- Verified: selfhost-bootstrap.test.sh, selfhost-smoke.sh (passed 4 times in the sandbox), shellcheck clean. Not verified: --external-keys against a real OpenBao, the tls (Caddy) and demo-oidc profiles beyond `docker compose config`, offline start.
- Notes for next session: section 4 (Helm chart; helm binary is unavailable here, get.helm.sh is 403). PR #534 still has unticked tasks, keep auto-merge off until all are ticked.

## 2026-11-20 worker
- Task: p2-packaging 3.1-3.7 - done (ticked after evaluator PASS and green just ci)
- Verified: just ci -> exit 0; selfhost-bootstrap.test.sh and selfhost-smoke.sh pass
- Notes for next session: section 4 (Helm) next; helm is unavailable here (get.helm.sh 403), so helm-test must skip with a message. Keep auto-merge off until all tasks are ticked.
