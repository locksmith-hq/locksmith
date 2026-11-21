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

## 2026-11-20 20:08 worker
- Task: merge-conflict fix on PR #534 - done
- Verified: just quick -> ok
- Notes for next session: 22 tasks still unticked; docs/testing.md conflict resolved keeping both selfhost and ci lines.

## 2026-11-20 20:16 worker
- Task: p2-packaging CI fix - done (flake)
- Verified: cargo test -p locksmith-audit --test export -> 3 passed locally; CI failure was only locksmith-audit::export incremental_export_writes_each_event_once_and_verifies_offline (1 of 773), branch does not touch audit; main merged in (already up to date)
- Notes for next session: flaky audit export test (docker-backed); the App token cannot re-run jobs (403), so this log push re-triggers CI. If it fails again on the same test, open a needs-rescue.

## 2026-11-20 worker (wake-up: merge review finished on #534)
- Task: p2-packaging - blocked (no task started)
- Verified: merge-ready status error "no review verdict": review run failed at the completeness check (unchecked tasks 4.1-8.3); auto-merge had been re-enabled, disabled again with --disable-auto
- Notes for next session: sections 4-8 remain; helm is unavailable in the VM (get.helm.sh 403) so 4.5 must skip with a message; re-enable auto-merge only when every task is ticked.

## 2026-11-20 worker (section 4)
- Task: p2-packaging 4.1-4.3 - Helm chart (infra/helm/locksmith), values.schema.json with good/bad tests, scripts/helm-test.sh, `just helm-test`; evaluator PASS on attempt 2 (attempt 1 found wrong gateway bind env, gateway egress to control plane blocked, migration enabled without args; all fixed)
- Verified: scripts/helm-schema.test.sh (python jsonschema; helm lint and kubeconform also clean when built via go install), test-recipes-check, tree-check, just quick. Not verified: kind install stage (kind/kubectl absent), so 4.4 and 4.5 stay unticked; the relay smoke request is not implemented (only /readyz).
- Deviations: OIDC issuer/audience/JWKS are plain values (public), not existingSecret; migration hook Job defaults off because the control plane migrates in-process and has no migrate-only mode (good-values uses a placeholder `--migrate-only`).
- Notes for next session: sections 4.4-4.5, 5-8 remain; keep auto-merge off until all ticked. Task 5.4 needs a lead PR (protected workflow).

## 2026-11-21 worker (wake-up: merge review finished on #534)
- Task: p2-packaging - blocked (no task started)
- Verified: merge-ready status = "unchecked tasks" (4.4-8.3 open) and "no review verdict"; auto-merge was enabled again on #534, disabled with --disable-auto (now null)
- Notes for next session: tasks 4.4-8.3 remain; 4.4/4.5 need kind and kubectl (absent in VM), 5.4 needs a lead PR (protected workflow), 7.1 is an owner gate. Re-enable auto-merge only when every task is ticked.

## 2026-11-21 worker (wake-up: merge review finished on #534)
- Task: p2-packaging - blocked (no task started)
- Verified: review run failed at the completeness check ("unchecked tasks", 4.4-8.3 open); auto-merge was on again, disabled with --disable-auto (now null)
- Notes for next session: next takeable tasks are 5.1-5.3, 5.5, 6.x (no kind/helm needed); 4.4/4.5 need kind (absent), 5.4 needs a lead PR, 7.1 is an owner gate. Whoever re-enables auto-merge on #534 early causes this loop: only enable when every task is ticked.

## 2026-11-21 worker (wake-up: merge review finished on #534)
- Task: p2-packaging 5.1, 5.5 - done; auto-merge on #534 disabled (review failed only on unchecked tasks); evaluator PASS
- Verified: scripts/make-manifest.test.sh, cargo test -p ls-update, just quick
- Notes for next session: 5.2 (verify-release.sh), 5.3 (gen-formula.sh), 6.x next; 4.4/4.5 need kind (absent), 5.4 needs a lead PR, 7.1 is an owner gate. release.yml does not pass --sbom/--images yet (task 5.4). Keep auto-merge off until every task is ticked.

## 2026-11-21 worker (wake-up: merge review finished on #534)
- Task: p2-packaging 5.2, 5.3 - done (auto-merge on #534 had been enabled again; disabled, review had failed only on unchecked tasks and CODEOWNERS path crates/ls-update)
- Verified: `just release-verify` (make-manifest, verify-release with throwaway minisign key and stub cosign incl. tampered asset/manifest/key/identity, gen-formula tests), test-recipes-check
- Notes for next session: cosign is not in the VM, so the cosign check is tested with a stub; real identity check runs in release.yml (task 5.4, lead PR). Next: 6.1-6.4. PR touches /crates/ls-update/ (CODEOWNERS): the owner's approval is required to merge. Keep auto-merge off until every task is ticked.

## 2026-11-21 worker (wake-up: merge review finished on #534)
- Task: p2-packaging 6.1-6.4 - done, evaluator PASS (sonnet); auto-merge on #534 stays off (tasks 4.4, 4.5, 5.4, 5.6, 7.x, 8.x open)
- Verified: `just installer-test` (good, --version, bad signature, bad hash, missing minisign, unsupported platform, canary credentials never printed), test-recipes-check, just quick
- Notes for next session: 7.1 is an owner gate; 4.4/4.5 need kind, 5.4 needs a lead PR, 5.6 needs cosign/actionlint. #534 hygiene check failed once on the PR (log blocked by proxy); tree-check, task-guard, public-check and gitleaks pass locally on HEAD, so rerun/likely transient. #534 touches /crates/ls-update/ (CODEOWNERS): owner approval needed.
