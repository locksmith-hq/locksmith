# Tasks: P2 packaging

## 1. Research and layout [sonnet]
- [x] 1.1 [haiku] Research spike: write `docs/research/packaging.md` with source URLs and dates for cosign keyless (identity and verify flags), `actions/attest-build-provenance`, SBOM tool choice (syft or cargo-cyclonedx), Helm, kind, kubeconform, Caddy and the production OpenBao image; for each record the pinned version and last release date; record whether cargo-dist can emit our `manifest.json` layout (decision 2) and whether the gateway supports a key provider other than OpenBao transit.
- [x] 1.2 [haiku] Read `services/control-plane/src/config.rs` and the gateway config; list in the research note every environment variable each service needs, its default, which are secrets (names only), and how the web console bundle is served. Update `design.md` Context only through the next task if an assumption was wrong, never by rewriting decisions.
- [x] 1.3 Teach `scripts/tree-check.sh` the new paths (`infra/docker`, `infra/compose/selfhost`, `infra/helm/locksmith`) and add pinned versions of the new CI tools to `scripts/ci-tools.sh`.
- [x] 1.4 Verify: `bash scripts/tree-check.sh` and `bash scripts/ci-tools.sh --check` (or the script's documented dry mode).

## 2. Container images [sonnet]
- [x] 2.1 `infra/docker/control-plane.Dockerfile`: multi-stage `cargo build --release --locked -p <control-plane package>`, minimal runtime base, non-root user, health check, AGPL licence text and source link in the image, no shell secrets.
- [x] 2.2 `infra/docker/gateway.Dockerfile` likewise, plus a `.dockerignore` that excludes `.env`, `target/` and `.git`.
- [x] 2.3 `just images` recipe building both for the host architecture with `docker build`; `scripts/image-check.sh` asserts non-root user, no `dev-only` string in any layer, and a started container answers its health endpoint.
- [x] 2.4 Verify: `just images && bash scripts/image-check.sh`.

## 3. Compose self-host [sonnet]
- [x] 3.1 `infra/compose/selfhost/compose.yaml`: Postgres 18, OpenBao production mode with file storage, control plane, gateway; healthchecks, `depends_on` conditions, localhost-only published ports, no fixed tokens, restart policy, named volumes.
- [x] 3.2 `infra/compose/selfhost/bootstrap.sh`: generate secrets with a secure generator into `.env` (mode 0600, kept if present), initialize OpenBao once and store its unseal material in a separate root-only volume, refuse known dev-only values, print no secret value. Shellcheck clean.
- [x] 3.3 `just selfhost-up` (bootstrap then `docker compose up --wait`) and `just selfhost-down`; a `--external-keys` option that skips the bundled OpenBao and reads the address and credential reference from `.env`.
- [x] 3.4 Optional profiles: `tls` (Caddy) and `demo-oidc` (the existing Keycloak realm, labelled not for production); accept any OIDC issuer URL by variable.
- [x] 3.5 `scripts/selfhost-smoke.sh` (`just selfhost-smoke`): fresh up, API health, one request through the gateway to a throwaway upstream container, restart and check data and keys persist, then check secrets-file mode, difference between two fresh runs and absence of secrets in `docker compose logs`.
- [x] 3.6 Tests for the refusal path and idempotence of `bootstrap.sh` (`scripts/selfhost-bootstrap.test.sh`, no Docker needed for the secret and refusal checks).
- [x] 3.7 Verify: `bash scripts/selfhost-bootstrap.test.sh` then `just selfhost-smoke`.

## 4. Helm chart [sonnet]
- [x] 4.1 `infra/helm/locksmith` scaffold: `Chart.yaml`, `values.yaml` (image digests, replicas, resources, `existingSecret` names for Postgres DSN, OIDC and key provider), Deployments, Services, optional Ingress.
- [x] 4.2 Migration Job (hook) and NetworkPolicy; pod security context non-root, read-only root filesystem, dropped capabilities, no service-account token unless needed.
- [x] 4.3 `values.schema.json` that rejects any literal password or token field and requires the secret reference names; unit tests with good and bad values files.
- [ ] 4.4 `scripts/helm-test.sh` (`just helm-test`): `helm lint`, `helm template | kubeconform`, then on a kind cluster install with prerequisite Secrets created from generated values, wait for ready pods and the migration Job, run the same smoke request as compose, and print pod status and events on failure. The script skips with a clear message (not a pass) when Docker or kind is absent.
- [ ] 4.5 Verify: `just helm-test`.

## 5. Release pipeline [sonnet]
- [x] 5.1 Extend `scripts/make-manifest.sh` and its test: require all four macOS and Linux archives, list names and SHA-256, reject unsafe names; also emit the SBOM and image digest list into the release directory.
- [ ] 5.2 `scripts/verify-release.sh <dir>`: minisign check against `crates/ls-update/update-pubkey.txt`, SHA-256 of each asset against the manifest, cosign verify with the expected workflow identity, SBOM present and parseable; one result line per asset, non-zero on any failure. Test with a planted tampered byte (`scripts/verify-release.test.sh`, using a locally generated throwaway minisign key and cosign test identity, nothing committed).
- [ ] 5.3 `scripts/gen-formula.sh <dir>`: Homebrew formula from the manifest (URLs and SHA-256 only) with a test that every entry matches the manifest.
- [ ] 5.4 Update `.github/workflows/release.yml`: `workflow_dispatch` input `dry_run`, buildx multi-arch image build and push (skipped in dry run), cosign keyless signing with `id-token: write` on the signing job only, build provenance attestation, SBOM, formula artifact, `verify-release.sh` as a final required step, slug `locksmith-hq/locksmith`. The signing key stays the `MINISIGN_SECRET_KEY` secret referenced by name. (Workflow files are protected: this task is a lead PR the owner merges.)
- [x] 5.5 Change the release slug in `crates/ls-update` (`DEFAULT_SOURCE`) and its tests; no behaviour change to signature or hash verification.
- [ ] 5.6 Verify: `bash scripts/verify-release.test.sh`, `cargo nextest run -p ls-update`, `actionlint .github/workflows/release.yml`, then `just release-dry-run` (a documented local run of the same scripts against a one-triple build).

## 6. smith installers [sonnet]
- [ ] 6.1 Rewrite `scripts/install.sh`: public release source via plain HTTPS (`curl`), no `gh`, platform detection for macOS and Linux (arm64, x86_64), `--version` and `--dir` options, minisign verification and SHA-256 before install, and a clear stop (never a silent skip) when no verifier is available; install only the binary.
- [ ] 6.2 `scripts/install.test.sh` (`just installer-test`): serve a local test release directory, cover good install, bad signature, bad hash, missing verifier, unsupported platform, and assert the installer reads no credential file and prints no environment values.
- [ ] 6.3 [haiku] Add `docs/testing.md` rows and `justfile` recipes for `images`, `selfhost-smoke`, `helm-test`, `release-verify` and `installer-test`, as the recipe check requires.
- [ ] 6.4 Verify: `just installer-test` and `bash scripts/test-recipes-check.sh`.

## 7. Docs and owner gate [haiku]
- [ ] 7.1 Gate: confirm `openspec/decisions.md` records the owner's approval of the self-host key custody default (bundled production-mode OpenBao labelled containment, external provider option). Otherwise stop applying the tasks below and report to the lead; tasks 1 to 6 do not depend on it.
- [ ] 7.2 `apps/docs` and `docs/`: self-host guide for compose and Helm (prerequisites, one command, what is generated, backup of the secrets file and the OpenBao volume, upgrade, external keys), with the key custody label stated as containment.
- [ ] 7.3 `apps/docs`: install and verify guide (`install.sh`, Homebrew, `minisign`, `cosign verify`, `gh attestation verify`) and a first-release checklist for the owner (public repo, tag, tap repository, secret names).
- [ ] 7.4 Verify: `npm run build` for `apps/docs` and `bash scripts/public-check.sh` (links and denylist).

## 8. Local verification [sonnet]
- [ ] 8.1 `just up`, then `just selfhost-smoke`, `just helm-test`, `just release-dry-run`, `just release-verify` on its output and `just installer-test`; run `just leak-scan` over the images, logs and the dry-run directory.
- [ ] 8.2 `just apps-build`, then `just ci`.
- [ ] 8.3 Last change of its phase check: if no other Phase 4 row (P3, P4) remains unarchived when this lands, run the manual `ci-platforms` workflow (macOS and Linux) and record the result in `progress.md`.
