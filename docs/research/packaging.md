# P2 packaging research (tasks 1.1 and 1.2)

Retrieved 2026-11-20. Release dates are GitHub `published_at` from `gh api repos/<o>/<r>/releases/latest` unless stated. Names only: no secret values appear here.

## 1.1 Tool versions and decisions

| Tool | Pinned version | Last release | Source | Licence |
|---|---|---|---|---|
| cosign | v3.1.4 | 2026-10-20 | github.com/sigstore/cosign/releases/tag/v3.1.4 | Apache-2.0 |
| actions/attest (used by attest-build-provenance) | v4.2.2 | 2026-08-04 | github.com/actions/attest | MIT |
| actions/attest-build-provenance | v4.2.2 | 2026-08-06 | github.com/actions/attest-build-provenance | MIT |
| syft (chosen SBOM tool) | v1.57.2 | 2026-11-16 | github.com/anchore/syft/releases/tag/v1.57.2 | Apache-2.0 |
| cargo-cyclonedx (rejected) | 0.5.10 | 2026-11-10 | github.com/CycloneDX/cyclonedx-rust-cargo | Apache-2.0 |
| Helm | v4.3.2 | 2026-11-13 | github.com/helm/helm/releases/tag/v4.3.2 | Apache-2.0 |
| kind | v0.33.0 | 2026-08-26 | github.com/kubernetes-sigs/kind/releases/tag/v0.33.0 | Apache-2.0 |
| kubeconform | v0.8.0 | 2026-06-04 | github.com/yannh/kubeconform/releases/tag/v0.8.0 | Apache-2.0 |
| Caddy image `caddy:2.11.9` | v2.11.9 | GitHub 2026-11-05; Docker Hub tag last updated 2026-11-16 | github.com/caddyserver/caddy/releases/tag/v2.11.9; hub.docker.com/_/caddy | Apache-2.0 |
| OpenBao image `openbao/openbao:2.7.2` (recommended) | 2.7.2 | Docker Hub tag last updated 2026-10-26 | hub.docker.com/r/openbao/openbao/tags | MPL-2.0 |
| OpenBao 2.7.3 (newer, not recommended yet) | 2.7.3 | 2026-11-19 (one day old) | github.com/openbao/openbao/releases/tag/v2.7.3 | MPL-2.0 |
| cargo-dist (rejected) | v0.34.0 | 2026-11-02 | github.com/axodotdev/cargo-dist/releases/tag/v0.34.0 | Apache-2.0 |

**Could not verify:**
- `docs.sigstore.dev` and `axodotdev.github.io` do not resolve from this session. Cosign flags come from the cosign README on the default branch (`gh api repos/sigstore/cosign/contents/README.md`), not from the v3.1.4 tag. Re-check against the tag before pinning in CI.
- The cargo-dist book was read from `raw.githubusercontent.com/axodotdev/cargo-dist/main/book/src/reference/config.md`, not from the tag.
- The gh API returns 403 for `axodotdev/cargo-dist` contents in this session.
- The Caddy image exists on Docker Hub (API check above), but no digest was fetched.
- No cosign binary was run in this session. A download-and-run attempt was denied by the sandbox permission check and was not retried.

### cosign keyless (for release.yml signing job)
- Sign a blob: `cosign sign-blob <file> --bundle <file>.sigstore.json --yes` (no `--key`, so keyless).
- Verify a blob: `cosign verify-blob <file> --bundle <file>.sigstore.json --certificate-identity <id> --certificate-oidc-issuer https://token.actions.githubusercontent.com`. A regex form is `--certificate-identity-regexp`; the issuer also has `--certificate-oidc-issuer-regexp`.
- Expected identity for a tag release: `https://github.com/locksmith-hq/locksmith/.github/workflows/release.yml@refs/tags/vX.Y.Z`. A dry run on a branch has `refs/heads/<branch>`, so the dry-run check needs its own identity or the regex form.
- Images: `cosign verify <image> --certificate-identity ... --certificate-oidc-issuer ...`.
- Keyless signing needs `id-token: write` on the signing job only.
- Offline check: a bundle carries the certificate and log inclusion proof, so verification can run offline with the bundle file.

### actions/attest (build provenance)
- `actions/attest-build-provenance` v4 is a wrapper on `actions/attest`, and the upstream page says new implementations should use `actions/attest`. Use `actions/attest@v4` (pinned v4.2.2) in release.yml.
- Required permissions: `id-token: write`, `attestations: write`, `artifact-metadata: write`. Input: `subject-path` (glob or list, up to 1024 subjects).
- Verify: `gh attestation verify <file> --repo locksmith-hq/locksmith` (or `--owner locksmith-hq`; the two are mutually exclusive). Optional pins: `--signer-workflow`, `--signer-repo`, `--predicate-type` (default SLSA v1). Source: `cli/cli` `pkg/cmd/attestation/verify/verify.go` on the default branch.

### SBOM tool: syft (chosen)
- Syft scans directories, archives and container images, and writes CycloneDX JSON. Images are in scope (task 2.x and 5.1), so one tool covers binaries and images.
- cargo-cyclonedx reads only the Cargo dependency graph. It cannot describe an image's OS packages, so it would need a second tool.

### cargo-dist: can it emit our manifest.json? No
- Our `scripts/make-manifest.sh` writes `{"version": ..., "targets": {"<triple>": {"name", "sha256"}}}` and `ls-update` reads that layout.
- cargo-dist writes its own `dist-manifest-schema.json`-described manifest, not our layout.
- Its checksums are per-archive sidecar files (`checksum` option: `sha256` default, or `sha512`, `blake2b` and others). There is no whole-release manifest.
- Its signing options are Windows Authenticode only (`ssldotcom-windows-sign`, `azure-windows-sign`). Minisign is not mentioned.
- `extra-artifacts` adds files but does not change the manifest.
- Adopting it would also regenerate `release.yml`. Decision 2 stands: extend the existing workflow.

### Helm, kind, kubeconform
- Helm v4 is a major version. Pin v4.3.2 explicitly and confirm the chart renders under v4 in task 4.5.
- kind v0.33.0 needs Docker. kubeconform v0.8.0 validates rendered manifests (`helm template | kubeconform`).

### OpenBao image
- Use Docker Hub `openbao/openbao:2.7.2`, the same tag as the dev compose. Its tag was last updated 2026-10-26.
- 2.7.3 (2026-11-19) is one day old. Wait a few weeks, or pin by digest after review.
- ghcr.io is not used (docs/cloud-dev.md records a 403).

### Gateway key provider
- Not configurable today. `services/gateway/src/config.rs` has only the `OPENBAO_*` variables and an `OpenBaoConfig` struct.
- `services/gateway/src/main.rs:79` builds `OpenBaoTransit::new(...)` directly.
- A seam exists in code: `Unwrapper` (`services/gateway/src/decrypt.rs:75`) is a trait object, and `ls-envelope`'s `KeyWrapper` is implemented by `OpenBaoTransit`. A second provider needs a new impl, a config variant and main.rs wiring. The control plane has the same shape (`DekWrapper` trait, `kms::openbao` constructor).

## 1.2 Environment variables

### control plane (binary `locksmith-api`, `services/control-plane/src/config.rs`)

| Variable | Required | Default | Secret |
|---|---|---|---|
| `DATABASE_URL` | yes | none (app role, contains a password) | yes |
| `DATABASE_OWNER_URL` | yes | none (migration role, contains a password) | yes |
| `LOCKSMITH_BIND` | no | `127.0.0.1:8080` | no |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | off | no |
| `LOCKSMITH_DEV_AUTH` | no | off; `1` refused in release builds unless `LOCKSMITH_ALLOW_DEV_AUTH=1`, and only on loopback | no |
| `OPENBAO_ADDR` | no (enables KMS) | unset: secret-version writes return 503 | no |
| `OPENBAO_CONTROL_PLANE_TOKEN` | yes if `OPENBAO_ADDR` set | none | yes |
| `OPENBAO_TRANSIT_KEY` | no | `gateway` | no |
| `OPENBAO_TRANSIT_KEY_VERSION` | no | `1` | no |
| `OPENBAO_AUDIT_CHECKPOINT_TOKEN` | no (enables checkpoint job) | unset: job off | yes |
| `OPENBAO_AUDIT_CHECKPOINT_KEY` | no | `audit-checkpoint` | no |
| `LOCKSMITH_GATEWAY_SERVICE_TOKEN` | no; unset refuses all `/internal/v1` with 401 | unset; at least 32 bytes, no outer whitespace | yes |
| `LOCKSMITH_AGENT_SIGNING_KEY` | no; unset means 503 on token requests (ephemeral key only with dev auth) | unset; base64 32-byte Ed25519 seed | yes |
| `LOCKSMITH_OIDC_ISSUER` | no; off if unset | unset | no (public) |
| `LOCKSMITH_OIDC_AUDIENCE` | yes if issuer set | none | no (public) |
| `LOCKSMITH_OIDC_JWKS_URL` | yes if issuer set; http or https | none | no (public) |
| `RUST_LOG` | no | `info` (read by tracing `EnvFilter`, not `config.rs`) | no |

### gateway (binary `locksmith-gateway`, `services/gateway/src/config.rs`)

| Variable | Required | Default | Secret |
|---|---|---|---|
| `LOCKSMITH_GATEWAY_BIND` | no | `127.0.0.1:8090` | no |
| `DATABASE_URL` | yes (app role; gateway never migrates) | none | yes |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | off | no |
| `LOCKSMITH_CONTROL_PLANE_URL` | yes; http or https | none | no |
| `LOCKSMITH_GATEWAY_SERVICE_TOKEN` | yes; at least 32 bytes; must equal the control plane's value | none | yes |
| `OPENBAO_ADDR` | yes | none | no |
| `OPENBAO_GATEWAY_TOKEN` | yes; non-empty, no outer whitespace | none | yes |
| `OPENBAO_TRANSIT_KEY` | no | `gateway` | no |
| `LOCKSMITH_GATEWAY_BINDINGS` | yes; path to a TOML file | none | no (file holds org id, origins and secret ids, no values) |

Notes:
- The gateway needs no OIDC variables. Agent tokens are checked against the control plane's JWKS at `LOCKSMITH_CONTROL_PLANE_URL`.
- Secret names, listed once: `DATABASE_URL`, `DATABASE_OWNER_URL`, `OPENBAO_CONTROL_PLANE_TOKEN`, `OPENBAO_AUDIT_CHECKPOINT_TOKEN`, `LOCKSMITH_GATEWAY_SERVICE_TOKEN` (both services), `LOCKSMITH_AGENT_SIGNING_KEY`, `OPENBAO_GATEWAY_TOKEN`.
- Both services log only variable names in config errors (tested).

### Web console bundle
- `apps/web` is a Vite SPA. `npm run build` runs `tsc --noEmit && node build.mjs`, which writes `apps/web/dist/`.
- No service serves it. Neither service has `ServeDir`, a fallback service or a static route. The control plane's CORS is for Tauri origins only.
- The client calls same-origin paths (`apiBase` defaults to `""`).
- `VITE_OIDC_ISSUER` (default `http://localhost:8180/realms/locksmith`) and `VITE_OIDC_CLIENT_ID` (default `locksmith-web`) are baked in at build time.
- Gap: the design does not say how the console is served. Options: the Caddy profile serves `dist/` and proxies `/api` to the control plane, or a static image is added. Decide in task 2 or 3.

## Assumptions in design.md Context that are wrong or incomplete
1. Decision 7 says OIDC needs a Secret reference. OIDC issuer, audience and JWKS URL are public values, not credentials, so they belong in values, not in `existingSecret`.
2. Task 5.1 and 5.2 say "archives", but `release.yml` uploads bare `smith-<triple>` binaries. The manifest and `ls-update` use bare files. Either the task text or the release layout must change; this is a decision for the owner.
3. The web console is not mentioned in design.md. It is an SPA with no server (see above).
4. The gateway has no provider choice. Design Context says "key provider" is configurable; it is OpenBao only (code seam, not a config option).
5. Context lists the services and the dev compose correctly.

## Open items for the lead
- Confirm `actions/attest@v4` in place of `actions/attest-build-provenance` (the task named the wrapper).
- Confirm OpenBao pin 2.7.2 (digest to be recorded in task 2.x).
- Verify cosign flags against the v3.1.4 tag once docs.sigstore.dev is reachable.
