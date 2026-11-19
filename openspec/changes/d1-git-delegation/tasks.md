# Tasks: D1 Git delegation

## 1. Contract [sonnet]
- [x] 1.1 Add the `/git/{host}/{owner}/{repo}/...` route description to the gateway OpenAPI (if any) and a `GitBinding` shape (host, repo prefix, allowed services) with fixture data and docs in design.md.
- [x] 1.2 Verify: `cargo nextest run -p ls-gateway git_binding` passes.

## 2. Streaming route [sonnet]
- [x] 2.1 `services/gateway/src/git.rs`: path allow-list (info/refs, upload-pack, receive-pack), service-to-grant mapping, binding and egress check before any decrypt.
- [x] 2.2 Stream request and response bodies to the upstream with the injected credential (PAT first); never follow redirects; bounded timeouts.
- [x] 2.3 App installation token support reusing `ls-proxy::github`.
- [x] 2.4 Verify: `cargo nextest run -p ls-gateway git` against a `git http-backend` fixture: clone, push, unbound repo 403, fetch-only grant cannot push, redirect not followed.

## 3. Redaction and audit [sonnet]
- [ ] 3.1 Redact the credential in upstream headers and text error bodies; ledger events `git.fetch`, `git.push` and denials without credential or pack data.
- [ ] 3.2 Add a Git case to the adversarial gateway suite (`tests/adversarial/gateway/`) for the error channel and header echo.
- [ ] 3.3 Verify: `cargo nextest run -p ls-gateway git_redact`, `just leak-scan`, `just audit-verify`.

## 4. Client setup [sonnet]
- [ ] 4.1 `smith git setup --gateway <url>` writes `insteadOf` and the credential helper returning the agent token; `smith doctor` check; `teardown` removes it.
- [ ] 4.2 Console and desktop: show Git bindings (repo, services) on the bindings page in `apps/web` and `apps/desktop` with Vitest tests.
- [ ] 4.3 Verify: `cargo nextest run -p smith-cli git`, `npm test --workspace apps/web`, `just apps-build`.

## 5. Large body check [sonnet]
- [ ] 5.1 A 50 MB push through the gateway with bounded memory asserted in the test.
- [ ] 5.2 Verify: `cargo nextest run -p ls-gateway git_large`.

## 6. Local verification [sonnet]
- [ ] 6.1 `just up`, a `just git-smoke` recipe (clone and push through the gateway to the fixture), `just apps-build`, then `just ci`.
