set positional-arguments

ci: fmt lint test-rust test-web tree-check public-check migration-guard

# Fast local check: fmt + lint only for files committed on this branch since `base`.
# The full `just ci` runs in GitHub Actions on every PR.
quick base="origin/main":
    #!/usr/bin/env bash
    set -euo pipefail
    files=$(git diff --name-only --diff-filter=ACMR "$1"...HEAD)
    [ -n "$files" ] || { echo "quick: no committed changes vs $1"; exit 0; }
    rs=$(grep '\.rs$' <<<"$files" || true)
    if [ -n "$rs" ]; then
      rustfmt --check $rs
      # Clippy only the crates that own a changed file (nearest Cargo.toml), in one run so deps build once.
      dirs=$(for f in $rs; do d=$(dirname "$f"); until [ -f "$d/Cargo.toml" ] || [ "$d" = . ]; do d=$(dirname "$d"); done; echo "$d"; done | sort -u)
      pkgs=""
      for d in $dirs; do
        case "$d" in
          apps/desktop/*) cargo clippy --manifest-path "$d/Cargo.toml" --all-targets -- -D warnings ;; # not in the workspace
          .) pkgs="--workspace" ;;
          *) pkgs="$pkgs -p $(sed -n 's/^name *= *"\(.*\)"/\1/p' "$d/Cargo.toml" | head -1)" ;;
        esac
      done
      if [ -n "$pkgs" ]; then cargo clippy $pkgs --all-targets -- -D warnings; fi
    fi
    if grep -qE '\.(tsx?|mjs|js)$|^knip\.json$|^\.oxfmtrc\.json$|^\.oxlintrc\.json$' <<<"$files"; then npx turbo run lint format:check knip typecheck; fi

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    npm run lint

# a0-spikes' rls tests need `just up` (like ls-e2e); its header and lint tests run here.
test-rust:
    cargo nextest run --workspace --exclude ls-e2e -E 'not (package(a0-spikes) & binary(rls))'
    cargo test --workspace --exclude ls-e2e --doc

# Rust tests without Docker or the `just up` stack (macOS ci-platforms); filter in .config/nextest.toml.
test-rust-portable:
    cargo nextest run --workspace --profile portable
    cargo test --workspace --exclude ls-e2e --doc

test-web:
    npm run build && npm test

# Tauri app: not in the root workspace, so fmt/lint/test-rust skip it.
desktop-test:
    cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --check
    cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml

# Build every app for the host OS (web console + desktop binary); each change's Local verification runs it.
apps-build: desktop-test
    npm run build
    cd apps/desktop && npm exec -- tauri build --debug --no-bundle

# Plants a build error in each app and checks apps-build's npm build step fails on it.
apps-build-test:
    scripts/apps-build.test.sh

# Regenerate packages/api-types from crates/ls-ipc (ts-rs).
api-types:
    cargo test -p ls-ipc --features ts export_bindings
    npx --yes oxfmt@0.79.0 -c .oxfmtrc.json packages/api-types/src

tree-check:
    scripts/tree-check.sh


# Public-readiness hygiene: licences, root docs, links, denylist, secret canary.
public-check:
    scripts/public-check.test.sh
    scripts/public-check.sh

# Shipped database migrations must not change (add a new one). Compares against origin/main.
migration-guard:
    scripts/check-migrations.test.sh
    scripts/check-migrations.sh

# Install a git pre-push hook that runs the denylist check (see docs/public-private-boundary.md).
install-hooks:
    printf '#!/usr/bin/env bash\nexec "$(git rev-parse --show-toplevel)/scripts/public-check.sh" denylist\n' > "$(git rev-parse --git-path hooks)/pre-push"
    chmod +x "$(git rev-parse --git-path hooks)/pre-push"

dev app:
    npm run build -w apps/{{app}}

# Build and install Locksmith.app (smith, locksmithd, locksmith-mcp, desktop) locally on macOS.
desktop-install:
    bash scripts/dev-install-desktop.sh

# D1 smoke: clone and push through the gateway's /git route to a real `git http-backend` fixture,
# plus the smith-cli `git setup` checks. Self-contained (no `just up` needed).
git-smoke:
    cargo nextest run -p ls-gateway git_clone_and_push_through_gateway git_fetch_only_grant_cannot_push
    cargo nextest run -p smith-cli git

# Local dev harness (infra/compose): Postgres, Grafana LGTM, OpenBao, WireMock.
# Dev values come from infra/compose/.env.example. Export OPENBAO_IMAGE etc. in the shell to override.
compose := "docker compose -f infra/compose/compose.yaml --env-file infra/compose/.env.example"

# `up` also writes the audit checkpoint public key to the verifier config (S5 task 4.1).
# Includes the Keycloak issuer and mail catcher (compose profile `auth`, T1); `up-lite` skips them.
up:
    {{compose}} --profile auth up -d --wait
    bash scripts/audit-verifier-config.sh

up-lite:
    {{compose}} up -d --wait
    bash scripts/audit-verifier-config.sh

down:
    {{compose}} --profile auth down

reset:
    {{compose}} --profile auth down -v

logs svc:
    {{compose}} --profile auth logs --tail=200 {{svc}}

psql *args:
    {{compose}} exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"' -- "$@"

ps:
    {{compose}} --profile auth ps

# Verify the running stack (needs `just up`).
harness-check:
    bash scripts/harness-check.sh

# Start each MCP server in .mcp.json and make one read call (needs `just up`).
mcp-check:
    bash scripts/mcp-check.sh

# Canaries (fake secrets for leak tests) live in gitignored infra/compose/.canaries (mode 0600).
# `just canary new` mints one and prints its id; `just canary list` prints ids, never values.
# LOCKSMITH_CANARIES overrides the file.
canary action:
    #!/usr/bin/env bash
    set -euo pipefail
    case "$1" in new|list) ;; *) echo "usage: just canary new|list" >&2; exit 2 ;; esac
    exec python3 -I tests/kit/oracle.py "canary-$1" --file "${LOCKSMITH_CANARIES:-infra/compose/.canaries}"

# Scan Postgres, Loki and Tempo (needs `just up`), plus any --dir/--transcript, for every active
# canary. Prints `LEAK <encoding> <source>:<where>` (never a value) and exits non-zero on a hit or
# SOURCE-UNREACHABLE. Usage: just leak-scan [--explain] [--dir P] [--transcript P]
leak-scan *args:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    eval "$(grep -E '^POSTGRES_(USER|PASSWORD|DB)=' "$root/infra/compose/.env.example")"
    export PGHOST=127.0.0.1 PGPORT=5432 PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD" PGDATABASE="$POSTGRES_DB"
    canaries="${LOCKSMITH_CANARIES:-$root/infra/compose/.canaries}"
    cd {{quote(invocation_directory())}}
    exec python3 -I "$root/tests/kit/oracle.py" scan --canary-file "$canaries" --stack "$@"

# S5 audit ledger CLI against `just up`, as the `audit_verifier` role. The export directory is
# LOCKSMITH_AUDIT_EXPORT_DIR (default infra/compose/.audit-export, gitignored); extra args (e.g.
# --json) go to locksmith-audit.
audit-export *args:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    eval "$(grep -E '^(POSTGRES_DB|LOCKSMITH_AUDIT_VERIFIER_PASSWORD)=' "$root/infra/compose/.env.example")"
    export LOCKSMITH_AUDIT_DATABASE_URL="postgres://audit_verifier:${LOCKSMITH_AUDIT_VERIFIER_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
    dir="${LOCKSMITH_AUDIT_EXPORT_DIR:-$root/infra/compose/.audit-export}"
    cd "$root" && exec cargo run -q -p locksmith-audit -- export --dir "$dir" "$@"

# Verify every org's chain and checkpoints in the database. When an export exists, also trust its
# signed checkpoints (`--checkpoints-from`, so a rewrite or truncation shows even after the
# `audit_checkpoints` rows are deleted) and verify the export itself offline (`--dir`).
audit-verify *args:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    eval "$(grep -E '^(POSTGRES_DB|LOCKSMITH_AUDIT_VERIFIER_PASSWORD)=' "$root/infra/compose/.env.example")"
    export LOCKSMITH_AUDIT_DATABASE_URL="postgres://audit_verifier:${LOCKSMITH_AUDIT_VERIFIER_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
    dir="${LOCKSMITH_AUDIT_EXPORT_DIR:-$root/infra/compose/.audit-export}"
    cd "$root"
    bin="cargo run -q -p locksmith-audit --"
    if [ ! -d "$dir" ]; then
      echo "audit-verify: no export at $dir, so the database is checked against its own checkpoint rows only (run just audit-export)" >&2
      exec $bin verify --db "$@"
    fi
    rc=0
    $bin verify --db --checkpoints-from "$dir" "$@" || rc=$?
    $bin verify --dir "$dir" "$@" || { c=$?; [ "$rc" -ge "$c" ] || rc=$c; }
    exit "$rc"

# The audit tamper test (needs `just up`): in a scratch database on the compose Postgres, tamper as
# locksmith_owner (edit a field, delete a row, swap seqs, truncate past a checkpoint, edit exported
# lines, rewrite history and delete the checkpoint rows) and check each fails verify while the
# untouched ledger passes. `just ci` runs the same test against a throwaway container.
audit-tamper-test:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    eval "$(grep -E '^POSTGRES_(USER|PASSWORD)=' "$root/infra/compose/.env.example")"
    export LOCKSMITH_AUDIT_TEST_ADMIN_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/postgres"
    cd "$root" && exec cargo nextest run -p locksmith-audit --test tamper

# S5 audit smoke (needs `just up` and `just api`): an agent relays a canary through `smith`, oha
# drives 200 relays/s when installed (prints relay and append p99), a signed checkpoint covers the
# head, then export, `audit-verify` (--db and --dir) and `leak-scan` over the stack and the export.
audit-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    cd "$root"
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo build -q -p smith-cli --bin smith
    cargo build -q -p locksmith-audit
    AUDIT_SMOKE_LOAD="${AUDIT_SMOKE_LOAD:-1}" cargo nextest run -p ls-e2e --test audit --no-capture
    dir="${LOCKSMITH_AUDIT_EXPORT_DIR:-$root/infra/compose/.audit-export}"
    just audit-export
    just audit-verify
    just leak-scan --explain --require-coverage --dir "$dir"

# Run locksmith-api against `just up`: dev auth on, loopback bind, OTLP to the LGTM container.
api:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    set -a; . "$root/infra/compose/.env.example"; set +a
    export LOCKSMITH_DEV_AUTH=1 LOCKSMITH_ALLOW_DEV_AUTH=1 LOCKSMITH_BIND=127.0.0.1:8080 LOCKSMITH_MCP_RESOURCE_URL=http://127.0.0.1:8080/mcp OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
    cd "$root" && exec cargo run -q -p ls-control-plane --bin locksmith-api

# B4 API contract suite: `just api-contract <url>` records a normalised transcript under target/api-contract/;
# `just api-contract --diff <url-a> <url-b>` compares two servers (needs `just up` and `just api`).
api-contract *args:
    bash scripts/api-contract.sh {{args}}

# T3 console e2e: Playwright drives the web console against `just up` (auth profile) and `just api`.
# Set PW_CHROMIUM to a Chromium binary when the Playwright browsers are not installed.
web-e2e *args:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
      just up
      (just api >/tmp/locksmith-api.log 2>&1 &)
      for _ in $(seq 1 360); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 2; done
      curl -fsS http://127.0.0.1:8080/healthz >/dev/null || { echo "api did not start; see /tmp/locksmith-api.log" >&2; exit 1; }
    fi
    cd apps/web && npx playwright test --trace off "$@"

# T1 sign-up, verify, sign-in (auth code + PKCE), reset and API calls against Keycloak (needs `just up` and `just api`).
auth-e2e:
    python3 -I scripts/auth-e2e.py

# M1 hub MCP sign-in: a scripted MCP client signs in on Keycloak (consent, PKCE, resource) and lists tools (needs `just up` and `just api`).
mcp-e2e:
    python3 -I scripts/mcp-e2e.py

# Run locksmith-gateway against `just up` and `just api`. Needs LOCKSMITH_GATEWAY_BINDINGS (a TOML
# file naming the org and bindings; see tests/e2e/tests/relay.rs for the shape). The gateway connects
# as locksmith_app until the locksmith_gateway role lands (S3 progress notes).
gateway:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    set -a; . "$root/infra/compose/.env.example"; set +a
    : "${LOCKSMITH_GATEWAY_BINDINGS:?set LOCKSMITH_GATEWAY_BINDINGS to a bindings TOML file}"
    export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
    cd "$root" && exec cargo run -q -p ls-gateway --bin locksmith-gateway

# S3 relay smoke test (needs `just up` and `just api`): the test starts its own gateway, relays a
# canary secret to the WireMock upstream and checks nothing leaks back. Run `just leak-scan` after.
relay-smoke:
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo nextest run -p ls-e2e --test relay

# S4 connector smoke test (needs `just up` and `just api`): registers an agent, grants a canary
# secret and relays to the WireMock upstream through `smith` and the MCP tools; asserts the upstream
# saw the secret and the agent did not. Run `just leak-scan` after.
connector-smoke:
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo build -q -p smith-cli --bin smith
    cargo build -q -p locksmith-mcp
    cargo nextest run -p ls-e2e --test connector

# D3 Postgres relay smoke test (needs `just up`, `just api` and psql): the test starts its own
# gateway with a pg listener, creates a SCRAM role on the compose Postgres and runs real `psql`
# through `smith db connect --gateway`; asserts the result and that no file holds the agent token or
# the database password. Run `just leak-scan` after.
db-smoke:
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo build -q -p smith-cli --bin smith
    cargo nextest run -p ls-e2e --test db_relay

# D2 AWS vend smoke (P1 owns `aws-smoke`, the real-AWS session smoke; this one is local on Floci; needs `just up` for Floci and `just api`; `pip install awscli`): the real `aws` CLI
# gets scoped, short-lived STS credentials from the gateway through `smith aws setup` and
# `credential_process`; asserts the assumed-role identity, expiry and that the agent HOME holds no
# key. Skips with a note without `aws` or Floci unless E2E_REQUIRE_AWS is set. Run `just leak-scan` after.
aws-vend-smoke:
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo build -q -p smith-cli --bin smith
    cargo nextest run -p ls-e2e --test aws_smoke --no-capture

# D4 workload-identity smoke (needs `just up` and `just workload-smoke-api`): an in-process
# GitHub-shaped OIDC stub issuer (TLS on loopback) and runner endpoint; `smith login --workload
# github` exchanges its token, relays to the WireMock upstream and holds no secret; a non-matching
# `ref` and a revoked grant are refused. Run `just leak-scan` after.
workload-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    cd "$root"
    bash scripts/workload-smoke-cert.sh >/dev/null
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo build -q -p smith-cli --bin smith
    cargo nextest run -p ls-e2e --test workload

# `just api` for `just workload-smoke`: trusts the stub issuer's self-signed certificate and allows
# a loopback issuer (local development only; the default `just api` does neither).
workload-smoke-api:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    cd "$root"
    export SSL_CERT_FILE="$(bash scripts/workload-smoke-cert.sh)"
    export LOCKSMITH_WORKLOAD_ALLOW_PRIVATE_ISSUERS=1
    exec just api

# S6 stack adversarial gate (needs `just up` and `just api`; fails fast without them): every
# gateway case with skips as failures, then `leak-scan` over the stack, the audit export and the
# kept artifacts. `--agent claude` adds the live prompts (no claude CLI or key: `skip live`, fails).
adversarial-gate *args:
    @bash tests/adversarial/gate.sh "$@"

# Regenerate packages/sdk/src/schema.d.ts from the control-plane OpenAPI file.
sdk-gen:
    npm run gen --workspace packages/sdk

# SDK smoke against `just up` + `just api`: create, list, delete an agent, then leak-scan the output.
sdk-smoke:
    bash scripts/sdk-smoke.sh

# End-to-end tests against the local stack (needs `just up`).
test-e2e:
    cargo nextest run -p ls-e2e

# Run one component's tests by directory name (see docs/testing.md): `just test control-plane`.
test name:
    #!/usr/bin/env bash
    set -euo pipefail
    n="$1"
    dir=""
    for d in crates/"$n" services/"$n" apps/"$n" packages/"$n" integrations/"$n" tests/"$n"; do
      [ -d "$d" ] && dir="$d" && break
    done
    run() { echo "+ $*" >&2; "$@"; }
    if [ -z "$dir" ] || ! grep -q "^| \`$dir\` |" docs/testing.md; then
      echo "just test: unknown component '$n'. Valid names:" >&2
      sed -n 's/^| `[a-z0-9]*\/\([a-z0-9_.-]*\)` |.*/  \1/p' docs/testing.md >&2
      exit 1
    fi
    case "$dir" in
      apps/desktop) run just desktop-test; run npm test --workspace apps/desktop ;;
      apps/web) run npm test --workspace apps/web ;;
      tests/e2e) run just test-e2e ;;
      tests/adversarial) run bash tests/adversarial/run.sh selftest ;;
      tests/kit) run bash tests/kit/leak_scan_test.sh ;;
      *)
        pkg=$(cargo metadata --no-deps --format-version 1 | jq -r --arg m "$PWD/$dir/Cargo.toml" '.packages[]|select(.manifest_path==$m)|.name')
        if [ -n "$pkg" ]; then run cargo nextest run -p "$pkg" --no-tests pass
        elif [ -f "$dir/package.json" ] && jq -e '.scripts.test' "$dir/package.json" >/dev/null; then run npm test --workspace "$dir"
        else
          cov=$(awk -F'|' -v d="\`$dir\`" '$2 ~ d {print $6}' docs/testing.md)
          echo "just test: $n has no tests of its own; covered by:$cov" >&2
          tgt=$(grep -o '`[a-z]*/[a-z0-9_-]*`' <<<"$cov" | head -1 | tr -d '`' || true)
          if [ -n "$tgt" ]; then run just test "${tgt#*/}"
          elif grep -q 'just test-web' <<<"$cov"; then run just test-web; fi
        fi ;;
    esac

# Build the control-plane and gateway images for the host architecture (P2). Extra flags (proxy, CA secret) go in IMAGE_BUILD_ARGS. Check: scripts/image-check.sh.
images:
    docker build $IMAGE_BUILD_ARGS -f infra/docker/control-plane.Dockerfile -t locksmith-control-plane:dev .
    docker build $IMAGE_BUILD_ARGS -f infra/docker/gateway.Dockerfile -t locksmith-gateway:dev .

# Self-host compose bundle (P2). Bootstraps secrets into infra/compose/selfhost/.env, then `up --wait`.
# Args go to bootstrap.sh: --external-keys, --tls, --demo-oidc. Images come from .env (LOCKSMITH_VERSION or *_IMAGE).
selfhost-up *args:
    bash infra/compose/selfhost/bootstrap.sh {{args}}
    docker compose --env-file infra/compose/selfhost/.env -f infra/compose/selfhost/compose.yaml up -d --wait --wait-timeout 240

# Stop the self-host stack; volumes (data, keys, unseal material) are kept. Pass `-v` to delete them.
selfhost-down *args:
    docker compose --env-file infra/compose/selfhost/.env -f infra/compose/selfhost/compose.yaml --profile tls --profile demo-oidc --profile bundled-keys down {{args}}

# Fresh self-host stack from locally built images (`just images` first): relay through the gateway, restart persistence, secret hygiene. Own project and volumes.
selfhost-smoke:
    bash scripts/selfhost-bootstrap.test.sh
    bash scripts/selfhost-smoke.sh

# Helm chart (P2): values schema tests, helm lint, template + kubeconform, then a kind install smoke. Stages whose tools are missing are skipped and the run says INCOMPLETE, never PASS.
helm-test:
    bash scripts/helm-test.sh

# Release scripts (P2): manifest, verify-release (minisign, sha256, cosign identity, SBOM) and Homebrew formula tests with throwaway keys. Needs minisign and jq; says SKIP, never PASS, when they are missing.
release-verify:
    bash scripts/make-manifest.test.sh
    bash scripts/verify-release.test.sh
    bash scripts/gen-formula.test.sh

# Installer (P2): scripts/install.sh against a local release directory with a throwaway minisign key (good install, bad signature, bad hash, missing verifier, unsupported platform, no credential reads). Needs minisign, jq and curl; says SKIP, never PASS, when missing.
installer-test:
    bash scripts/install.test.sh
