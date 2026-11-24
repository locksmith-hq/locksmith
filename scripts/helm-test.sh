#!/usr/bin/env bash
# Helm chart test (P2 packaging, task 4.4): schema tests, `helm lint`, `helm template | kubeconform`,
# then an install on a throwaway kind cluster with prerequisite Secrets generated here, waiting for
# the pods (and the migration Job when enabled) and checking both services answer.
#
# Each stage that needs a missing tool is SKIPPED with a message and counted; a run with any skipped
# stage exits 0 but says "INCOMPLETE" and never prints PASS. Secret values are generated into a
# 0700 temp directory and are never printed. Pinned tool versions: docs/research/packaging.md.
#
# Usage: scripts/helm-test.sh        (`just helm-test` wraps this; `just images` first for the kind stage)
# Env: LOCKSMITH_CONTROL_PLANE_IMAGE / LOCKSMITH_GATEWAY_IMAGE (default locksmith-*:dev), KEEP_KIND=1 keeps the cluster.
# shellcheck disable=SC2015  # A && ok || bad is the reporting idiom
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
chart=infra/helm/locksmith
fails=0 skipped=0
ok()   { echo "ok   $*"; }
bad()  { echo "FAIL $*" >&2; fails=$((fails + 1)); }
skip() { echo "SKIP $*"; skipped=$((skipped + 1)); }

# Values that satisfy the schema; secret names only (the Secrets are created by the kind stage).
demo_set=(--set secrets.database.existingSecret=ls-db --set secrets.internal.existingSecret=ls-internal
  --set secrets.keyProvider.existingSecret=ls-keys --set keyProvider.address=http://openbao:8200)

echo "== 1. values schema (good and bad files)"
if bash scripts/helm-schema.test.sh; then ok "schema tests"; else bad "schema tests"; fi

echo "== 2. helm lint and template"
rendered=""
if command -v helm >/dev/null 2>&1; then
  helm lint "$chart" "${demo_set[@]}" >/dev/null && ok "helm lint (defaults + secret names)" || bad "helm lint"
  helm lint "$chart" -f "$chart/tests/good-values.yaml" >/dev/null && ok "helm lint (good-values.yaml)" || bad "helm lint good-values.yaml"
  rendered=$(mktemp); trap 'rm -f "$rendered"' EXIT
  helm template locksmith "$chart" --kube-version 1.31.0 "${demo_set[@]}" --set migration.enabled=true --set 'migration.args={migrate-only}' --set ingress.enabled=true \
    --set ingress.host=locksmith.example.com >"$rendered" && ok "helm template" || { bad "helm template"; rendered=""; }
  if [ -n "$rendered" ]; then
    # Literal-secret hygiene: the rendered manifests carry no Secret object and only secretKeyRef for credentials.
    if grep -q '^kind: Secret$' "$rendered"; then bad "chart renders a Secret object"; else ok "chart renders no Secret object"; fi
  fi
else
  skip "helm lint/template: helm not installed (pinned v4.3.2; get.helm.sh may be blocked, \`go install helm.sh/helm/v4/cmd/helm@v4.3.2\` works)"
fi

echo "== 3. kubeconform"
if [ -z "$rendered" ]; then skip "kubeconform: nothing rendered"
elif ! command -v kubeconform >/dev/null 2>&1; then skip "kubeconform not installed (pinned v0.8.0)"
else
  if kubeconform -strict -summary -ignore-missing-schemas - <"$rendered"; then ok "kubeconform"; else bad "kubeconform"; fi
fi

echo "== 4. kind install and smoke"
CP_IMG="${LOCKSMITH_CONTROL_PLANE_IMAGE:-locksmith-control-plane:dev}"
GW_IMG="${LOCKSMITH_GATEWAY_IMAGE:-locksmith-gateway:dev}"
kind_stage() {
  local work cluster ns=locksmith-test rel=ls kc app_pw pg_pw tok sign
  cluster="locksmith-helm-$$"; kc=(kubectl --context "kind-$cluster" -n "$ns")
  work=$(mktemp -d); chmod 700 "$work"
  on_fail() {
    echo "--- pod status and events ($ns)" >&2
    "${kc[@]}" get pods -o wide >&2 2>&1 || true
    "${kc[@]}" get events --sort-by=.lastTimestamp >&2 2>&1 | tail -40 || true
    for p in $("${kc[@]}" get pods -o name 2>/dev/null); do echo "--- logs $p" >&2; "${kc[@]}" logs --tail=30 "$p" >&2 2>&1 || true; done
  }
  cleanup() { [ "${KEEP_KIND:-0}" = 1 ] || kind delete cluster --name "$cluster" >/dev/null 2>&1; rm -rf "$work"; }
  trap cleanup RETURN
  gen() { openssl rand -hex 24; }
  pg_pw=$(gen); app_pw=$(gen); tok=$(gen); sign=$(openssl rand -base64 32)
  kind create cluster --name "$cluster" --wait 120s >/dev/null 2>&1 || { bad "kind create cluster"; return; }
  kind load docker-image "$CP_IMG" "$GW_IMG" --name "$cluster" >/dev/null 2>&1 || { bad "kind load images (run 'just images')"; return; }
  kubectl --context "kind-$cluster" create namespace "$ns" >/dev/null
  # Prerequisite Secrets and a test Postgres and OpenBao (dev mode, random token, test only), values via stdin.
  local pgimg=postgres:18.7 baoimg=openbao/openbao:2.7.2
  docker pull -q "$pgimg" >/dev/null 2>&1; docker pull -q "$baoimg" >/dev/null 2>&1
  kind load docker-image "$pgimg" "$baoimg" --name "$cluster" >/dev/null 2>&1 || true
  "${kc[@]}" create secret generic ls-db \
    --from-literal=DATABASE_URL="postgres://locksmith_app:${app_pw}@postgres:5432/locksmith" \
    --from-literal=DATABASE_OWNER_URL="postgres://locksmith:${pg_pw}@postgres:5432/locksmith" >/dev/null
  "${kc[@]}" create secret generic ls-internal \
    --from-literal=LOCKSMITH_GATEWAY_SERVICE_TOKEN="$(gen)" --from-literal=LOCKSMITH_AGENT_SIGNING_KEY="$sign" >/dev/null
  "${kc[@]}" create secret generic ls-keys \
    --from-literal=OPENBAO_CONTROL_PLANE_TOKEN="$tok" --from-literal=OPENBAO_GATEWAY_TOKEN="$tok" \
    --from-literal=OPENBAO_AUDIT_CHECKPOINT_TOKEN="$tok" >/dev/null
  "${kc[@]}" create secret generic ls-test-backing \
    --from-literal=PG_PASSWORD="$pg_pw" --from-literal=OWNER_PW="$(gen)" --from-literal=APP_PW="$app_pw" \
    --from-literal=VERIFIER_PW="$(gen)" --from-literal=BAO_TOKEN="$tok" >/dev/null
  "${kc[@]}" apply -f - >/dev/null <<YAML || { bad "apply backing services"; return; }
apiVersion: v1
kind: ConfigMap
metadata: {name: pg-init}
data:
  10-roles.sh: |
    #!/bin/sh
    set -eu
    psql -v ON_ERROR_STOP=1 -U locksmith -d locksmith -v owner_pw="\$OWNER_PW" -v app_pw="\$APP_PW" -v verifier_pw="\$VERIFIER_PW" >/dev/null <<'SQL'
    CREATE ROLE locksmith_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    CREATE ROLE locksmith_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    CREATE ROLE audit_verifier LOGIN PASSWORD :'verifier_pw' NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
    SQL
---
apiVersion: v1
kind: Pod
metadata: {name: postgres, labels: {app: postgres}}
spec:
  containers:
    - name: postgres
      image: $pgimg
      imagePullPolicy: IfNotPresent
      env:
        - {name: POSTGRES_USER, value: locksmith}
        - {name: POSTGRES_DB, value: locksmith}
        - {name: POSTGRES_PASSWORD, valueFrom: {secretKeyRef: {name: ls-test-backing, key: PG_PASSWORD}}}
        - {name: OWNER_PW, valueFrom: {secretKeyRef: {name: ls-test-backing, key: OWNER_PW}}}
        - {name: APP_PW, valueFrom: {secretKeyRef: {name: ls-test-backing, key: APP_PW}}}
        - {name: VERIFIER_PW, valueFrom: {secretKeyRef: {name: ls-test-backing, key: VERIFIER_PW}}}
      readinessProbe: {exec: {command: [pg_isready, -U, locksmith, -d, locksmith]}, periodSeconds: 3}
      volumeMounts: [{name: init, mountPath: /docker-entrypoint-initdb.d}]
  volumes: [{name: init, configMap: {name: pg-init, defaultMode: 0755}}]
---
apiVersion: v1
kind: Service
metadata: {name: postgres}
spec: {selector: {app: postgres}, ports: [{port: 5432}]}
---
apiVersion: v1
kind: Pod
metadata: {name: openbao, labels: {app: openbao}}
spec:
  containers:
    - name: openbao
      image: $baoimg
      imagePullPolicy: IfNotPresent
      args: ["server", "-dev", "-dev-listen-address=0.0.0.0:8200"]
      env:
        - {name: BAO_DEV_ROOT_TOKEN_ID, valueFrom: {secretKeyRef: {name: ls-test-backing, key: BAO_TOKEN}}}
        - {name: BAO_ADDR, value: "http://127.0.0.1:8200"}
        - {name: BAO_TOKEN, valueFrom: {secretKeyRef: {name: ls-test-backing, key: BAO_TOKEN}}}
      readinessProbe: {exec: {command: [sh, -c, "bao secrets enable transit >/dev/null 2>&1; bao read transit/keys/gateway >/dev/null 2>&1 || { bao write -f transit/keys/gateway type=aes256-gcm96 && bao write -f transit/keys/audit-checkpoint type=ed25519; } >/dev/null 2>&1; bao read transit/keys/audit-checkpoint >/dev/null"]}, periodSeconds: 3, timeoutSeconds: 5}
---
apiVersion: v1
kind: Service
metadata: {name: openbao}
spec: {selector: {app: openbao}, ports: [{port: 8200}]}
YAML
  "${kc[@]}" wait --for=condition=Ready pod/postgres pod/openbao --timeout=180s >/dev/null 2>&1 || { bad "test Postgres/OpenBao not ready"; on_fail; return; }
  local cp_repo=${CP_IMG%:*} cp_tag=${CP_IMG##*:} gw_repo=${GW_IMG%:*} gw_tag=${GW_IMG##*:}
  if ! helm upgrade --install "$rel" "$chart" --kube-context "kind-$cluster" -n "$ns" --wait --timeout 240s \
      "${demo_set[@]}" --set images.pullPolicy=Never \
      --set images.controlPlane.repository="$cp_repo" --set images.controlPlane.tag="$cp_tag" \
      --set images.gateway.repository="$gw_repo" --set images.gateway.tag="$gw_tag" >/dev/null 2>"$work/helm.err"; then
    bad "helm install did not become ready"; sed 's/postgres:\/\/[^ ]*/<dsn>/g' "$work/helm.err" >&2; on_fail; return
  fi
  ok "helm install ready (migration Job is off by default: the control plane migrates on start)"
  "${kc[@]}" rollout status deploy/$rel-control-plane deploy/$rel-gateway --timeout=60s >/dev/null 2>&1 \
    && ok "both Deployments rolled out" || { bad "rollout"; on_fail; return; }
  local svc code
  for svc in control-plane:8080 gateway:8090; do
    code=$("${kc[@]}" run "probe-${svc%%:*}" --rm -i --restart=Never --image="$pgimg" --override-type=strategic \
      --overrides='{"spec":{"securityContext":{"runAsUser":0}}}' --command -- \
      sh -c "exec 3<>/dev/tcp/$rel-${svc%%:*}/${svc##*:} && printf 'GET /readyz HTTP/1.0\r\n\r\n' >&3 && head -n1 <&3" 2>/dev/null | tr -d '\r' | awk '{print $2}')
    [ "$code" = 200 ] && ok "${svc%%:*} /readyz answers 200 through its Service" || { bad "${svc%%:*} /readyz returned '${code:-none}' (NetworkPolicy may block the probe pod; see events)"; on_fail; return; }
  done
}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then skip "kind stage: Docker is absent or its daemon is not reachable"
elif ! command -v kind >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1; then skip "kind stage: kind or kubectl not installed (pinned kind v0.33.0)"
elif ! command -v helm >/dev/null 2>&1; then skip "kind stage: helm not installed"
elif ! docker image inspect "$CP_IMG" "$GW_IMG" >/dev/null 2>&1; then skip "kind stage: images $CP_IMG / $GW_IMG not built (run 'just images')"
else kind_stage
fi

echo
if [ "$fails" -gt 0 ]; then echo "helm-test: FAILED ($fails failure(s), $skipped stage(s) skipped)" >&2; exit 1; fi
if [ "$skipped" -gt 0 ]; then echo "helm-test: INCOMPLETE, $skipped stage(s) SKIPPED; this is not a pass"; exit 0; fi
echo "helm-test: PASS"
