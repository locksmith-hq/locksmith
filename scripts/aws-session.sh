#!/usr/bin/env bash
# AWS dev session helper: up | down | status | drift | smoke   (just aws-up, aws-down, ...)
# Needs AWS credentials in the environment (profile or SSO); it never prints them,
# and refuses to run without them. Nothing here reads or prints secret values.
set -euo pipefail
cd "$(dirname "$0")/.."

cmd="${1:-}"
tf="infra/tofu"
export PATH="${TOFU_BIN_DIR:-$HOME/.local/bin}:$PATH"

usage() { echo "usage: aws-session.sh up|down|status|drift|smoke" >&2; exit 2; }

need_creds() {
  if ! command -v aws >/dev/null 2>&1; then
    echo "aws-session: the aws CLI is not installed; install it and sign in (aws sso login)" >&2; exit 3
  fi
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "aws-session: no usable AWS credentials; run 'aws sso login' (agent VMs have none by design, decision A0-18)" >&2; exit 3
  fi
}

need_tools() {
  for t in tofu jq; do
    command -v "$t" >/dev/null 2>&1 || { echo "aws-session: $t is required" >&2; exit 3; }
  done
  TF_CLI_CONFIG_FILE="$(bash scripts/tofu-setup.sh)"; export TF_CLI_CONFIG_FILE
}

base_out() { tofu -chdir="$tf/base" output -json | jq -r "$1"; }

# Writes the session variable file from base outputs and the caller's inputs. No secrets.
write_vars() {
  if [ "$cmd" = up ]; then
    : "${LOCKSMITH_ALLOWED_CIDR:?set LOCKSMITH_ALLOWED_CIDR to your public IP as a /32}"
    : "${LOCKSMITH_IMAGE_TAG:?set LOCKSMITH_IMAGE_TAG to the pushed ECR image tag}"
  fi
  # down/drift only need valid placeholders; the values do not matter for destroy or the plan diff.
  LOCKSMITH_ALLOWED_CIDR="${LOCKSMITH_ALLOWED_CIDR:-192.0.2.1/32}"
  LOCKSMITH_IMAGE_TAG="${LOCKSMITH_IMAGE_TAG:-unset}"
  mkdir -p target/aws
  tofu -chdir="$tf/base" output -json | jq \
    --arg cidr "$LOCKSMITH_ALLOWED_CIDR" --arg tag "$LOCKSMITH_IMAGE_TAG" \
    --arg start "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg ssm "${LOCKSMITH_DATABASE_URL_PARAMETER_ARN:-}" '{
      vpc_id: .vpc_id.value,
      public_subnet_ids: .public_subnet_ids.value,
      session_tasks_security_group_id: .session_tasks_security_group_id.value,
      kms_key_arn: .kms_key_arn.value,
      ecr_repository_urls: .ecr_repository_urls.value,
      aurora_endpoint: .aurora_endpoint.value,
      cognito_issuer_url: .cognito_issuer_url.value,
      allowed_cidr: $cidr, image_tag: $tag, start_time: $start, database_url_parameter_arn: $ssm
    }' > target/aws/session.auto.tfvars.json
}

session_init() { tofu -chdir="$tf/session" init -input=false >/dev/null; }
tfvars() { echo "-var-file=$PWD/target/aws/session.auto.tfvars.json"; }

task_ips() {
  local cluster
  cluster="$(tofu -chdir="$tf/session" output -raw cluster_name)"
  for svc in control-plane gateway; do
    local arn eni ip
    arn="$(aws ecs list-tasks --cluster "$cluster" --service-name "$svc" --query 'taskArns[0]' --output text)"
    [ "$arn" = "None" ] && continue
    eni="$(aws ecs describe-tasks --cluster "$cluster" --tasks "$arn" \
      --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value | [0]" --output text)"
    ip="$(aws ec2 describe-network-interfaces --network-interface-ids "$eni" \
      --query 'NetworkInterfaces[0].Association.PublicIp' --output text)"
    echo "$svc $ip"
  done
}

case "$cmd" in
  up)
    need_tools; need_creds; write_vars; session_init
    tofu -chdir="$tf/session" apply -input=false -auto-approve "$(tfvars)"
    echo "session ends at: $(tofu -chdir="$tf/session" output -raw expires_at)"
    echo "task public IPs (control-plane 8080, gateway 8081; may take a minute):"
    task_ips || true ;;
  down)
    need_tools; need_creds; write_vars; session_init
    tofu -chdir="$tf/session" destroy -input=false -auto-approve "$(tfvars)" ;;
  status)
    need_tools; need_creds; session_init
    echo "session outputs:"; tofu -chdir="$tf/session" output 2>&1 || true
    task_ips || echo "no running tasks" ;;
  drift)
    need_tools; need_creds
    for m in base session; do
      [ "$m" = session ] && { write_vars; }
      tofu -chdir="$tf/$m" init -input=false >/dev/null
      args=(-input=false -detailed-exitcode -lock=false)
      [ "$m" = session ] && args+=("$(tfvars)")
      set +e; tofu -chdir="$tf/$m" plan "${args[@]}" >/dev/null; rc=$?; set -e
      case "$rc" in
        0) echo "drift: $m clean" ;;
        2) echo "drift: $m has changes (run 'tofu plan' for details)"; drift=1 ;;
        *) echo "drift: $m plan failed" >&2; exit 1 ;;
      esac
    done
    exit "${drift:-0}" ;;
  smoke)
    need_tools; need_creds
    smoke_fail=0
    check() { # name, command...
      local name="$1"; shift
      if "$@" >/dev/null 2>&1; then echo "PASS $name"; else echo "FAIL $name"; smoke_fail=1; fi
    }
    key="$(base_out .kms_key_arn.value)"; bucket="$(base_out .checkpoints_bucket.value)"

    # shellcheck disable=SC2329  # invoked through check()
    kms_roundtrip() {
      local a b blob
      a="$(head -c 32 /dev/urandom | base64)"
      blob="$(aws kms encrypt --key-id "$key" --plaintext "$a" --cli-binary-format raw-in-base64-out \
        --query CiphertextBlob --output text)"
      b="$(aws kms decrypt --ciphertext-blob "$blob" --key-id "$key" --query Plaintext --output text)"
      [ "$a" = "$b" ]
    }
    # shellcheck disable=SC2329  # invoked through check()
    s3_lock() {
      local k
      k="smoke/$(date -u +%s)-$$.txt"
      aws s3api put-object --bucket "$bucket" --key "$k" --body /dev/null --server-side-encryption aws:kms >/dev/null
      [ "$(aws s3api head-object --bucket "$bucket" --key "$k" --query ObjectLockMode --output text)" = "GOVERNANCE" ]
    }
    cp_ip=""
    while read -r svc ip; do
      [ "$svc" = control-plane ] && cp_ip="$ip"
    done < <(task_ips 2>/dev/null || true)

    check "kms wrap/unwrap" kms_roundtrip
    check "s3 object lock write" s3_lock
    # /readyz touches the database, so a pass proves Aurora resumed from auto-pause.
    check "aurora resume (control plane /readyz)" bash -c "[ -n '$cp_ip' ] && curl -fsS -m 120 --retry 3 --retry-delay 10 'http://$cp_ip:8080/readyz'"
    issuer="$(base_out .cognito_issuer_url.value)"
    # The spec's "token accepted by the control plane" check needs T1 sign-in; until then this checks the issuer is live.
    check "cognito issuer discovery reachable" curl -fsS -m 20 "$issuer/.well-known/openid-configuration"
    check "fargate task answers /healthz" bash -c "[ -n '$cp_ip' ] && curl -fsS -m 30 'http://$cp_ip:8080/healthz'"
    exit "$smoke_fail" ;;
  *) usage ;;
esac
