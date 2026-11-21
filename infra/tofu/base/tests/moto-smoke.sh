#!/usr/bin/env bash
# Opt-in smoke of the base stack's S3 and KMS pieces against a local moto server
# (task 3.4). Not part of `just ci`: it pip-installs moto into a cached venv.
#
# Applies kms.tf, s3.tf and variables.tf from a scratch copy with endpoint
# overrides, then asserts:
#   - alias/locksmith-dev exists and targets an enabled key with rotation on;
#   - the checkpoints bucket has Object Lock GOVERNANCE, 1 day, and KMS SSE;
#   - both buckets block public access.
# Uses fake credentials only; nothing real or secret is read or printed.
#
# Usage: bash infra/tofu/base/tests/moto-smoke.sh   (or `just aws-moto-smoke`)
set -euo pipefail

MOTO_VERSION="${MOTO_VERSION:-5.2.5}"
here="$(cd "$(dirname "$0")" && pwd)"
base="$(cd "$here/.." && pwd)"
repo="$(cd "$base/../../.." && pwd)"

cache="${XDG_CACHE_HOME:-$HOME/.cache}/locksmith"
venv="${LOCKSMITH_MOTO_VENV:-$cache/moto-venv}"
if ! "$venv/bin/python" -c "import moto, sys; sys.exit(moto.__version__ != '$MOTO_VERSION')" 2>/dev/null; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q --disable-pip-version-check "moto[server]==$MOTO_VERSION"
fi

TF_CLI_CONFIG_FILE="$(bash "$repo/scripts/tofu-setup.sh")"
export TF_CLI_CONFIG_FILE PATH="${TOFU_BIN_DIR:-$HOME/.local/bin}:$PATH"

# Fake credentials, local endpoint only; never touch a real profile.
unset AWS_PROFILE AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE
export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_DEFAULT_REGION=us-east-1
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"

work="$(mktemp -d)"
moto_pid=""
cleanup() {
  if [ -n "$moto_pid" ]; then kill "$moto_pid" 2>/dev/null || true; fi
  rm -rf "${work:?}"
}
trap cleanup EXIT

port="$("$venv/bin/python" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
endpoint="http://127.0.0.1:$port"
"$venv/bin/moto_server" -H 127.0.0.1 -p "$port" >"$work/moto.log" 2>&1 &
moto_pid=$!
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "$endpoint/moto-api/" 2>/dev/null && break
  sleep 0.2
done
curl -fsS -o /dev/null "$endpoint/moto-api/" || { echo "moto-smoke: moto server did not start" >&2; exit 1; }

mod="$work/base"
mkdir -p "$mod"
cp "$base/kms.tf" "$base/s3.tf" "$base/variables.tf" "$mod/"
cat >"$mod/smoke_provider.tf" <<EOF
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "testing"
  secret_key                  = "testing"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints {
    kms = "$endpoint"
    s3  = "$endpoint"
    sts = "$endpoint"
  }
}

data "aws_caller_identity" "current" {}
EOF

tofu -chdir="$mod" init -backend=false -input=false -no-color >"$work/init.log" 2>&1 \
  || { cat "$work/init.log" >&2; exit 1; }
tofu -chdir="$mod" apply -auto-approve -input=false -no-color >"$work/apply.log" 2>&1 \
  || { tail -40 "$work/apply.log" >&2; exit 1; }
grep -E '^Apply complete' "$work/apply.log"

"$venv/bin/python" -I - "$endpoint" <<'PY'
import sys
import boto3

ep = sys.argv[1]
kw = dict(endpoint_url=ep, region_name="us-east-1",
          aws_access_key_id="testing", aws_secret_access_key="testing")
kms, s3, sts = (boto3.client(n, **kw) for n in ("kms", "s3", "sts"))
acct = sts.get_caller_identity()["Account"]
fails = []

def check(ok, msg):
    print(("ok   " if ok else "FAIL ") + msg)
    if not ok:
        fails.append(msg)

aliases = {a["AliasName"]: a.get("TargetKeyId") for a in kms.list_aliases()["Aliases"]}
key = aliases.get("alias/locksmith-dev")
check(key is not None, "kms alias/locksmith-dev exists")
if key:
    md = kms.describe_key(KeyId=key)["KeyMetadata"]
    check(md["KeyState"] == "Enabled", "kms key enabled")
    check(kms.get_key_rotation_status(KeyId=key)["KeyRotationEnabled"], "kms key rotation enabled")

cp = f"locksmith-dev-checkpoints-{acct}"
art = f"locksmith-dev-artifacts-{acct}"
lock = s3.get_object_lock_configuration(Bucket=cp)["ObjectLockConfiguration"]
ret = lock.get("Rule", {}).get("DefaultRetention", {})
check(lock.get("ObjectLockEnabled") == "Enabled", "checkpoints Object Lock enabled")
check(ret.get("Mode") == "GOVERNANCE", f"checkpoints retention mode GOVERNANCE (got {ret.get('Mode')})")
check(ret.get("Days") == 1, f"checkpoints retention 1 day (got {ret.get('Days')})")
check(s3.get_bucket_versioning(Bucket=cp).get("Status") == "Enabled", "checkpoints versioning enabled")

for b in (cp, art):
    rule = s3.get_bucket_encryption(Bucket=b)["ServerSideEncryptionConfiguration"]["Rules"][0]
    sse = rule["ApplyServerSideEncryptionByDefault"]
    check(sse["SSEAlgorithm"] == "aws:kms", f"{b} SSE-KMS")
    pab = s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"]
    check(all(pab.values()), f"{b} public access blocked")

print("moto-smoke: " + ("FAILED" if fails else "OK"))
sys.exit(1 if fails else 0)
PY
