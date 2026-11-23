#!/usr/bin/env bash
# G12: AWS credential vending (D2 task 6.1): `POST /v1/aws/credentials` on the gateway. The base
# credential is the case canary (the `secret_access_key` of the AWS secret, version 2). STS is a
# stub (fixtures/sts_stub.py, via the gateway's STS endpoint override) that records what the
# gateway sent and answers ok, with an error body that echoes request details and the canary, or
# with the canary inside a "credential". The agent holds a `delegate` grant allowing
# `s3:GetObject` on one bucket, capped at 1200 s; the binding caps at 1800 s. Probes, as an
# agent with its own HTTP client (curl with the agent token) and through
# `smith aws credential-process`:
#   - policy: a request body with `policy`, `Policy`, `session_policy`, `actions`, `resources`,
#     `external_id` and `policy_arns` is ignored: STS receives the policy rendered from the grant
#     (one Allow statement, no `*`), identical to a plain request's; another role is a 403 with
#     no STS call;
#   - duration: 7200 and absurd numbers are clamped to the grant's 1200 s (or refused 400),
#     never above 3600; 899, 0, -1 and 1 are 400 with no STS call;
#   - STS error echo: an STS error body with the role ARN, a marker and the canary becomes the
#     fixed slug `sts_error` (502); none of it reaches the caller (curl or smith);
#   - redaction: an STS answer that carries the canary is refused 502 `redaction_failed`;
#   - base credential absent: the oracle scans every response, `smith` output, the stub's log,
#     the gateway log and the ledger for the canary; the ledger holds `aws.credentials.issued`
#     and `aws.credentials.denied`.
# Skips when the stack is down. STS is the stub, not Floci: the stub records the exact request
# (policy, duration, role, external id) and can echo or leak on demand (design.md decision 6).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

BUCKET_ARN="arn:aws:s3:::g11-bucket/*"
ROLE_ARN="arn:aws:iam::123456789012:role/g11-role"
GRANT_MAX=1200

# STS stub; its mode is switched per probe through a file.
mode_file="$GW_WORK/sts.mode"
echo ok >"$mode_file"
: >"$ARTIFACT_DIR/sts-hits.log"
rm -f "$GW_WORK/sts.port"
python3 -I "$GW_ROOT/tests/adversarial/fixtures/sts_stub.py" "$GW_WORK/sts.port" "$ARTIFACT_DIR/sts-hits.log" \
  "$mode_file" "$CANARY_FILE" 2>>"$ARTIFACT_DIR/sts-stub.err" &
sts_pid=$!
gw_on_exit "kill $sts_pid 2>/dev/null; wait $sts_pid 2>/dev/null"
for _ in $(seq 1 100); do
  [[ -s "$GW_WORK/sts.port" ]] && break
  sleep 0.05
done
[[ -s "$GW_WORK/sts.port" ]] || gw_fail "the STS stub did not start"
export LOCKSMITH_GATEWAY_AWS_STS_ENDPOINT="http://127.0.0.1:$(<"$GW_WORK/sts.port")/"
marker_file="$mode_file.marker"

# Bindings: one AWS binding for the secret, reading version 2 (the JSON base credential).
g11_bind() {
  GW_BINDINGS="$GW_WORK/bindings.toml"
  printf 'org_id = "%s"\n[[aws_binding]]\nsecret_id = "%s"\nrole_arn = "%s"\nregion = "us-east-1"\nexternal_id = "g11-external"\nvend = true\nmax_duration_secs = 1800\nversion = 2\n' \
    "$GW_ORG" "$GW_SECRET_ID" "$ROLE_ARN" >"$GW_BINDINGS"
}
GW_BIND_FN=g11_bind
gw_setup

# Version 2: the base credential JSON (the only request carrying the canary; 0600 file in GW_WORK).
python3 -I -c '
import json, sys
v = open(sys.argv[1]).read().strip()
with open(sys.argv[2], "w") as fh:
    json.dump({"value": json.dumps({"access_key_id": "AKIAG9FAKEBASEKEY001", "secret_access_key": v})}, fh)
' "$CANARY_FILE" "$GW_WORK/version2.json"
gw_post "/v1/projects/$GW_PROJECT/environments/$GW_ENVIRONMENT/secrets/$GW_SECRET_ID/versions" "$GW_WORK/version2.json" version2
rm -f "$GW_WORK/version2.json"

# The delegate grant: s3:GetObject on one bucket, at most GRANT_MAX seconds.
gw_post "/v1/agents/$GW_AGENT_ID/grants" "$(gw_body dgrant "{\"secret_id\":\"$GW_SECRET_ID\",\"mode\":\"delegate\",\"scope\":{\"actions\":[\"s3:GetObject\"],\"resources\":[\"$BUCKET_ARN\"],\"max_duration_secs\":$GRANT_MAX}}")" dgrant

: >"$ARTIFACT_DIR/results.txt"
auth="$(gw_auth_header)"

# vend NAME BODY: POST BODY to /v1/aws/credentials; prints the status. The response is saved
# in ARTIFACT_DIR (it holds fake STS credentials by design; the oracle looks for the canary).
vend() {
  local name="$1" body="$2" st
  printf '%s' "$body" >"$GW_WORK/req-$name.json"
  st="$(gw_curl -X POST -H "@$auth" -H 'Content-Type: application/json' --data-binary "@$GW_WORK/req-$name.json" \
    -D "$ARTIFACT_DIR/raw-$name.hdr" -o "$ARTIFACT_DIR/raw-$name.out" -w '%{http_code}' \
    "$GW_GATEWAY_URL/v1/aws/credentials" 2>>"$ARTIFACT_DIR/raw-$name.err")" || st=000
  echo "$name status=$st" >>"$ARTIFACT_DIR/results.txt"
  echo "$st"
}
sts_calls() { grep -c . "$ARTIFACT_DIR/sts-hits.log" || true; }
# hit_field FIELD: one field of the last STS request.
hit_field() { tail -n 1 "$ARTIFACT_DIR/sts-hits.log" | python3 -I -c 'import json,sys; v=json.load(sys.stdin).get(sys.argv[1]); print("" if v is None else v)' "$1"; }
error_slug() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("error",""))' "$ARTIFACT_DIR/raw-$1.out" 2>/dev/null || true; }
jstr() { python3 -I -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }

# The session policy must be the grant's one Allow statement and nothing wider.
check_policy() {
  python3 -I -c '
import json, sys
pol = json.loads(sys.argv[1])
allow = [s for s in pol["Statement"] if s.get("Effect") == "Allow"]
assert len(allow) == 1, "expected exactly one Allow statement"
a = allow[0]
acts = a["Action"] if isinstance(a["Action"], list) else [a["Action"]]
res = a["Resource"] if isinstance(a["Resource"], list) else [a["Resource"]]
assert acts == ["s3:GetObject"], acts
assert res == [sys.argv[2]], res
' "$1" "$BUCKET_ARN" 2>/dev/null || gw_fail "$2: STS received a session policy that is not the grant's"
}

# 1. Baseline: the policy rendered from the grant, the duration within the grant's maximum.
st="$(vend baseline '{}')"
[[ "$st" == 200 ]] || gw_fail "baseline returned $st (see raw-baseline.out)"
[[ "$(sts_calls)" == 1 ]] || gw_fail "baseline: STS saw $(sts_calls) calls (expected 1)"
base_policy="$(hit_field Policy)"
check_policy "$base_policy" baseline
d="$(hit_field DurationSeconds)"
(( d >= 900 && d <= GRANT_MAX )) || gw_fail "baseline: DurationSeconds $d outside 900..$GRANT_MAX"
[[ "$(hit_field RoleArn)" == "$ROLE_ARN" ]] || gw_fail "baseline: STS got another role"

# 2. An agent-supplied policy (and scope, role, external id) is ignored.
evil='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
n0="$(sts_calls)"
st="$(vend policy "{\"policy\":$(jstr "$evil"),\"Policy\":$(jstr "$evil"),\"session_policy\":$evil,\"actions\":[\"*\"],\"resources\":[\"*\"],\"external_id\":\"agent-chosen\",\"policy_arns\":[\"arn:aws:iam::aws:policy/AdministratorAccess\"]}")"
[[ "$st" == 200 ]] || gw_fail "policy: returned $st (unknown fields must be ignored, not an error)"
[[ "$(sts_calls)" == $((n0 + 1)) ]] || gw_fail "policy: expected one STS call"
check_policy "$(hit_field Policy)" policy
[[ "$(hit_field Policy)" == "$base_policy" ]] || gw_fail "policy: the policy differs from the plain request's"
[[ "$(hit_field ExternalId)" == g11-external ]] || gw_fail "policy: the external id came from the agent"
# A role the binding does not name is refused before STS.
n0="$(sts_calls)"
st="$(vend other-role '{"role_arn":"arn:aws:iam::123456789012:role/admin"}')"
[[ "$st" == 403 ]] || gw_fail "other-role: returned $st (expected 403)"
[[ "$(sts_calls)" == "$n0" ]] || gw_fail "other-role: STS was called"

# 3. Duration: above the maximum is clamped to the grant's, never above 3600; below 900 is 400.
for spec in "over 7200" "huge 99999999" "max-int 4294967295"; do
  set -- $spec
  n0="$(sts_calls)"
  st="$(vend "dur-$1" "{\"duration_secs\":$2}")"
  if [[ "$st" == 200 ]]; then
    [[ "$(sts_calls)" == $((n0 + 1)) ]] || gw_fail "dur-$1: expected one STS call"
    d="$(hit_field DurationSeconds)"
    [[ "$d" == "$GRANT_MAX" ]] || gw_fail "dur-$1: STS got DurationSeconds $d (expected the grant maximum $GRANT_MAX)"
  elif [[ "$st" == 400 ]]; then
    [[ "$(sts_calls)" == "$n0" ]] || gw_fail "dur-$1: refused but STS was called"
  else
    gw_fail "dur-$1: returned $st (expected 200 clamped, or 400)"
  fi
done
for spec in "short 899" "zero 0" "negative -1" "one 1"; do
  set -- $spec
  n0="$(sts_calls)"
  st="$(vend "dur-$1" "{\"duration_secs\":$2}")"
  [[ "$st" == 400 ]] || gw_fail "dur-$1: returned $st (expected 400)"
  [[ "$(sts_calls)" == "$n0" ]] || gw_fail "dur-$1: STS was called"
done
[[ "$(error_slug dur-short)" == duration_too_short ]] || gw_fail "dur-short: not the duration_too_short slug"
# No STS request ever asked for more than the grant allows.
python3 -I -c '
import json, sys
mx = int(sys.argv[2])
for line in open(sys.argv[1]):
    d = int(json.loads(line)["DurationSeconds"] or 0)
    assert d <= mx and d <= 3600, d
' "$ARTIFACT_DIR/sts-hits.log" "$GRANT_MAX" || gw_fail "an STS request asked for more than the grant maximum"

# 4. STS error echo: the error text never reaches the caller.
echo err >"$mode_file"
st="$(vend sts-error '{}')"
[[ "$st" == 502 ]] || gw_fail "sts-error: returned $st (expected 502)"
[[ "$(error_slug sts-error)" == sts_error ]] || gw_fail "sts-error: not the fixed sts_error slug"
marker="$(<"$marker_file")"
cat "$ARTIFACT_DIR/raw-sts-error.hdr" "$ARTIFACT_DIR/raw-sts-error.out" >"$GW_WORK/sts-error.all"
if grep -qF -- "$marker" "$GW_WORK/sts-error.all"; then gw_fail "sts-error: the STS error text reached the caller"; fi
if grep -qF -- "$ROLE_ARN" "$GW_WORK/sts-error.all"; then gw_fail "sts-error: the role ARN reached the caller"; fi
if grep -qiF -- "AccessDenied" "$GW_WORK/sts-error.all"; then gw_fail "sts-error: the STS error code reached the caller"; fi
# The same through smith: a non-zero exit, nothing on stdout, no STS text on stderr.
if gw_smith aws-error aws credential-process; then gw_fail "smith aws credential-process succeeded on an STS error"; fi
[[ ! -s "$ARTIFACT_DIR/smith-aws-error.out" ]] || gw_fail "smith aws credential-process printed on stdout for an STS error"
if grep -qF -- "$marker" "$ARTIFACT_DIR/smith-aws-error.err"; then gw_fail "smith: the STS error text reached the caller"; fi

# 5. An STS answer that carries the base credential is refused.
echo leak >"$mode_file"
st="$(vend redaction '{}')"
[[ "$st" == 502 ]] || gw_fail "redaction: returned $st (expected 502)"
[[ "$(error_slug redaction)" == redaction_failed ]] || gw_fail "redaction: not the redaction_failed slug"
echo ok >"$mode_file"

# 6. smith credential-process (the AWS CLI's path): documented JSON on stdout, nothing on disk.
gw_smith aws-ok aws credential-process --duration-secs 7200 || gw_fail "smith aws credential-process failed (see smith-aws-ok.err)"
python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d["Version"] == 1 and all(d.get(k) for k in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"))
' "$ARTIFACT_DIR/smith-aws-ok.out" || gw_fail "smith aws credential-process: not the credential_process JSON"
d="$(hit_field DurationSeconds)"
[[ "$d" == "$GRANT_MAX" ]] || gw_fail "smith: STS got DurationSeconds $d (expected $GRANT_MAX)"
if find "$GW_AGENT_HOME" -type f \( -name credentials -o -path '*/.aws/*' \) | grep -q .; then
  gw_fail "smith left AWS credentials in the agent home"
fi

# 7. Ledger: issued and denied events exist; the oracle scans the export for the canary.
gw_ledger final
issued="$(gw_ledger_count "$GW_LEDGER" aws.credentials.issued)"
denied="$(gw_ledger_count "$GW_LEDGER" aws.credentials.denied)"
echo "ledger issued=$issued denied=$denied" >>"$ARTIFACT_DIR/results.txt"
(( issued >= 1 )) || gw_fail "no aws.credentials.issued event in the ledger"
(( denied >= 1 )) || gw_fail "no aws.credentials.denied event in the ledger"
echo "G12 ok"
