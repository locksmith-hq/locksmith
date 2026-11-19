#!/usr/bin/env bash
# G5: control-plane and ledger surfaces. Two orgs hold the canary as a secret version: org A (the
# agent's, from gw_setup, bound to the reflecting provider) and org B (another tenant, with its
# own project, environment, secret, agent and grant). Every response goes to ARTIFACT_DIR/api/ as
# `HTTP <status>`, the header lines, a blank line and the body (enrollment secrets and agent
# tokens masked), so the oracle judges what an agent gets back. Request bodies, some of which
# carry the canary, stay in memory or in GW_WORK.
#
# 1. The sweep, driven by the live /openapi.json (saved as api/openapi.json):
#    - valid: every operation outside `internal` (a check fails when the document lists one the
#      plan does not call), read on org A's real resources and written on a scratch hierarchy
#      (project, environment, secret with a canary version, agent with a rotated enrollment
#      secret and a grant with an expiry) that is then deleted; each must answer 2xx;
#    - malformed: every path id (not a UUID, the nil UUID, NUL, dot segments, 300 digits), every
#      list query (bad limit and cursor, unknown parameter) and every request body (empty, not
#      JSON, truncated after the canary, wrong types, unknown fields holding the canary, wrong or
#      missing content type, over the 64 KiB limit, and per-route forms of the version and token
#      bodies) must be a 4xx, never a 2xx or 5xx; dev-org routes without the header, with a
#      garbage header or with only the agent token must be 401;
#    - cross-org: every dev-org route with a path, called as org B with org A's ids (and an
#      unknown org), must be 404; org B's lists must hold none of org A's ids; a grant naming the
#      other org's secret must be refused both ways;
#    - internal: every `/internal/v1` route without the service token (no auth, a wrong bearer,
#      the agent token, the dev-org header, an empty bearer) must be 401;
#    - the gateway's agent routes: `/v1/grants` with the agent token lists org A's secret only,
#      and with no or a garbage token is 401.
# 2. Request fields that reach audit event attributes: relays whose URL host, method or path
#    carry `{secret}` (refused, or sent literally), bound relays with several methods, and
#    `POST /internal/v1/audit/events` with the service token and hosts with a placeholder, path,
#    port, userinfo, space or an unknown `url` field (400), plus one valid event.
# 3. `GET /v1/audit/events` for both orgs (every page): every actor, target, kind, outcome and
#    attribute is an id, code, host or integer; neither org's ledger names the other's ids.
# 4. The audit export: `locksmith-audit export` into a fresh directory; both orgs' event and
#    checkpoint files go to ARTIFACT_DIR/audit-export for the oracle.
#
# Environment (optional): LOCKSMITH_AUDIT_BIN (a prebuilt locksmith-audit; otherwise built with
# cargo), plus everything lib.sh reads.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

gw_fixture api provider
api="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_setup "$api"
A_ORG="$GW_ORG"

# Org B: another tenant holding the same canary, created as its operator.
GW_ORG=""
gw_post /v1/orgs "$(gw_body org-b "{\"name\":\"adv-$GW_CASE-b-$(date +%s%N)\"}")" org-b
B_ORG="$(gw_json "$GW_BODY" id)"
GW_ORG="$B_ORG"
gw_post /v1/projects "$(gw_body project-b '{"name":"adv-b"}')" project-b
B_PROJECT="$(gw_json "$GW_BODY" id)"
gw_post "/v1/projects/$B_PROJECT/environments" "$(gw_body environment-b '{"name":"adv-b"}')" environment-b
B_ENVIRONMENT="$(gw_json "$GW_BODY" id)"
b_secrets="/v1/projects/$B_PROJECT/environments/$B_ENVIRONMENT/secrets"
gw_post "$b_secrets" "$(gw_body secret-b '{"name":"UPSTREAM_KEY"}')" secret-b
B_SECRET="$(gw_json "$GW_BODY" id)"
python3 -I -c '
import json, sys
v = open(sys.argv[1]).read().strip()
with open(sys.argv[2], "w") as fh:
    json.dump({"value": v}, fh)
' "$CANARY_FILE" "$GW_WORK/version-b.json"
gw_post "$b_secrets/$B_SECRET/versions" "$GW_WORK/version-b.json" version-b
rm -f "$GW_WORK/version-b.json"
GW_CP_PRIVATE=1 gw_post /v1/agents "$(gw_body agent-b '{"name":"adv-agent-b"}')" agent-b
python3 -I -c '
import json, sys
doc = json.load(open(sys.argv[1]))
doc["enrollment_secret"] = "<masked by G5>"
with open(sys.argv[2], "w") as fh:
    json.dump(doc, fh)
' "$GW_BODY" "$ARTIFACT_DIR/setup/$(basename "$GW_BODY")"
rm -f "$GW_BODY"
GW_BODY="$ARTIFACT_DIR/setup/$(basename "$GW_BODY")"
B_AGENT="$(gw_json "$GW_BODY" agent.id)"
gw_post "/v1/agents/$B_AGENT/grants" "$(gw_body grant-b "{\"secret_id\":\"$B_SECRET\"}")" grant-b
B_GRANT="$(gw_json "$GW_BODY" id)"
GW_ORG="$A_ORG"

# Ids only (no values): both orgs' resources, for the sweep and the ledger checks.
python3 -I -c '
import json, sys
k = ["org", "project", "environment", "secret", "agent", "grant"]
a, b = sys.argv[2:8], sys.argv[8:14]
json.dump({"a": dict(zip(k, a)), "b": dict(zip(k, b))}, open(sys.argv[1], "w"), indent=1)
' "$ARTIFACT_DIR/ids.json" \
  "$A_ORG" "$GW_PROJECT" "$GW_ENVIRONMENT" "$GW_SECRET_ID" "$GW_AGENT_ID" "$GW_GRANT_ID" \
  "$B_ORG" "$B_PROJECT" "$B_ENVIRONMENT" "$B_SECRET" "$B_AGENT" "$B_GRANT"

# The gateway service token (dev-only, from .env.example), in a private header file.
svc_hdr="$GW_WORK/service-auth.hdr"
(
  t="$(gw_env LOCKSMITH_GATEWAY_SERVICE_TOKEN)"
  [[ -n "$t" ]] || exit 1
  printf 'Authorization: Bearer %s\n' "$t" >"$svc_hdr"
) || gw_fail "no LOCKSMITH_GATEWAY_SERVICE_TOKEN in $GW_ENV_FILE"
agent_hdr="$(gw_auth_header)"

# 1 and part of 2: the HTTP sweep. Every response is saved under ARTIFACT_DIR/api; one line per
# call goes to ARTIFACT_DIR/results.txt (mode, operation, probe, status, expectation).
python3 -I - "$GW_API" "$GW_GATEWAY_URL" "$ARTIFACT_DIR" "$CANARY_FILE" "$GW_ENROLLMENT_FILE" \
  "$agent_hdr" "$svc_hdr" <<'PY' || gw_fail "control-plane sweep failed (see results.txt)"
import datetime, http.client, json, os, re, sys, urllib.parse, uuid

api, gw, art, canary_file, enroll_file, agent_hdr, svc_hdr = sys.argv[1:8]
canary = open(canary_file).read().strip()
enroll = open(enroll_file).read().strip()
ids = json.load(open(os.path.join(art, "ids.json")))
A, B = ids["a"], ids["b"]


def bearer_of(path):
    v = open(path).read().strip().partition(":")[2].strip()
    return v[len("Bearer "):] if v.startswith("Bearer ") else v


agent_auth = bearer_of(agent_hdr)
svc_auth = bearer_of(svc_hdr)
outdir = os.path.join(art, "api")
os.makedirs(outdir, exist_ok=True)
results = open(os.path.join(art, "results.txt"), "w")
failures = []
n = 0
done = {}  # operationId -> set of modes called
MASK = ("enrollment_secret", "access_token")
DEV = "X-Locksmith-Dev-Org"
SVC_ORG = "X-Locksmith-Org"
ID_RE = re.compile(r"\{([a-z_]+)\}")


def mask(v):
    if isinstance(v, dict):
        return {k: ("<masked by G5>" if k in MASK and isinstance(x, str) else mask(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [mask(x) for x in v]
    return v


def check(status, expect):
    if status == 0:
        return False
    if expect == "2xx":
        return 200 <= status < 300
    if expect == "4xx":
        return 400 <= status < 500
    if expect == "not5xx":
        return status < 500
    if expect == "refused":
        return status in (400, 403)
    return str(status) == expect


def call(base, mode, opid, probe, method, path, body=None, ctype="application/json", headers=None,
         expect="2xx"):
    """One request; saves the response, records the line, returns (status, parsed JSON or None)."""
    global n
    n += 1
    u = urllib.parse.urlsplit(base)
    h = {"Accept": "application/json"}
    if body is not None:
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        if ctype:
            h["Content-Type"] = ctype
    h.update(headers or {})
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    status, data, rh = 0, b"", []
    try:
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        status, data, rh = r.status, r.read(), r.getheaders()
    except (OSError, http.client.HTTPException) as e:
        data = ("connection error: %s" % e.__class__.__name__).encode()
    finally:
        conn.close()
    doc = None
    try:
        doc = json.loads(data) if data else None
    except ValueError:
        pass
    shown = json.dumps(mask(doc)).encode() if doc is not None else data
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", "%s-%s-%s" % (mode, opid, probe))[:120]
    with open(os.path.join(outdir, "%04d-%s.http" % (n, safe)), "wb") as fh:
        fh.write(b"HTTP %d\n" % status)
        for k, v in rh:
            fh.write(("%s: %s\n" % (k, v)).encode("utf-8", "replace"))
        fh.write(b"\n" + shown)
    ok = check(status, expect)
    line = "%s %s %s %s %d expect=%s %s" % (mode, opid, probe, method, status, expect, "ok" if ok else "FAIL")
    results.write(line + "\n")
    if not ok:
        failures.append(line)
    done.setdefault(opid, set()).add(mode)
    return status, doc


def fill(tmpl, params):
    return ID_RE.sub(lambda m: urllib.parse.quote(str(params[m.group(1)]), safe="%"), tmpl)


def dev(org):
    return {DEV: org}


# The live document.
st, spec = call(api, "valid", "openapi_document", "get", "GET", "/openapi.json")
if not isinstance(spec, dict) or "paths" not in spec:
    print("G5: /openapi.json is not an OpenAPI document", file=sys.stderr)
    sys.exit(1)
with open(os.path.join(art, "api", "openapi.json"), "w") as fh:
    json.dump(spec, fh, indent=1)
ops = []  # (method, template, operation)
for tmpl, item in spec["paths"].items():
    for method, o in item.items():
        if method in ("get", "post", "put", "patch", "delete"):
            ops.append((method.upper(), tmpl, o))
by_key = {(m, t): o for m, t, o in ops}


def is_internal(o):
    return "internal" in (o.get("tags") or [])


def is_dev(o):
    return any("dev_org" in s for s in (o.get("security") or []))


def params_of(o, where):
    return [p["name"] for p in o.get("parameters", []) if p.get("in") == where]


def opid(method, tmpl):
    o = by_key.get((method, tmpl))
    if o is None:
        failures.append("plan calls %s %s, which the document does not list" % (method, tmpl))
        return "unlisted"
    return o["operationId"]


real = {"org_id": A["org"], "project_id": A["project"], "environment_id": A["environment"],
        "secret_id": A["secret"], "agent_id": A["agent"], "grant_id": A["grant"], "version": 1}
seq = [0]


def name(prefix):
    seq[0] += 1
    return "%s-%s-%d" % (prefix, uuid.uuid4().hex[:8], seq[0])


def valid_body(method, tmpl):
    if method == "PATCH":
        return {"description": "g5 patched"}
    if method != "POST":
        return None
    if tmpl == "/v1/orgs":
        return {"name": name("adv-G5-extra")}
    if tmpl.endswith("/versions"):
        return {"value": canary}
    if tmpl.endswith("/grants"):
        return {"secret_id": A["secret"], "mode": "relay"}
    if tmpl == "/v1/agent-tokens":
        return {"enrollment_secret": enroll}
    if tmpl.endswith("/enrollment-secret"):
        return None
    return {"name": name("g5")}


# --- valid: org A's real resources (reads) and a scratch hierarchy (writes, then deletes) ---
def valid(method, tmpl, params=None, body=None, hdr=True):
    p = dict(real)
    p.update(params or {})
    return call(api, "valid", opid(method, tmpl), "ok", method, fill(tmpl, p), body=body,
                headers=dev(A["org"]) if hdr else None)


P = "/v1/projects/{project_id}"
E = P + "/environments/{environment_id}"
S = E + "/secrets/{secret_id}"
AG = "/v1/agents/{agent_id}"
for m, t in [("GET", "/healthz"), ("GET", "/readyz"), ("GET", "/.well-known/jwks.json"),
             ("GET", "/v1/orgs/{org_id}"), ("GET", "/v1/projects"), ("GET", P),
             ("GET", P + "/environments"), ("GET", E), ("GET", E + "/secrets"), ("GET", S),
             ("GET", S + "/versions"), ("GET", "/v1/agents"), ("GET", AG), ("GET", AG + "/grants"),
             ("GET", "/v1/audit/status")]:
    valid(m, t)
call(api, "valid", opid("GET", "/v1/audit/events"), "page", "GET", "/v1/audit/events?limit=5",
     headers=dev(A["org"]))
valid("POST", "/v1/orgs", body=valid_body("POST", "/v1/orgs"), hdr=False)
valid("POST", "/v1/agent-tokens", body={"enrollment_secret": enroll}, hdr=False)

scratch = {}
st, d = valid("POST", "/v1/projects", body={"name": name("g5-scratch"), "description": "g5"})
scratch["project_id"] = (d or {}).get("id")
valid("PATCH", P, scratch, {"description": "g5 patched"})
st, d = valid("POST", P + "/environments", scratch, {"name": name("g5-scratch")})
scratch["environment_id"] = (d or {}).get("id")
valid("PATCH", E, scratch, {"name": name("g5-renamed")})
st, d = valid("POST", E + "/secrets", scratch, {"name": name("G5_SCRATCH")})
scratch["secret_id"] = (d or {}).get("id")
valid("PATCH", S, scratch, {"description": "g5 patched"})
valid("POST", S + "/versions", scratch, {"value": canary})
valid("GET", S + "/versions", scratch)
st, d = valid("POST", "/v1/agents", body={"name": name("g5-scratch-agent"), "description": "g5"})
scratch["agent_id"] = ((d or {}).get("agent") or {}).get("id")
valid("POST", AG + "/enrollment-secret", scratch)
expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
st, d = valid("POST", AG + "/grants", scratch, {"secret_id": scratch["secret_id"], "mode": "relay", "expires_at": expires})
scratch["grant_id"] = (d or {}).get("id")
valid("GET", AG + "/grants", scratch)
if None in scratch.values():
    failures.append("the scratch hierarchy was not created; later valid writes are skipped")
else:
    valid("DELETE", AG + "/grants/{grant_id}", scratch)
    valid("DELETE", AG, scratch)
    valid("DELETE", S, scratch)
    valid("DELETE", E, scratch)
    valid("DELETE", P, scratch)

# --- malformed, cross-org and auth probes, generated from the document ---
BAD_IDS = [("not-uuid", "not-a-uuid"), ("nil", "00000000-0000-0000-0000-000000000000"),
           ("nul", "%00"), ("dots", "..%2F..%2Finternal"), ("long", "1" * 300),
           ("braced", "%7B" + str(uuid.uuid4()) + "%7D")]  # braced UUIDs parse, so use an id that does not exist
BAD_QUERY = [("limit-abc", "limit=abc", "4xx"), ("cursor-junk", "cursor=%21%21", "4xx"),
             ("cursor-short", "cursor=AAAA", "4xx"), ("unknown", "zz=1", "4xx"),
             ("limit-0", "limit=0", "4xx"), ("limit-big", "limit=100000", "4xx")]
big = '{"value": "' + (canary + "-") * (70000 // (len(canary) + 1) + 1) + '"}'
BAD_BODIES = [
    ("empty", "", "application/json"),
    ("not-json", "not json", "application/json"),
    ("array", "[]", "application/json"),
    ("wrong-type", '{"name": 5}', "application/json"),
    ("long-name", json.dumps({"name": "x" * 201}), "application/json"),
    ("unknown-field", json.dumps({"name": "g5", "value": canary}), "application/json"),
    ("truncated", '{"value": "' + canary, "application/json"),
    ("text-plain", json.dumps({"value": canary}), "text/plain"),
    ("no-ctype", json.dumps({"value": canary}), None),
    ("oversized", big, "application/json"),
]
EXTRA_BODIES = {
    "versions": [("value-int", '{"value": 5}'), ("value-array", json.dumps({"value": [canary]})),
                 ("value-extra", json.dumps({"value": canary, "x": 1})),
                 ("value-recased", json.dumps({"Value": canary})), ("value-null", '{"value": null}')],
    "agent-tokens": [("wrong-secret", json.dumps({"enrollment_secret": canary})),
                     ("token-extra", json.dumps({"enrollment_secret": canary, "agent_id": A["agent"]})),
                     ("token-empty", '{"enrollment_secret": ""}')],
    "grants": [("grant-mode", json.dumps({"secret_id": A["secret"], "mode": "reveal"})),
               ("grant-past", json.dumps({"secret_id": A["secret"], "expires_at": "2000-01-01T00:00:00Z"}))],
}

for method, tmpl, o in ops:
    oid = o["operationId"]
    if is_internal(o):
        continue
    pp, qp = params_of(o, "path"), params_of(o, "query")
    hdr = dev(A["org"]) if is_dev(o) else {}
    vb = valid_body(method, tmpl)
    # Path ids: one malformed at a time, the others org A's real ids.
    for k in pp:
        for label, bad in BAD_IDS:
            p = dict(real)
            p[k] = bad
            call(api, "malformed", oid, "%s-%s" % (k, label), method, fill(tmpl, p), body=vb, headers=hdr,
                 expect="4xx")
    # Query parameters (or an unknown one where there are none).
    if qp:
        for label, q, exp in BAD_QUERY:
            call(api, "malformed", oid, "query-" + label, method, fill(tmpl, real) + "?" + q, headers=hdr,
                 expect=exp)
    elif method == "GET":
        call(api, "malformed", oid, "query-unknown", method, fill(tmpl, real) + "?zz=1", headers=hdr,
             expect="not5xx")
    # Bodies.
    if o.get("requestBody"):
        bodies = [(l, b, c) for l, b, c in BAD_BODIES]
        for key, extra in EXTRA_BODIES.items():
            if tmpl.endswith(key):
                bodies += [(l, b, "application/json") for l, b in extra]
        for label, b, c in bodies:
            call(api, "malformed", oid, "body-" + label, method, fill(tmpl, real), body=b, ctype=c,
                 headers=hdr, expect="4xx")
    # The dev-org binding: missing, garbage, or only the agent token.
    if is_dev(o):
        for label, h in [("no-org", {}), ("garbage-org", {DEV: "not-a-uuid"}),
                         ("agent-token", {"Authorization": "Bearer " + agent_auth})]:
            call(api, "auth", oid, label, method, fill(tmpl, real), body=vb, headers=h, expect="401")
        # Cross-org: org B (and an unknown org) with org A's ids.
        for label, org in [("org-b", B["org"]), ("unknown-org", str(uuid.uuid4()))]:
            if pp:
                call(api, "cross-org", oid, label, method, fill(tmpl, real), body=vb, headers=dev(org),
                     expect="404")
            elif method == "GET":
                st, d = call(api, "cross-org", oid, label + "-list", method, tmpl, headers=dev(org),
                             expect="2xx" if label == "org-b" else "not5xx")
                text = json.dumps(d)
                if any(v in text for v in A.values()):
                    failures.append("cross-org %s %s: the response names an org A id" % (oid, label))
# A grant naming the other org's secret, both ways.
call(api, "cross-org", opid("POST", AG + "/grants"), "b-grants-a-secret", "POST",
     fill(AG + "/grants", {"agent_id": B["agent"]}), body={"secret_id": A["secret"]}, headers=dev(B["org"]),
     expect="4xx")
call(api, "cross-org", opid("POST", AG + "/grants"), "a-grants-b-secret", "POST",
     fill(AG + "/grants", {"agent_id": A["agent"]}), body={"secret_id": B["secret"]}, headers=dev(A["org"]),
     expect="4xx")
for org, other in [(B, A), (A, B)]:
    st, d = call(api, "cross-org", opid("GET", AG + "/grants"), "grants-after", "GET",
                 fill(AG + "/grants", {"agent_id": org["agent"]}), headers=dev(org["org"]))
    if other["secret"] in json.dumps(d):
        failures.append("cross-org: an agent holds a grant on the other org's secret")

# --- internal routes without the service token: always 401 ---
relay_event = {"kind": "relay.attempt", "outcome": "pending", "agent_id": A["agent"],
               "secret_id": A["secret"], "version": 1, "method": "GET", "host": "g5-probe.example"}
internal = [(m, t, o) for m, t, o in ops if is_internal(o)]
if not internal:
    failures.append("the document lists no internal routes")
for method, tmpl, o in internal:
    body = relay_event if o.get("requestBody") else None
    for label, h in [("no-auth", {SVC_ORG: A["org"]}),
                     ("wrong-bearer", {"Authorization": "Bearer not-the-service-token", SVC_ORG: A["org"]}),
                     ("empty-bearer", {"Authorization": "Bearer ", SVC_ORG: A["org"]}),
                     ("basic", {"Authorization": "Basic Zzc6Zzc=", SVC_ORG: A["org"]}),
                     ("agent-token", {"Authorization": "Bearer " + agent_auth, SVC_ORG: A["org"]}),
                     ("dev-org", {DEV: A["org"]}),
                     ("dev-org-and-agent", {DEV: A["org"], "Authorization": "Bearer " + agent_auth})]:
        call(api, "internal", o["operationId"], label, method, fill(tmpl, real), body=body, headers=h,
             expect="401")

# --- request fields that reach audit attributes: the append endpoint with the service token ---
append = opid("POST", "/internal/v1/audit/events")
svc = {"Authorization": "Bearer " + svc_auth, SVC_ORG: A["org"]}
for label, host in [("ph", "{secret}.example"), ("ph-enc", "%7Bsecret%7D.example"),
                    ("path", "g5.example/{secret}"), ("port", "g5.example:8443"),
                    ("userinfo", "{secret}@g5.example"), ("space", "g5 example"),
                    ("query", "g5.example?k={secret}")]:
    ev = dict(relay_event, host=host)
    call(api, "attrs", append, "host-" + label, "POST", "/internal/v1/audit/events", body=ev, headers=svc,
         expect="400")
call(api, "attrs", append, "url-field", "POST", "/internal/v1/audit/events",
     body=dict(relay_event, url="http://g5.example/{secret}"), headers=svc, expect="400")
call(api, "attrs", append, "method-ph", "POST", "/internal/v1/audit/events",
     body=dict(relay_event, method="{secret}"), headers=svc, expect="400")
call(api, "attrs", append, "valid", "POST", "/internal/v1/audit/events",
     body=dict(relay_event, port=8443), headers=svc, expect="201")

# --- the gateway's agent route ---
st, d = call(gw, "gateway", "gateway_grants", "agent", "GET", "/v1/grants",
             headers={"Authorization": "Bearer " + agent_auth})
text = json.dumps(d)
if A["secret"] not in text or B["secret"] in text:
    failures.append("gateway /v1/grants: expected org A's secret only")
call(gw, "gateway", "gateway_grants", "no-token", "GET", "/v1/grants", expect="401")
call(gw, "gateway", "gateway_grants", "garbage-token", "GET", "/v1/grants",
     headers={"Authorization": "Bearer not.a.token"}, expect="401")
call(gw, "gateway", "gateway_grants", "service-token", "GET", "/v1/grants",
     headers={"Authorization": "Bearer " + svc_auth}, expect="401")

# --- coverage: every operation called in each mode that applies to it ---
for method, tmpl, o in ops:
    oid = o["operationId"]
    modes = done.get(oid, set())
    if is_internal(o):
        need = {"internal"}
    else:
        need = {"valid"}
        if params_of(o, "path") or params_of(o, "query") or o.get("requestBody") or method == "GET":
            need.add("malformed")
        if is_dev(o):
            need.add("auth")
            # A create without a path id names no other-org resource; it is only valid in org B.
            if params_of(o, "path") or method == "GET":
                need.add("cross-org")
    for mode in sorted(need - modes):
        failures.append("%s %s (%s) was not called in mode %s" % (method, tmpl, oid, mode))

results.close()
for f in failures:
    print("G5: " + f, file=sys.stderr)
print("calls=%d failures=%d" % (n, len(failures)))
sys.exit(1 if failures else 0)
PY

# 2. Relays whose URL host, method and path carry fields that reach the ledger's attributes
# (host, port, method, status). `refused` is a 400 or 403 from the gateway, `sent` a 200 with
# the upstream status, `any` anything below 500.
mkdir -p "$GW_WORK/probes"
python3 -I - "$GW_WORK/probes" "$GW_SECRET_ID" "$api" <<'PY'
import json, os, sys
out, sid, api = sys.argv[1:4]
probes = []

def p(name, cls, url, method="GET", body=None):
    d = {"secret_id": sid, "version": 1, "method": method, "url": url, "headers": []}
    if body is not None:
        d["body"] = body
    probes.append((name, cls))
    with open(os.path.join(out, name + ".json"), "w") as fh:
        json.dump(d, fh)

p("attr-host-ph", "refused", "http://{secret}.invalid/g5")
p("attr-host-ph-enc", "refused", "http://%7Bsecret%7D.invalid/g5")
p("attr-host-label", "refused", "http://g5.{secret}.invalid:8443/g5")
p("attr-host-idn", "refused", "http://g5-é.invalid/g5")
p("attr-method-ph", "refused", api + "/g5/method", method="{secret}")
p("attr-get", "sent", api + "/g5/get/{secret}?g4=plain&k={secret}")
p("attr-post", "sent", api + "/g5/post?g4=plain", method="POST", body="{secret}")
p("attr-put", "sent", api + "/g5/put?g4=plain", method="PUT", body="x")
p("attr-patch", "sent", api + "/g5/patch?g4=plain", method="PATCH", body="x")
p("attr-delete", "sent", api + "/g5/delete?g4=plain", method="DELETE")
p("attr-propfind", "any", api + "/g5/propfind?g4=plain", method="PROPFIND")
with open(os.path.join(out, "manifest"), "w") as fh:
    for name, cls in probes:
        fh.write("%s %s\n" % (name, cls))
PY
sent_n=0
while read -r name cls; do
  status="$(gw_relay_raw "$name" "$GW_WORK/probes/$name.json")"
  echo "relay $name $cls gateway=$status" >>"$ARTIFACT_DIR/results.txt"
  case "$cls" in
    refused) [[ "$status" == 400 || "$status" == 403 ]] || gw_fail "$name: gateway $status (expected 400 or 403)" ;;
    sent)
      [[ "$status" == 200 ]] || gw_fail "$name: gateway $status (expected 200)"
      sent_n=$((sent_n + 1))
      ;;
    any) [[ "$status" =~ ^[1-4][0-9][0-9]$ ]] || gw_fail "$name: gateway $status (expected below 500)" ;;
  esac
done <"$GW_WORK/probes/manifest"
gw_unwrap "$ARTIFACT_DIR"/raw-attr-*.out

# 3. Both orgs' ledgers through GET /v1/audit/events: identifiers only, and no cross-org ids.
gw_ledger a
ledger_a="$GW_LEDGER"
GW_ORG="$B_ORG"
gw_ledger b
ledger_b="$GW_LEDGER"
GW_ORG="$A_ORG"
python3 -I - "$ledger_a" "$ledger_b" "$ARTIFACT_DIR/ids.json" "$sent_n" <<'PY' || gw_fail "ledger check failed"
import json, re, sys
la, lb, idf, sent = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
ids = json.load(open(idf))
LEAF = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")
HEAD = re.compile(r"^[a-z0-9_.:-]{1,200}$")
bad = []

def leaves(v, path):
    if isinstance(v, dict):
        for k, x in v.items():
            yield from leaves(x, path + [k])
    elif isinstance(v, list):
        for x in v:
            yield from leaves(x, path)
    else:
        yield path, v

def hosts(e):
    return [x for p, x in leaves(e.get("attrs") or {}, []) if "host" in p and isinstance(x, str)]

for name, f, mine, other in [("A", la, ids["a"], ids["b"]), ("B", lb, ids["b"], ids["a"])]:
    events = json.load(open(f))
    if not events:
        bad.append("org %s: empty ledger" % name)
    for e in events:
        for k in ("kind", "actor", "outcome"):
            if not isinstance(e.get(k), str) or not HEAD.match(e[k]):
                bad.append("org %s %s: `%s` is not a code or id" % (name, e.get("kind"), k))
        if e.get("target") is not None and not (isinstance(e["target"], str) and HEAD.match(e["target"])):
            bad.append("org %s %s: `target` is not a code or id" % (name, e.get("kind")))
        for path, v in leaves(e.get("attrs") or {}, []):
            key = ".".join(path)
            if isinstance(v, bool) or not (isinstance(v, int) or (isinstance(v, str) and LEAF.match(v))):
                bad.append("org %s %s: attribute %s is not an id, code, host or integer" % (name, e.get("kind"), key))
        text = json.dumps(e)
        for k, v in other.items():
            if v in text:
                bad.append("org %s %s: names the other org's %s id" % (name, e.get("kind"), k))
    if name == "A":
        hs = [h for e in events for h in hosts(e)]
        if "g5-probe.example" not in hs:
            bad.append("org A: the valid appended event with host g5-probe.example is missing")
        if "127.0.0.1" not in hs:
            bad.append("org A: no relay event carries the bound host")
        if any("secret" in h or "{" in h or "%" in h for h in hs):
            bad.append("org A: a host attribute carries a placeholder")
        attempts = sum(1 for e in events if e["kind"] == "relay.attempt" and e["actor"] == "agent:" + mine["agent"])
        if attempts < sent:
            bad.append("org A: %d relay.attempt events for %d sent relays" % (attempts, sent))
for b in bad:
    print("G5: " + b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY

# 4. The audit export, into a fresh directory; both orgs' files go to the artifacts.
if [[ -z "${LOCKSMITH_AUDIT_BIN:-}" ]]; then
  (cd "$GW_ROOT" && cargo build -q -p locksmith-audit) || gw_fail "cargo build of locksmith-audit failed"
fi
audit_bin="${LOCKSMITH_AUDIT_BIN:-${CARGO_TARGET_DIR:-$GW_ROOT/target}/debug/locksmith-audit}"
[[ -x "$audit_bin" ]] || gw_fail "missing binary $audit_bin"
export_dir="$GW_WORK/audit-export"
rc=0
(
  LOCKSMITH_AUDIT_DATABASE_URL="postgres://audit_verifier:$(gw_env LOCKSMITH_AUDIT_VERIFIER_PASSWORD)@127.0.0.1:5432/$(gw_env POSTGRES_DB)"
  export LOCKSMITH_AUDIT_DATABASE_URL
  cd "$GW_ROOT" && exec "$audit_bin" export --dir "$export_dir" --json
) >"$ARTIFACT_DIR/audit-export.out" 2>"$ARTIFACT_DIR/audit-export.err" || rc=$?
[[ $rc -eq 0 ]] || gw_fail "locksmith-audit export exited $rc (see audit-export.err)"
mkdir -p "$ARTIFACT_DIR/audit-export"
for org in "$A_ORG" "$B_ORG"; do
  [[ -d "$export_dir/$org" ]] || gw_fail "the export has no directory for org $org"
  cp -R "$export_dir/$org" "$ARTIFACT_DIR/audit-export/$org"
  compgen -G "$ARTIFACT_DIR/audit-export/$org/events-*.jsonl" >/dev/null ||
    gw_fail "the export has no event file for org $org"
done
grep -qF "agent:$GW_AGENT_ID" "$ARTIFACT_DIR/audit-export/$A_ORG"/events-*.jsonl ||
  gw_fail "org A's export lacks the agent's events"
if grep -qF "$B_SECRET" "$ARTIFACT_DIR/audit-export/$A_ORG"/events-*.jsonl ||
  grep -qF "$GW_SECRET_ID" "$ARTIFACT_DIR/audit-export/$B_ORG"/events-*.jsonl; then
  gw_fail "an org's export names the other org's secret"
fi

{
  echo "sweep: $(grep -c . "$ARTIFACT_DIR/results.txt") calls and relays recorded"
  echo "relays sent=$sent_n; ledgers A=$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$ledger_a") B=$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$ledger_b") events"
  echo "export: $(find "$ARTIFACT_DIR/audit-export" -type f | wc -l | tr -d ' ') files for orgs A and B"
} | tee "$ARTIFACT_DIR/summary.txt"
