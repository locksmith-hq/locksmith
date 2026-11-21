#!/usr/bin/env python3
"""Helper for the remote-MCP adversarial cases (G9 agent MCP on the gateway, G10 hub MCP on the
control plane; change m1-remote-mcp, task 6.1). Run it as `python3 -I mcp_check.py <command>`.
Standard library only. It never prints a token or a secret value: output is names, ids, counts.

Commands:
  call BASE_URL AUTH_HDR_FILE CALLS_JSONL OUT_PREFIX
      MCP Streamable HTTP client. Sends `initialize` and `notifications/initialized`, then each
      line of CALLS_JSONL (a JSON-RPC request), in one session. Replies (one JSON object per line)
      go to OUT_PREFIX.out and `<id> <http status>` lines to OUT_PREFIX.http. AUTH_HDR_FILE holds
      one `Authorization: Bearer ...` line (a private file, so no token is on a command line).
      BASE_URL is the server root; the endpoint is BASE_URL/mcp. Exit 1 if `initialize` fails.
  scan-tools REPLIES_FILE [--present NAME]... [--absent NAME]... [--id ID]
      Reads a reply file written by `call`, takes the `tools/list` reply (id ID, default `list`)
      and fails when any tool input or output schema has a value-like property name or an open
      map, when a tool has no output schema, or when a --present tool is missing or an --absent
      tool is listed. The rule is the one of `ls_mcp_server::find_value_like_field`.
  scan-keys REPLIES_FILE
      Fails when a tool result (structured content, or its text when that is JSON) carries a
      value-like object key at any depth.
  words
      Prints the forbidden last words (the run_test.sh self-check compares them with the Rust list).
  hub-ready
      Exit 0 when Keycloak and the hub `/mcp` are reachable, else print why and exit 3.
  hub-token OUT_HDR_FILE | console-token OUT_HDR_FILE
      Sign in as the seeded dev user (as scripts/mcp-e2e.py does) and write the Authorization
      header to OUT_HDR_FILE (mode 0600): an MCP-audience token, or a console-audience token.
  hub-setup CANARY_FILE CONSOLE_HDR_FILE OUT_JSON
      As the person, in their personal org: a project, an environment, a secret holding the
      canary as version 1, an agent and a grant. Writes the ids (never a value) to OUT_JSON.
  ledger BASE_URL AUTH_HDR_FILE OUT_JSON
      Every page of GET /v1/audit/events with that header, as one JSON array.

Environment: API_URL (control plane, default http://127.0.0.1:8080), KEYCLOAK_URL.
"""
import importlib.util
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

# Mirrors `ls_mcp_server::FORBIDDEN_LAST_WORDS` (run_test.sh checks that the lists agree).
FORBIDDEN_LAST_WORDS = (
    "value", "values", "secret", "secrets", "password", "passwords", "passphrase", "passphrases",
    "token", "tokens", "credential", "credentials", "key", "keys", "pem", "jwt",
)

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never through a proxy


def name_words(name):
    """Mirror of `ls_mcp_server::name_words`: split on non-alphanumerics and camelCase humps."""
    words, cur = [], ""
    for i, c in enumerate(name):
        if not c.isalnum():
            if cur:
                words.append(cur)
                cur = ""
            continue
        prev = name[i - 1] if i > 0 else None
        nxt = name[i + 1] if i + 1 < len(name) else None
        hump = (
            c.isupper() and cur != ""
            and ((prev is not None and (prev.islower() or prev.isdigit()))
                 or (prev is not None and prev.isupper() and nxt is not None and nxt.islower()))
        )
        if hump:
            words.append(cur)
            cur = ""
        cur += c.lower()
    if cur:
        words.append(cur)
    return words


def is_value_like(name):
    w = name_words(name)
    return bool(w) and w[-1] in FORBIDDEN_LAST_WORDS


def find_value_like_field(schema):
    """First value-like property name (or open map) in a JSON schema, at any depth, else None."""
    if schema is True or schema == {}:
        return "open schema"
    if isinstance(schema, list):
        for v in schema:
            r = find_value_like_field(v)
            if r:
                return r
        return None
    if not isinstance(schema, dict):
        return None
    if "patternProperties" in schema:
        return "open map (patternProperties)"
    if "additionalProperties" in schema and schema["additionalProperties"] is not False:
        return "open map (additionalProperties)"
    for k, v in schema.items():
        if k == "properties" and isinstance(v, dict):
            for name, sub in v.items():
                if is_value_like(name):
                    return name
                r = find_value_like_field(sub)
                if r:
                    return r
        elif k in ("required", "enum", "const", "default", "examples", "type", "format",
                   "description", "title", "pattern", "additionalProperties"):
            continue
        else:
            r = find_value_like_field(v)
            if r:
                return r
    return None


def read_replies(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def die(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)


# --- client ------------------------------------------------------------------------------------

def auth_header(path):
    line = open(path).read().strip()
    name, _, value = line.partition(":")
    return name.strip(), value.strip()


def post(url, hdr, payload, session=None):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
         hdr[0]: hdr[1]}
    if session:
        h["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=h)
    try:
        r = OPENER.open(req, timeout=60)
        status, headers, text = r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, headers, text = e.code, e.headers, e.read().decode("utf-8", "replace")
    body = None
    for line in text.splitlines():
        line = line[5:].strip() if line.startswith("data:") else line.strip()
        if line.startswith("{"):
            try:
                body = json.loads(line)
            except ValueError:
                pass
    return status, headers, body


def cmd_call(base, hdr_file, calls_file, prefix):
    url = base.rstrip("/") + "/mcp"
    hdr = auth_header(hdr_file)
    init = {"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "adversarial", "version": "0"}}}
    out, http = open(prefix + ".out", "w"), open(prefix + ".http", "w")
    status, headers, body = post(url, hdr, init)
    http.write("init %d\n" % status)
    if body is not None:
        out.write(json.dumps(body) + "\n")
    if status != 200 or not body or "result" not in body:
        out.close()
        http.close()
        die("initialize failed with HTTP %d" % status)
    session = headers.get("Mcp-Session-Id")
    post(url, hdr, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    for line in open(calls_file):
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        status, _, body = post(url, hdr, req, session)
        http.write("%s %d\n" % (req.get("id"), status))
        if body is not None:
            out.write(json.dumps(body) + "\n")
    out.close()
    http.close()


# --- scans -------------------------------------------------------------------------------------

def cmd_scan_tools(path, args):
    present, absent, want_id = [], [], "list"
    i = 0
    while i < len(args):
        if args[i] == "--present":
            present.append(args[i + 1])
        elif args[i] == "--absent":
            absent.append(args[i + 1])
        elif args[i] == "--id":
            want_id = args[i + 1]
        else:
            die("scan-tools: unknown argument " + args[i], 2)
        i += 2
    reply = next((r for r in read_replies(path) if str(r.get("id")) == want_id), None)
    tools = ((reply or {}).get("result") or {}).get("tools")
    if not isinstance(tools, list):
        die("scan-tools: no tools/list result with id %s in %s" % (want_id, os.path.basename(path)))
    names = []
    for t in tools:
        name = t.get("name", "?")
        names.append(name)
        for key in ("inputSchema", "outputSchema"):
            schema = t.get(key)
            if schema is None:
                if key == "outputSchema":
                    die("scan-tools: tool %s has no outputSchema" % name)
                continue
            bad = find_value_like_field(schema)
            if bad:
                die("scan-tools: tool %s %s has a value-like field: %s" % (name, key, bad))
    for n in present:
        if n not in names:
            die("scan-tools: expected tool %s is not listed (listed: %s)" % (n, ", ".join(sorted(names))))
    for n in absent:
        if n in names:
            die("scan-tools: tool %s is listed but must be off" % n)
    print("tools=%d: %s" % (len(names), ",".join(sorted(names))))


def keys_of(v, path=""):
    """Every object key at any depth, with its path."""
    if isinstance(v, dict):
        for k, x in v.items():
            yield path + "/" + k, k
            yield from keys_of(x, path + "/" + k)
    elif isinstance(v, list):
        for x in v:
            yield from keys_of(x, path)


def cmd_scan_keys(path):
    n = 0
    for r in read_replies(path):
        res = r.get("result")
        if not isinstance(res, dict) or "tools" in res or "capabilities" in res:
            continue
        docs = []
        if res.get("structuredContent") is not None:
            docs.append(res["structuredContent"])
        for c in res.get("content") or []:
            try:
                docs.append(json.loads(c.get("text", "")))
            except (ValueError, TypeError, AttributeError):
                pass
        for d in docs:
            for p, k in keys_of(d):
                n += 1
                if is_value_like(k):
                    die("scan-keys: reply %s carries the value-like key %s" % (r.get("id"), p))
    print("keys scanned: %d" % n)


# --- Keycloak and the console (hub case) -------------------------------------------------------

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "scripts", filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def write_header(path, token):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("Authorization: Bearer %s\n" % token)


def cmd_hub_ready():
    kc = os.environ.get("KEYCLOAK_URL", "http://localhost:8180").rstrip("/")
    api = os.environ.get("API_URL", "http://127.0.0.1:8080").rstrip("/")
    try:
        OPENER.open(kc + "/realms/locksmith/.well-known/openid-configuration", timeout=5)
    except Exception:
        die("Keycloak at %s (just up)" % kc, 3)
    req = urllib.request.Request(api + "/mcp", data=b"{}", headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    try:
        OPENER.open(req, timeout=5)
        die("hub /mcp at %s answered without a token" % api, 1)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            die("hub /mcp at %s is not mounted (HTTP %d; the control plane needs the OIDC issuer "
                "and LOCKSMITH_MCP_RESOURCE_URL, see just api)" % (api, e.code), 3)
    except Exception:
        die("control plane at %s" % api, 3)


def cmd_token(kind, out):
    mcp = load("mcp_e2e", "mcp-e2e.py")
    if kind == "hub":
        tok, _, _ = mcp.sign_in()
    else:
        tok, _ = mcp.base.sign_in(*mcp.USER)
    if not tok:
        die("%s sign-in failed" % kind)
    write_header(out, tok)


def api_call(base, hdr, method, path, body=None):
    h = {"Accept": "application/json", hdr[0]: hdr[1]}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        r = OPENER.open(req, timeout=30)
        status, text = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode("utf-8", "replace")
    try:
        return status, json.loads(text) if text else None
    except ValueError:
        return status, None


def cmd_hub_setup(canary_file, hdr_file, out):
    base = os.environ.get("API_URL", "http://127.0.0.1:8080").rstrip("/")
    hdr = auth_header(hdr_file)
    canary = open(canary_file).read().strip()
    suffix = os.urandom(4).hex()

    def must(method, path, body, what):
        status, doc = api_call(base, hdr, method, path, body)
        if status != 201 or not isinstance(doc, dict):
            die("hub-setup: %s returned HTTP %d" % (what, status))
        return doc

    project = must("POST", "/v1/projects", {"name": "adv-g10-" + suffix}, "project")["id"]
    env = must("POST", "/v1/projects/%s/environments" % project, {"name": "adv"}, "environment")["id"]
    secrets = "/v1/projects/%s/environments/%s/secrets" % (project, env)
    secret = must("POST", secrets, {"name": "UPSTREAM_KEY"}, "secret")["id"]
    must("POST", "%s/%s/versions" % (secrets, secret), {"value": canary}, "version")
    agent_doc = must("POST", "/v1/agents", {"name": "adv-g10-" + suffix}, "agent")
    agent = agent_doc["agent"]["id"]  # the enrollment secret in agent_doc is dropped, never saved
    grant = must("POST", "/v1/agents/%s/grants" % agent, {"secret_id": secret}, "grant")["id"]
    with open(out, "w") as fh:
        json.dump({"project": project, "environment": env, "secret": secret, "agent": agent,
                   "grant": grant}, fh)


def cmd_ledger(base, hdr_file, out):
    hdr = auth_header(hdr_file)
    items, cursor = [], ""
    while True:
        q = "limit=100" + ("&cursor=" + urllib.parse.quote(cursor) if cursor else "")
        status, doc = api_call(base.rstrip("/"), hdr, "GET", "/v1/audit/events?" + q)
        if status != 200 or not isinstance(doc, dict):
            die("GET /v1/audit/events returned HTTP %d" % status)
        items += doc.get("items", [])
        cursor = doc.get("next") or ""
        if not cursor:
            break
    json.dump(items, open(out, "w"), indent=1)


def main(argv):
    if not argv:
        die(__doc__, 2)
    cmd, args = argv[0], argv[1:]
    if cmd == "call" and len(args) == 4:
        cmd_call(*args)
    elif cmd == "scan-tools" and args:
        cmd_scan_tools(args[0], args[1:])
    elif cmd == "scan-keys" and len(args) == 1:
        cmd_scan_keys(args[0])
    elif cmd == "words":
        print(" ".join(FORBIDDEN_LAST_WORDS))
    elif cmd == "hub-ready":
        cmd_hub_ready()
    elif cmd in ("hub-token", "console-token") and len(args) == 1:
        cmd_token(cmd.split("-")[0], args[0])
    elif cmd == "hub-setup" and len(args) == 3:
        cmd_hub_setup(*args)
    elif cmd == "ledger" and len(args) == 3:
        cmd_ledger(*args)
    else:
        die(__doc__, 2)


if __name__ == "__main__":
    main(sys.argv[1:])
