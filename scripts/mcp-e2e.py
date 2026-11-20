#!/usr/bin/env python3
"""M1 task 4.1: a scripted MCP client signs in to the Hub `/mcp` the way the MCP authorization spec
describes and lists the tools. Needs `just up` and the control plane started with
`LOCKSMITH_MCP_RESOURCE_URL=http://127.0.0.1:8080/mcp` (`just api` sets it).

  1. an unauthenticated `initialize` gets 401 with `WWW-Authenticate: Bearer resource_metadata=...`;
  2. the protected-resource metadata (RFC 9728) names the resource and the issuer, and the issuer's
     OpenID discovery document is reachable;
  3. authorization code + PKCE (S256) with `resource=<hub MCP URI>` on the pre-registered public
     client `locksmith-mcp`; the consent screen is shown (consent is required) and approved;
  4. the access token carries the MCP audience (not the console audience) and `auth_time`;
  5. a refresh keeps `auth_time` (the revoke rule of design.md "Client binding for revoke" needs it);
  6. `initialize` + `tools/list` over Streamable HTTP with the token succeed and the list is not empty;
  7. a token minted for the console client is refused on `/mcp` (no passthrough).

No token or password is printed. Env overrides: KEYCLOAK_URL, API_URL.
"""
import base64
import hashlib
import html
import importlib.util
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("auth_e2e", os.path.join(HERE, "auth-e2e.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

KC = base.KC
API = base.API
REALM = base.REALM
CLIENT = "locksmith-mcp"
REDIRECT = "http://127.0.0.1:8765/callback"
RESOURCE = os.environ.get("MCP_RESOURCE", API + "/mcp")
USER = base.SEEDED_OK
check = base.check


def jwt_claims(tok):
    part = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def mcp(token, payload, session=None):
    """POST one JSON-RPC message to /mcp; returns (status, headers, parsed body or None)."""
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if session:
        h["Mcp-Session-Id"] = session
    req = urllib.request.Request(API + "/mcp", data=json.dumps(payload).encode(), headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        status, hdrs, text = r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        status, hdrs, text = e.code, e.headers, e.read().decode("utf-8", "replace")
    body = None
    for line in text.splitlines():
        line = line[5:].strip() if line.startswith("data:") else line.strip()
        if line.startswith("{"):
            try:
                body = json.loads(line)
            except ValueError:
                pass
    return status, hdrs, body


def hidden_form(page):
    """The action and every named input of the first form on a page."""
    act = base.form_action(page)
    fields = {}
    for m in re.finditer(r"<input[^>]*>", page):
        tag = m.group(0)
        n = re.search(r'name="([^"]+)"', tag)
        v = re.search(r'value="([^"]*)"', tag)
        t = re.search(r'type="([^"]+)"', tag)
        if n and (not t or t.group(1) in ("hidden", "submit")):
            fields.setdefault(n.group(1), html.unescape(v.group(1)) if v else "")
    return act, fields


def sign_in():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {
        "client_id": CLIENT, "response_type": "code", "scope": "openid", "redirect_uri": REDIRECT,
        "state": secrets.token_urlsafe(8), "code_challenge": challenge, "code_challenge_method": "S256",
        "resource": RESOURCE,
    }
    b = base.Browser()
    st, url, page = b.get(f"{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(q), REDIRECT)
    act = base.form_action(page or "")
    if st != 200 or not act:
        return None, None, False
    act = urllib.parse.urljoin(url, act)
    st, url, page = b.post(act, {"username": USER[0], "password": USER[1], "credentialId": ""}, REDIRECT)
    consent_shown = False
    if not url.startswith(REDIRECT):
        consent_shown = "accept" in (page or "")
        act, fields = hidden_form(page or "")
        if not act:
            return None, None, consent_shown
        act = urllib.parse.urljoin(url, act)
        fields["accept"] = fields.get("accept") or "Yes"
        st, url, page = b.post(act, fields, REDIRECT)
    code = base.code_from(url) if url.startswith(REDIRECT) else None
    if not code:
        return None, None, consent_shown
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": CLIENT, "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier, "resource": RESOURCE,
    }).encode()
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"{REALM}/protocol/openid-connect/token", data=body), timeout=30)
        tok = json.loads(r.read())
    except urllib.error.HTTPError:
        return None, None, consent_shown
    return tok.get("access_token"), tok.get("refresh_token"), consent_shown


def refresh(rt):
    body = urllib.parse.urlencode({"grant_type": "refresh_token", "client_id": CLIENT, "refresh_token": rt}).encode()
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"{REALM}/protocol/openid-connect/token", data=body), timeout=30)
        return json.loads(r.read()).get("access_token")
    except urllib.error.HTTPError:
        return None


def main():
    if not base.wait_ready():
        sys.exit("mcp-e2e: Keycloak not reachable; run `just up`")
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-e2e", "version": "0"}}}

    # 1. unauthenticated -> 401 with the RFC 9728 challenge.
    st, hdrs, _ = mcp(None, init)
    www = hdrs.get("WWW-Authenticate", "")
    m = re.search(r'resource_metadata="([^"]+)"', www)
    check("unauthenticated initialize is 401 with a resource_metadata challenge", st == 401 and bool(m), f"{st} {www}")
    if not m:
        sys.exit(1)

    # 2. metadata, then issuer discovery.
    meta = json.load(urllib.request.urlopen(m.group(1), timeout=30))
    check("protected-resource metadata names the hub MCP URI", meta.get("resource") == RESOURCE, str(meta.get("resource")))
    issuers = meta.get("authorization_servers") or []
    check("metadata lists the configured issuer", issuers == [REALM], str(issuers))
    disc = json.load(urllib.request.urlopen(issuers[0] + "/.well-known/openid-configuration", timeout=30))
    check("issuer discovery has an authorization and a token endpoint",
          "authorization_endpoint" in disc and "token_endpoint" in disc)
    check("issuer supports PKCE S256", "S256" in disc.get("code_challenge_methods_supported", []))

    # 3-4. sign in on the public client; consent is required; the token is for the MCP audience.
    tok, rt, consent = sign_in()
    check("sign-in on locksmith-mcp (code + PKCE + resource) yields an access token", bool(tok))
    check("the consent screen was shown (consent is required for MCP clients)", consent)
    if not tok:
        sys.exit(1)
    c = jwt_claims(tok)
    aud = c.get("aud")
    aud = [aud] if isinstance(aud, str) else (aud or [])
    check("token audience contains the MCP URI", RESOURCE in aud, str(aud))
    check("token is not usable on the console API (locksmith-api not in aud)", "locksmith-api" not in aud, str(aud))
    check("token carries auth_time", isinstance(c.get("auth_time"), int))
    check("token names the client (azp or client_id)", (c.get("client_id") or c.get("azp")) == CLIENT)

    # 5. a refresh keeps auth_time (decides the revoke rule, #493 option A).
    tok2 = refresh(rt) if rt else None
    check("refresh issues a new access token", bool(tok2))
    if tok2:
        c2 = jwt_claims(tok2)
        check("refresh keeps auth_time unchanged", c2.get("auth_time") == c.get("auth_time"),
              f"{c.get('auth_time')} -> {c2.get('auth_time')}")

    # 6. initialize + tools/list.
    st, hdrs, body = mcp(tok, init)
    check("initialize with the token is 200", st == 200 and bool(body and "result" in body), f"{st}")
    sid = hdrs.get("Mcp-Session-Id")
    mcp(tok, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    st, _, body = mcp(tok, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
    tools = [t.get("name") for t in ((body or {}).get("result") or {}).get("tools", [])]
    check("tools/list returns tools", st == 200 and len(tools) > 0, f"{st} {tools}")

    # 7. no passthrough: a console-audience token is refused.
    web, _ = base.sign_in(*USER)
    if web:
        st, hdrs, _ = mcp(web, init)
        check("a token minted for the console client is refused on /mcp", st == 401, str(st))
    else:
        check("could not get a console token for the passthrough check", False)

    if base.failures:
        print(f"mcp-e2e: {len(base.failures)} check(s) failed", file=sys.stderr)
        sys.exit(1)
    print("mcp-e2e: all checks passed")


if __name__ == "__main__":
    main()
