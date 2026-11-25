#!/usr/bin/env python3
"""OAuth provider stub for the C1 adversarial cases (G13, G14). Python 3 stdlib plus the
`openssl` CLI (key generation and RS256 signing only). Run with `python3 -I`.

  oauth_provider.py keygen DIR
      An RSA key (DIR/key.pem) and its JWKS (DIR/jwks.json, kid `adv-1`) for the human issuer.
  oauth_provider.py mint DIR ISSUER AUDIENCE SUBJECT OUT
      A human token (RS256, 10 minutes) for SUBJECT; OUT gets `Authorization: Bearer <jwt>` for
      `curl -H @OUT`, so the token is never on a command line.
  oauth_provider.py serve PORT_FILE HITS_LOG MODE_FILE CANARY_FILE KEY_DIR CLIENT_ID CLIENT_SECRET_FILE
      Serve on a free loopback port (written to PORT_FILE).

The server plays two roles on one port:
  - the human issuer: `GET /idp/jwks` (the gateway verifies the people's tokens with it);
  - the third-party provider, realm `/realms/provider` in the Keycloak layout the gateway's `mock`
    registry entry derives from LOCKSMITH_OAUTH_MOCK_ISSUER:
      GET  .../protocol/openid-connect/auth      the person's consent is implicit: a code is issued
                                                 at once and the answer is a 302 to redirect_uri
                                                 with code and state (PKCE S256 required, as the
                                                 Keycloak mock client)
      POST .../protocol/openid-connect/token     authorization_code (client credentials, the
                                                 redirect_uri and the PKCE verifier are checked;
                                                 a code is single use once exchanged) and
                                                 refresh_token. The access and the refresh token
                                                 are both the case canary.
      POST .../protocol/openid-connect/revoke    RFC 7009
      GET  .../protocol/openid-connect/userinfo  {sub, email} for the canary bearer
    and its API, on the same host (the registry entry's only API host):
      GET  /api/me     200 {"ok": true} for the canary bearer, 401 otherwise
      GET  /api/echo   for the canary bearer, reflects the bearer it received in the body (plain,
                       base64, base64url, hex, percent and JSON-escaped) and in X-Echo-* headers,
                       as a hostile or careless provider could; the gateway must redact it

MODE_FILE (re-read per request), first line:
  normal                 as above
  short                  the code exchange answers expires_in 30 (inside the gateway's 60 s
                         refresh window, so the first relay refreshes); refreshes answer 3600
  redirect-302 / redirect-307
                         the token endpoint answers that status with `Location:` the second line
                         of MODE_FILE (an internal address); nothing else
HITS_LOG gets one JSON line per request: the route and booleans or short labels (client_ok,
pkce = ok|missing|wrong|none, bearer_ok, token_ok, ...). Never a token, code, verifier, state or
client secret: the oracle scans this log too.
"""
import base64
import hashlib
import http.server
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse

KID = "adv-1"
REALM = "/realms/provider/protocol/openid-connect"


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def keygen(d):
    os.makedirs(d, exist_ok=True)
    key = os.path.join(d, "key.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", key], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(key, 0o600)
    out = subprocess.run(["openssl", "rsa", "-in", key, "-noout", "-modulus"], check=True,
                         capture_output=True, text=True).stdout.strip()
    n = bytes.fromhex(out.split("=", 1)[1])
    jwks = {"keys": [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256",
                      "n": b64url(n), "e": "AQAB"}]}
    with open(os.path.join(d, "jwks.json"), "w") as fh:
        json.dump(jwks, fh)


def mint(d, issuer, audience, subject, out):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    claims = {"iss": issuer, "aud": audience, "sub": subject, "iat": now, "nbf": now - 5,
              "exp": now + 600, "email": subject + "@example.test", "email_verified": True}
    signing = (b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(claims).encode())).encode()
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", os.path.join(d, "key.pem")],
                         input=signing, check=True, capture_output=True).stdout
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("Authorization: Bearer %s.%s\n" % (signing.decode(), b64url(sig)))


def serve(port_file, hits_log, mode_file, canary_file, key_dir, client_id, secret_file):
    canary = open(canary_file).read().strip()
    client_secret = open(secret_file).read().strip()
    jwks = open(os.path.join(key_dir, "jwks.json"), "rb").read()
    codes = {}  # code -> {challenge, method, redirect_uri}
    lock = threading.Lock()

    def mode():
        try:
            lines = open(mode_file).read().splitlines()
        except OSError:
            lines = []
        return (lines[0].strip() if lines else "normal") or "normal", (lines[1].strip() if len(lines) > 1 else "")

    def hit(**kw):
        with lock, open(hits_log, "a") as fh:
            fh.write(json.dumps(kw, sort_keys=True) + "\n")

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, status, body=b"", ctype="application/json", headers=()):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", ctype)
            self.send_header("cache-control", "no-store")
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def bearer_ok(self):
            v = self.headers.get("authorization", "")
            scheme, _, tok = v.partition(" ")
            return scheme.lower() == "bearer" and secrets.compare_digest(tok.strip(), canary)

        def form(self):
            n = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            return {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

        def client_ok(self, f):
            cid, sec = f.get("client_id"), f.get("client_secret")
            auth = self.headers.get("authorization", "")
            if auth.lower().startswith("basic "):
                try:
                    u, _, p = base64.b64decode(auth[6:]).decode().partition(":")
                    cid, sec = urllib.parse.unquote(u), urllib.parse.unquote(p)
                except ValueError:
                    return False
            return cid == client_id and sec is not None and secrets.compare_digest(sec, client_secret)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
            if u.path == "/idp/jwks":
                return self.reply(200, jwks)
            if u.path == REALM + "/auth":
                return self.authorize(q)
            if u.path == REALM + "/userinfo":
                ok = self.bearer_ok()
                hit(route="userinfo", bearer_ok=ok)
                if not ok:
                    return self.reply(401, {"error": "invalid_token"})
                return self.reply(200, {"sub": "adv-account-1", "email": "adv-account@example.test"})
            if u.path == "/api/me":
                ok = self.bearer_ok()
                hit(route="api-me", bearer_ok=ok)
                if not ok:
                    return self.reply(401, {"error": "invalid_token"})
                return self.reply(200, {"ok": True, "who": "adv-account-1"})
            if u.path == "/api/echo":
                ok = self.bearer_ok()
                hit(route="api-echo", bearer_ok=ok)
                if not ok:
                    return self.reply(401, {"error": "invalid_token"})
                got = self.headers.get("authorization", "").partition(" ")[2].strip()
                forms = {
                    "plain": got,
                    "base64": base64.b64encode(got.encode()).decode(),
                    "base64url": base64.urlsafe_b64encode(got.encode()).decode(),
                    "hex": got.encode().hex(),
                    "percent": urllib.parse.quote(got, safe=""),
                    "header": self.headers.get("authorization", ""),
                }
                body = json.dumps({"echo": forms, "json": json.dumps(got)}).encode()
                hdrs = [("x-echo-plain", got), ("x-echo-b64", forms["base64"]), ("x-echo-hex", forms["hex"])]
                return self.reply(200, body, headers=hdrs)
            hit(route="unknown-get")
            return self.reply(404, {"error": "not_found"})

        def authorize(self, q):
            redirect_uri, state = q.get("redirect_uri"), q.get("state")
            method, challenge = q.get("code_challenge_method"), q.get("code_challenge")
            hit(route="authorize", client_ok=q.get("client_id") == client_id,
                response_type=q.get("response_type"), challenge_method=method or "none",
                challenge_len=len(challenge or ""), has_state=bool(state), scope=q.get("scope", ""),
                has_verifier="code_verifier" in q)
            if not redirect_uri or q.get("client_id") != client_id:
                return self.reply(400, {"error": "invalid_request"})
            sep = "&" if urllib.parse.urlsplit(redirect_uri).query else "?"
            if method != "S256" or not challenge or q.get("response_type") != "code":
                loc = redirect_uri + sep + urllib.parse.urlencode({"error": "invalid_request", "state": state or ""})
                return self.reply(302, headers=[("location", loc)])
            code = secrets.token_urlsafe(24)
            with lock:
                codes[code] = {"challenge": challenge, "redirect_uri": redirect_uri}
            loc = redirect_uri + sep + urllib.parse.urlencode({"code": code, "state": state or ""})
            return self.reply(302, headers=[("location", loc)])

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            f = self.form()
            if u.path == REALM + "/token":
                return self.token(f)
            if u.path == REALM + "/revoke":
                tok = f.get("token", "")
                hit(route="revoke", client_ok=self.client_ok(f), hint=f.get("token_type_hint", ""),
                    token_ok=bool(tok) and secrets.compare_digest(tok, canary))
                return self.reply(200, b"")
            hit(route="unknown-post")
            return self.reply(404, {"error": "not_found"})

        def token(self, f):
            m, target = mode()
            grant = f.get("grant_type", "")
            client = self.client_ok(f)
            if m in ("redirect-302", "redirect-307"):
                hit(route="token", grant=grant, mode=m, client_ok=client)
                return self.reply(int(m[-3:]), headers=[("location", target)])
            if grant == "authorization_code":
                code = f.get("code", "")
                with lock:
                    entry = codes.get(code)
                verifier = f.get("code_verifier")
                if entry is None:
                    pkce = "none"
                elif not verifier:
                    pkce = "missing"
                elif secrets.compare_digest(b64url(hashlib.sha256(verifier.encode()).digest()), entry["challenge"]):
                    pkce = "ok"
                else:
                    pkce = "wrong"
                redirect_ok = entry is not None and f.get("redirect_uri") == entry["redirect_uri"]
                hit(route="token", grant=grant, mode=m, client_ok=client, code_known=entry is not None,
                    pkce=pkce, redirect_ok=redirect_ok)
                if not client:
                    return self.reply(401, {"error": "invalid_client"})
                if pkce != "ok" or not redirect_ok:
                    # The code stays valid: only the right verifier from the right client redeems it.
                    return self.reply(400, {"error": "invalid_grant"})
                with lock:
                    codes.pop(code, None)
                expires = 30 if m == "short" else 3600
                return self.reply(200, {"access_token": canary, "refresh_token": canary,
                                        "token_type": "Bearer", "expires_in": expires,
                                        "scope": "openid offline_access"})
            if grant == "refresh_token":
                tok = f.get("refresh_token", "")
                ok = bool(tok) and secrets.compare_digest(tok, canary)
                hit(route="token", grant=grant, mode=m, client_ok=client, token_ok=ok)
                if not client:
                    return self.reply(401, {"error": "invalid_client"})
                if not ok:
                    return self.reply(400, {"error": "invalid_grant"})
                return self.reply(200, {"access_token": canary, "refresh_token": canary,
                                        "token_type": "Bearer", "expires_in": 3600,
                                        "scope": "openid offline_access"})
            hit(route="token", grant=grant or "none", mode=m, client_ok=client)
            return self.reply(400, {"error": "unsupported_grant_type"})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    with open(port_file, "w") as fh:
        fh.write(str(srv.server_address[1]))
    srv.serve_forever()


def main(argv):
    if argv[:1] == ["keygen"] and len(argv) == 2:
        keygen(argv[1])
    elif argv[:1] == ["mint"] and len(argv) == 6:
        mint(*argv[1:6])
    elif argv[:1] == ["serve"] and len(argv) == 8:
        serve(*argv[1:8])
    else:
        sys.exit(__doc__.split("\n\n")[0])


if __name__ == "__main__":
    main(sys.argv[1:])
