#!/usr/bin/env python3
"""T1 auth end to end against the local Keycloak (`just up`) and the control plane (`just api`).

Drives the real browser flows with plain HTTP (cookie jar, HTML form scraping), no password grant:
  1. sign-up through the registration page (email as username), verification mail read from the
     mailpit API, the link followed;
  2. sign-in with authorization code + PKCE (S256) on the public `locksmith-web` client;
  3. the access token calls GET /v1/projects: 200 with it, 401 without, 401 with a tampered one;
  4. password reset through the "forgot password" page and its mail, then sign-in with the new
     password and the old one refused;
  5. the seeded verified user signs in and gets 200; the seeded unverified user is held at the
     verify-email step (no code issued);
  6. social: `kc_idp_hint=github|google` reaches the broker redirect and the provider's authorize
     URL carrying the placeholder client id. LIMIT: there is no mock Google/GitHub IdP, so the
     provider's own login and the callback are not exercised (the real providers need real
     client credentials and public callback URLs);
  7. the `smith-cli` device grant starts (PKCE S256 required) and issues a user code; the approval
     step needs a browser session and is not driven.

Tokens and passwords are never printed; only the fixed test-user passwords exist, as fixtures.
Env overrides: KEYCLOAK_URL, MAILPIT_URL, API_URL.
"""
import base64
import hashlib
import html
import http.cookiejar
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC = os.environ.get("KEYCLOAK_URL", "http://localhost:8180").rstrip("/")
MAIL = os.environ.get("MAILPIT_URL", "http://127.0.0.1:8025").rstrip("/")
API = os.environ.get("API_URL", "http://127.0.0.1:8080").rstrip("/")
REALM = f"{KC}/realms/locksmith"
CLIENT = "locksmith-web"
REDIRECT = "http://localhost:5173/callback"
# Fixtures: the realm's seeded users and the passwords the script gives its own sign-ups.
SEEDED_OK = ("alice@locksmith.test", "alice-dev-only")
SEEDED_UNVERIFIED = ("bob@locksmith.test", "bob-dev-only")
PW1, PW2 = "e2e-first-pw-dev-only", "e2e-second-pw-dev-only"

failures = []


def check(name, ok, extra=""):
    print(f"{'ok  ' if ok else 'FAIL'} {name}{(' - ' + extra) if extra and not ok else ''}")
    if not ok:
        failures.append(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Browser:
    """A cookie-keeping client that follows redirects by hand, so it can stop at the redirect URI."""

    def __init__(self):
        # Keycloak marks its cookies Secure even on http://localhost (browsers allow that).
        self.jar = http.cookiejar.CookieJar(http.cookiejar.DefaultCookiePolicy(secure_protocols=("http", "https")))
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect
        )

    def req(self, url, data=None, headers=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        r = urllib.request.Request(url, data=body, headers=headers or {})
        try:
            resp = self.op.open(r, timeout=30)
        except urllib.error.HTTPError as e:
            resp = e
        return resp.status, resp.headers.get("Location"), resp.read().decode("utf-8", "replace")

    def get(self, url, stop_prefix=REDIRECT):
        """GET, following redirects until a non-redirect or one that leaves for `stop_prefix`."""
        for _ in range(15):
            status, loc, body = self.req(url)
            if status in (301, 302, 303, 307) and loc:
                url = urllib.parse.urljoin(url, loc)
                if url.startswith(stop_prefix):
                    return status, url, ""
                continue
            return status, url, body
        raise RuntimeError("too many redirects")

    def post(self, url, data, stop_prefix=REDIRECT):
        status, loc, body = self.req(url, data)
        if status in (301, 302, 303, 307) and loc:
            nxt = urllib.parse.urljoin(url, loc)
            if nxt.startswith(stop_prefix):
                return status, nxt, ""
            return self.get(nxt, stop_prefix)
        return status, url, body


def form_action(page):
    m = re.search(r'<form[^>]*\saction="([^"]+)"', page)
    return html.unescape(m.group(1)) if m else None


def pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def auth_url(challenge, extra=None):
    q = {
        "client_id": CLIENT, "response_type": "code", "scope": "openid email profile",
        "redirect_uri": REDIRECT, "state": secrets.token_urlsafe(8), "nonce": secrets.token_urlsafe(8),
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    q.update(extra or {})
    return f"{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(q)


def exchange(code, verifier):
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": CLIENT, "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
    }).encode()
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"{REALM}/protocol/openid-connect/token", data=body), timeout=30)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}


def code_from(url):
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("code", [None])[0]


def sign_in(email, password):
    """Auth code + PKCE. Returns (access_token or None, last page body)."""
    verifier, challenge = pkce()
    b = Browser()
    st, url, page = b.get(auth_url(challenge))
    act = form_action(page or "")
    if st != 200 or not act:
        return None, page or ""
    st, url, page = b.post(act, {"username": email, "password": password, "credentialId": ""})
    code = code_from(url) if url.startswith(REDIRECT) else None
    if not code:
        return None, page
    st, tok = exchange(code, verifier)
    return (tok.get("access_token") if st == 200 else None), ""


def api(path, token=None):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = urllib.request.urlopen(urllib.request.Request(API + path, headers=h), timeout=30)
        return r.status
    except urllib.error.HTTPError as e:
        return e.code


def mail_link(to, subject_part, since):
    """The action link from the newest mail to `to` whose subject has `subject_part`."""
    deadline = time.time() + 30
    while time.time() < deadline:
        q = urllib.parse.quote(f"to:{to}")
        msgs = json.load(urllib.request.urlopen(f"{MAIL}/api/v1/search?query={q}", timeout=10)).get("messages", [])
        msgs = [m for m in msgs if subject_part.lower() in m["Subject"].lower() and m["ID"] not in since]
        if msgs:
            mid = msgs[0]["ID"]
            text = json.load(urllib.request.urlopen(f"{MAIL}/api/v1/message/{mid}", timeout=10))["Text"]
            m = re.search(r"https?://\S+action-token\S+", text)
            since.add(mid)
            return html.unescape(m.group(0)) if m else None
        time.sleep(1)
    return None


def wait_ready():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{REALM}/.well-known/openid-configuration", timeout=5)
            urllib.request.urlopen(f"{MAIL}/api/v1/info", timeout=5)
            return True
        except Exception:
            time.sleep(2)
    return False


def main():
    if not wait_ready():
        sys.exit("auth-e2e: Keycloak or mailpit not reachable; run `just up` (not `just up-lite`)")
    if api("/v1/projects") not in (401, 403):
        sys.exit("auth-e2e: the control plane is not answering on " + API + "; run `just api`")
    seen = set()
    email = f"e2e-{secrets.token_hex(4)}@locksmith.test"

    # 1. sign-up through the registration page.
    verifier, challenge = pkce()
    b = Browser()
    st, url, page = b.get(auth_url(challenge))
    reg = re.search(r'href="([^"]*registration[^"]*)"', page)
    st, url, page = b.get(urllib.parse.urljoin(url, html.unescape(reg.group(1)))) if reg else (0, url, "")
    act = form_action(page)
    check("registration page offered", bool(act))
    st, url, page = b.post(act, {
        "email": email, "firstName": "E2E", "lastName": "User", "password": PW1, "password-confirm": PW1,
    })
    check("sign-up lands on verify-email (no code before verification)",
          not url.startswith(REDIRECT) and "verif" in page.lower())

    # 2. verify through the mailed link, then sign in with auth code + PKCE.
    link = mail_link(email, "verify", seen)
    check("verification mail arrived with an action link", bool(link))
    if link:
        vb = Browser()
        st, url, page = vb.get(link)
        # The action-token page asks for one more click ("Click here to proceed").
        go = re.search(r'<a[^>]*href="([^"]+)"[^>]*>\s*(?:&raquo;\s*)?»?\s*Click here to proceed', page) or \
            re.search(r'href="([^"]*action-token[^"]*)"', page)
        if go:
            st, url, page = vb.get(urllib.parse.urljoin(url, html.unescape(go.group(1))))
        check("verification link accepted", bool(go) and st == 200 and "verified" in page.lower(), f"status {st}")
    token, _ = sign_in(email, PW1)
    check("sign-in (auth code + PKCE) after verification returns an access token", bool(token))

    # 3. control plane with and without the token.
    check("API with the token: 200 (user and personal org created on first sign-in)",
          api("/v1/projects", token) == 200 if token else False)
    check("API without a token: 401", api("/v1/projects") == 401)
    if token:
        h, p, s = token.split(".")
        check("API with a tampered token: 401", api("/v1/projects", f"{h}.{p}.{s[:-4]}AAAA") == 401)

    # 4. password reset through the mailed link.
    b = Browser()
    st, url, page = b.get(auth_url(pkce()[1]))
    fp = re.search(r'href="([^"]*reset-credentials[^"]*)"', page)
    st, url, page = b.get(urllib.parse.urljoin(url, html.unescape(fp.group(1)))) if fp else (0, url, "")
    act = form_action(page)
    check("forgot-password page offered", bool(act))
    if act:
        b.post(act, {"username": email})
        link = mail_link(email, "password", seen)
        check("reset mail arrived with an action link", bool(link))
        if link:
            st, url, page = b.get(link)
            act = form_action(page)
            check("reset link opens the update-password form", bool(act) and "password-new" in page)
            if act:
                b.post(act, {"password-new": PW2, "password-confirm": PW2})
    t_old, _ = sign_in(email, PW1)
    t_new, _ = sign_in(email, PW2)
    check("old password refused after reset", t_old is None)
    check("sign-in with the new password works and API answers 200",
          bool(t_new) and api("/v1/projects", t_new) == 200)

    # 5. seeded users.
    t, _ = sign_in(*SEEDED_OK)
    check("seeded verified user: sign-in and API 200", bool(t) and api("/v1/projects", t) == 200)
    t, page = sign_in(*SEEDED_UNVERIFIED)
    check("seeded unverified user: no token before email verification", t is None and "verif" in page.lower())

    # 6. social: the hint reaches the broker, which redirects to the provider.
    for idp, host in (("github", "github.com"), ("google", "accounts.google.com")):
        b = Browser()
        st, loc, _ = b.req(auth_url(pkce()[1], {"kc_idp_hint": idp}))
        broker = urllib.parse.urljoin(REALM + "/", loc) if loc else ""
        check(f"kc_idp_hint={idp} redirects to the Keycloak broker endpoint", f"/broker/{idp}/login" in broker)
        if f"/broker/{idp}/login" in broker:
            st, loc, _ = b.req(broker)
            q = urllib.parse.parse_qs(urllib.parse.urlparse(loc or "").query)
            check(f"broker redirects to {host} with the placeholder client id",
                  (loc or "").startswith("https://" + host) and q.get("client_id") == ["placeholder"])

    # 7. the CLI client's device grant is enabled (RFC 8628 start; the approval step is manual).
    try:
        body = urllib.parse.urlencode({"client_id": "smith-cli", "scope": "openid", "code_challenge": pkce()[1], "code_challenge_method": "S256"}).encode()
        r = urllib.request.urlopen(urllib.request.Request(f"{REALM}/protocol/openid-connect/auth/device", data=body), timeout=30)
        d = json.loads(r.read())
        check("smith-cli device authorization grant issues a user code", "user_code" in d and "device_code" in d)
    except urllib.error.HTTPError:
        check("smith-cli device authorization grant issues a user code", False)

    if failures:
        print(f"auth-e2e: {len(failures)} check(s) failed", file=sys.stderr)
        sys.exit(1)
    print("auth-e2e: all checks passed")


if __name__ == "__main__":
    main()
