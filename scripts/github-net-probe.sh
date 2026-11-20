#!/usr/bin/env bash
# Shows who answers GitHub requests from this machine (GitHub itself or a proxy in between), with no secrets.
# Used to debug the App token mint in cloud runs: a 403 "not permitted through this proxy" came from a proxy, not GitHub.
#   scripts/github-net-probe.sh    run it the same way locally and in a cloud environment, then compare
set -uo pipefail
# Proxy settings by name; values are cut at "@" so embedded credentials never print.
echo "== proxy env"; env | grep -iE '^(https?|all|no)_proxy=' | sed -E 's#(://)[^@/]*@#\1***@#' || echo "(none)"
echo "== git remote"; git remote get-url origin 2>/dev/null | sed -E 's#(://)[^@/]*@#\1***@#'

probe() { # <label> <curl args...>: HTTP status, server header, TLS issuer and the first 120 bytes of the body
  local out; out=$(curl -sS -m 15 -o /tmp/probe.body -D /tmp/probe.head -w '%{http_code} via %{remote_ip}' "${@:2}" 2>&1) || true
  printf '%-34s %s | server=%s | %s\n' "$1" "$out" "$(grep -i '^server:' /tmp/probe.head 2>/dev/null | tr -d '\r' | cut -d' ' -f2-)" \
    "$(head -c 120 /tmp/probe.body 2>/dev/null | tr '\n' ' ')"
}
echo "== requests (real GitHub: zen 200, app token request 401 'JSON web token', /app 401)"
probe "GET api /zen" https://api.github.com/zen
probe "POST api /app/installations/../tokens" -X POST https://api.github.com/app/installations/1/access_tokens
probe "GET api /app" https://api.github.com/app
probe "GET api /zen (no proxy)" --noproxy '*' https://api.github.com/zen
probe "POST token request (no proxy)" --noproxy '*' -X POST https://api.github.com/app/installations/1/access_tokens
probe "GET github.com git refs (no proxy)" --noproxy '*' "https://github.com/locksmith-hq/locksmith.git/info/refs?service=git-upload-pack"
echo "== TLS issuer for api.github.com (GitHub's is a public CA; a proxy's own CA means interception)"
echo | timeout 15 openssl s_client -connect api.github.com:443 -servername api.github.com 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null || echo "(no TLS handshake)"
