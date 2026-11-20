#!/usr/bin/env bash
# Runs a scheduled agent as its GitHub App persona instead of the owner's account (owner decision 2026-11-18).
#   agent-identity.sh setup <persona>   git author, push credentials and a gh shim; on any failure undoes them, prints FAIL and exits 1
#   agent-identity.sh token             prints a valid installation token (cached, re-minted after 50 minutes)
#   agent-identity.sh credential get    git credential helper
#   agent-identity.sh selftest          offline checks
# The key comes from AGENT_APP_KEY_<PERSONA> (base64 of the PEM; in the cloud an environment variable of that
# routine's own environment, owner decision 2026-11-20) or, on macOS, the login Keychain item
# "locksmith-agent-<persona>" (same base64). A network secret cannot do it: the JWT that the token request needs
# expires within 10 minutes, so it is signed here on every mint. Never print the key or the token.
set -uo pipefail
repo=locksmith-hq/locksmith
state="${AGENT_ID_DIR:-$HOME/.config/locksmith-agent}"
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

ids() { # <persona> -> "app_id installation_id bot_user_id" (none of these is secret)
  [ -n "${AGENT_APP_IDS:-}" ] && { echo "$AGENT_APP_IDS"; return; }  # a new App (e.g. research) before it gets a row here
  case "$1" in
    linus) echo "5817262 183325623 358305577" ;;
    alfie) echo "5817280 183325819 358306025" ;;
    josie) echo "5817281 183325900 358306063" ;;
    harriet) echo "5817284 183325994 358306137" ;;
    walt) echo "5817292 183326090 358306238" ;;
    ada) echo "5853454 184141394 359289580" ;;
    *) return 1 ;;
  esac
}
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
jwt() { # <app_id> <pem-file>
  local now h p
  now=$(date +%s)
  h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  p=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' $((now - 30)) $((now + 300)) "$1" | b64url)
  printf '%s.%s.%s' "$h" "$p" "$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$2" | b64url)"
}
token() {
  local persona row app inst _ var key pem auth=() t resp code
  persona=$(cat "$state/persona" 2>/dev/null) || return 1
  if [ -f "$state/token" ] && [ $(($(date +%s) - $(cat "$state/minted" 2>/dev/null || echo 0))) -lt 3000 ]; then
    cat "$state/token"; return 0
  fi
  row=$(ids "$persona") || return 1
  read -r app inst _ <<<"$row"
  var="AGENT_APP_KEY_$(tr '[:lower:]' '[:upper:]' <<<"$persona")"
  # Each failure records its cause in $state/why, so the WARN line says what to fix.
  key="${!var:-}"
  [ -n "$key" ] || ! command -v security >/dev/null || key=$(security find-generic-password -s "locksmith-agent-$persona" -w 2>/dev/null)
  [ -n "$key" ] || { why "$var is not set in this environment"; return 1; }
  pem=$(umask 077 && mktemp) || return 1
  printf '%s' "$key" | openssl base64 -d -A >"$pem" 2>/dev/null
  grep -q 'PRIVATE KEY' "$pem" || { rm -f "$pem"; why "$var is not the base64 of a private key file (${#key} characters)"; return 1; }
  auth=(-H "Authorization: Bearer $(jwt "$app" "$pem")")
  rm -f "$pem"
  # --noproxy: the cloud session proxy (HTTPS_PROXY) refuses App API paths with 403; GitHub itself is reachable directly.
  resp=$(curl -sS --noproxy '*' -w '\n%{http_code}' -X POST ${auth[@]+"${auth[@]}"} -H "Accept: application/vnd.github+json" \
    "https://api.github.com/app/installations/$inst/access_tokens" 2>/dev/null) || { why "cannot reach api.github.com (curl exit $?)"; return 1; }
  code=${resp##*$'\n'}
  t=$(jq -r '.token // empty' <<<"${resp%$'\n'*}" 2>/dev/null)
  [ -n "$t" ] || { why "GitHub answered HTTP $code to the token request: $(jq -r '.message // "no message"' <<<"${resp%$'\n'*}" 2>/dev/null | head -c 120)"; return 1; }
  (umask 077 && printf '%s' "$t" >"$state/token" && date +%s >"$state/minted")
  printf '%s' "$t"
}
why() { printf '%s' "$1" >"$state/why"; }
fail() { # <reason>: undo everything and fail: a run must never act as the owner by accident
  if [ -f "$state/git" ]; then # only undo git settings this script made
    git config --local --unset-all credential.https://github.com.helper 2>/dev/null
    git config --local --unset remote.origin.pushurl 2>/dev/null
    git config --local --unset http.https://github.com/.proxy 2>/dev/null
    git config --local --unset user.name 2>/dev/null; git config --local --unset user.email 2>/dev/null
  fi
  [ -f "$state/shim" ] && rm -f "$(cat "$state/shim")"
  rm -rf "$state"
  echo "FAIL identity: $1"
  exit 1
}
setup() {
  local persona="$1" row _ uid real dir shim=""
  row=$(ids "$persona") || { echo "FAIL identity: unknown persona '$persona'"; exit 1; }
  read -r _ _ uid <<<"$row"
  (umask 077 && mkdir -p "$state") && printf '%s' "$persona" >"$state/persona"
  token >/dev/null || fail "$(cat "$state/why" 2>/dev/null || echo "no working key for $persona")"

  # gh: a shim earlier on PATH adds the app token, so every later `gh` call inside this checkout acts as the app.
  # Outside it the shim passes through, so on a shared machine (the owner's Mac) the owner's own gh is unchanged.
  real=$(command -v gh) || fail "gh not found"
  IFS=: read -ra dirs <<<"$PATH"
  for dir in "${dirs[@]}"; do
    [ "$dir" = "$(dirname "$real")" ] && break
    [ -d "$dir" ] && [ -w "$dir" ] && { shim="$dir/gh"; break; }
  done
  [ -n "$shim" ] || fail "no writable PATH directory before $real for the gh shim"
  shim_text "$real" "$(git rev-parse --show-toplevel)" >"$shim"
  chmod +x "$shim"; printf '%s' "$shim" >"$state/shim"; hash -r
  [ "$(gh api /installation/repositories -q '.repositories[0].full_name' 2>/dev/null)" = "$repo" ] ||
    fail "the app token is not accepted through this network"

  # git: commits and pushes as the app. Fetch keeps the remote the session came with.
  : >"$state/git"
  git config --local user.name "locksmith-${persona}[bot]"
  git config --local user.email "$uid+locksmith-${persona}[bot]@users.noreply.github.com"
  git config --local credential.https://github.com.helper ""
  git config --local --add credential.https://github.com.helper "!bash $self credential"
  git config --local remote.origin.pushurl "https://github.com/$repo.git"
  git config --local http.https://github.com/.proxy ""  # straight to GitHub with the app token, not the session proxy
  GIT_TERMINAL_PROMPT=0 git ls-remote --heads "https://github.com/$repo.git" main >/dev/null 2>&1 ||
    fail "git cannot reach github.com with the app token"
  echo "OK identity: locksmith-${persona}[bot]"
}
shim_text() { # <real gh> <checkout root>
  # shellcheck disable=SC2016  # the shim expands these at run time
  printf '#!/usr/bin/env bash\ncase "$(pwd -P)/" in %q/*) t=$(AGENT_ID_DIR=%q bash %q token 2>/dev/null) && export GH_TOKEN="$t" NO_PROXY="${NO_PROXY:+$NO_PROXY,}api.github.com,github.com" no_proxy="${no_proxy:+$no_proxy,}api.github.com,github.com" ;; esac\nexec %q "$@"\n' \
    "$2" "$state" "$self" "$1"
}
selftest() {
  local d h p s
  d=$(mktemp -d)
  # shellcheck disable=SC2064  # expand now: d is local and gone by the time the trap runs
  trap "rm -rf '$d'" EXIT
  openssl genrsa -out "$d/k.pem" 2048 2>/dev/null; openssl rsa -in "$d/k.pem" -pubout -out "$d/k.pub" 2>/dev/null
  IFS=. read -r h p s <<<"$(jwt 42 "$d/k.pem")"
  pad() { local x; x=$(tr '_-' '/+' <<<"$1"); while [ $((${#x} % 4)) -ne 0 ]; do x="$x="; done; printf '%s' "$x"; }
  [ "$(pad "$p" | openssl base64 -d -A | jq -r .iss)" = 42 ] || { echo "selftest: bad payload"; exit 1; }
  pad "$s" | openssl base64 -d -A >"$d/sig"
  printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -verify "$d/k.pub" -signature "$d/sig" >/dev/null || { echo "selftest: bad signature"; exit 1; }
  ids alfie >/dev/null || { echo "selftest: persona table"; exit 1; }
  if ids nobody >/dev/null 2>&1; then echo "selftest: unknown persona accepted"; exit 1; fi
  state="$d/s"; mkdir "$state"; printf alfie >"$state/persona"
  if (AGENT_APP_KEY_ALFIE=$(printf 'not a key' | openssl base64 -A) token >/dev/null 2>&1); then echo "selftest: token from a bad key"; exit 1; fi
  grep -q 'not the base64 of a private key' "$state/why" || { echo "selftest: bad-key cause not recorded"; exit 1; }
  # the shim adds the token only inside its checkout
  printf '%s' tok >"$state/token"; date +%s >"$state/minted"
  # shellcheck disable=SC2016  # expands inside the fake gh
  printf '#!/usr/bin/env bash\necho "${GH_TOKEN:-none}"\n' >"$d/realgh"; chmod +x "$d/realgh"
  mkdir -p "$d/repo/sub" "$d/other"; shim_text "$d/realgh" "$(cd "$d/repo" && pwd -P)" >"$d/gh"; chmod +x "$d/gh"
  [ "$(cd "$d/repo/sub" && GH_TOKEN='' "$d/gh")" = tok ] || { echo "selftest: shim inside checkout"; exit 1; }
  [ "$(cd "$d/other" && GH_TOKEN='' "$d/gh")" = none ] || { echo "selftest: shim outside checkout"; exit 1; }
  [ -z "$(env -i HOME="$d" PATH="$PATH" AGENT_APP_KEY_JOSIE=x AGENT_APP_KEY_WALT=x bash "$self" persona)" ] || { echo "selftest: two keys picked one"; exit 1; }
  echo "agent-identity selftest: OK"
}

case "${1:-}" in
  setup) setup "${2:?usage: agent-identity.sh setup <persona>}" ;;
  token) token ;;
  credential) [ "${2:-}" = get ] && t=$(token) && printf 'username=x-access-token\npassword=%s\n' "$t" ;;
  selftest) selftest ;;
  *) echo "usage: agent-identity.sh setup <persona> | token | credential get | selftest" >&2; exit 2 ;;
esac
