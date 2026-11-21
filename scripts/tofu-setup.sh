#!/usr/bin/env bash
# Install a pinned OpenTofu and build a local provider mirror, so `tofu init`
# works where registry.opentofu.org is unreachable (the cloud agent VM, #479).
#
# - tofu comes from the GitHub release zip, checked against its SHA256SUMS.
# - hashicorp/aws comes from releases.hashicorp.com, checked against SHA256SUMS
#   whose GPG signature must come from HashiCorp's pinned signing key.
# - The zip goes into a packed filesystem mirror; the generated CLI config makes
#   tofu install hashicorp/aws only from that mirror.
#
# Usage: bash scripts/tofu-setup.sh    -> prints the CLI config path (use as TF_CLI_CONFIG_FILE)
# Idempotent: already-verified files are reused. Downloads contain no secrets.
set -euo pipefail

TOFU_VERSION="${TOFU_VERSION:-1.10.7}"
AWS_PROVIDER_VERSION="${AWS_PROVIDER_VERSION:-6.73.0}"
# HashiCorp Security (package signing), https://www.hashicorp.com/trust/security
HASHICORP_FPR="C874011F0AB405110D02105534365D9472D7468F"

cache="${LOCKSMITH_TOFU_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/locksmith/tofu}"
bin_dir="${TOFU_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$cache" "$bin_dir"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "tofu-setup: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

fetch() { curl -fsSL --retry 3 -m 300 -o "$2" "$1"; }

sha_check() { # <sums file> <file name> <dir>
  local want
  want="$(awk -v f="$2" '$2==f {print $1}' "$1")"
  [ -n "$want" ] || { echo "tofu-setup: $2 missing from $(basename "$1")" >&2; return 1; }
  echo "$want  $3/$2" | sha256sum -c --status - 2>/dev/null \
    || echo "$want  $3/$2" | shasum -a 256 -c --status - \
    || { echo "tofu-setup: checksum mismatch for $2" >&2; return 1; }
}

# 1. OpenTofu binary.
if ! command -v tofu >/dev/null 2>&1 || ! tofu version 2>/dev/null | grep -q "^OpenTofu v${TOFU_VERSION}$"; then
  d="$cache/tofu-$TOFU_VERSION"; mkdir -p "$d"
  zip="tofu_${TOFU_VERSION}_${os}_${arch}.zip"
  base="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}"
  fetch "$base/tofu_${TOFU_VERSION}_SHA256SUMS" "$d/SHA256SUMS"
  [ -f "$d/$zip" ] || fetch "$base/$zip" "$d/$zip"
  sha_check "$d/SHA256SUMS" "$zip" "$d"
  unzip -oq "$d/$zip" tofu -d "$d"
  install -m 0755 "$d/tofu" "$bin_dir/tofu"
  echo "tofu-setup: installed tofu $TOFU_VERSION to $bin_dir" >&2
  case ":$PATH:" in *":$bin_dir:"*) ;; *) echo "tofu-setup: add $bin_dir to PATH" >&2 ;; esac
fi

# 2. hashicorp/aws provider mirror (packed layout).
mirror="$cache/mirror"
pdir="$mirror/registry.opentofu.org/hashicorp/aws"
pzip="terraform-provider-aws_${AWS_PROVIDER_VERSION}_${os}_${arch}.zip"
if [ ! -f "$pdir/$pzip" ]; then
  d="$cache/aws-$AWS_PROVIDER_VERSION"; mkdir -p "$d" "$pdir"
  base="https://releases.hashicorp.com/terraform-provider-aws/${AWS_PROVIDER_VERSION}"
  sums="terraform-provider-aws_${AWS_PROVIDER_VERSION}_SHA256SUMS"
  fetch "$base/$sums" "$d/$sums"
  fetch "$base/$sums.72D7468F.sig" "$d/$sums.sig"
  fetch "https://www.hashicorp.com/.well-known/pgp-key.txt" "$d/hashicorp.asc"
  command -v gpg >/dev/null || { echo "tofu-setup: gpg is required to verify the provider (apt install gnupg / brew install gnupg)" >&2; exit 1; }
  gh="$(mktemp -d)"; trap 'rm -rf "$gh"' EXIT
  gpg --homedir "$gh" --batch --quiet --import "$d/hashicorp.asc" 2>/dev/null
  status="$(gpg --homedir "$gh" --batch --status-fd 1 --verify "$d/$sums.sig" "$d/$sums" 2>/dev/null || true)"
  grep -q "^\[GNUPG:\] VALIDSIG .* ${HASHICORP_FPR}\$" <<<"$status" \
    || { echo "tofu-setup: SHA256SUMS signature is not from HashiCorp key $HASHICORP_FPR" >&2; exit 1; }
  [ -f "$d/$pzip" ] || fetch "$base/$pzip" "$d/$pzip"
  sha_check "$d/$sums" "$pzip" "$d"
  cp "$d/$pzip" "$pdir/$pzip"
  echo "tofu-setup: mirrored hashicorp/aws $AWS_PROVIDER_VERSION" >&2
fi

# 3. CLI config: hashicorp/aws only from the mirror, everything else direct.
rc="$cache/tofurc"
cat >"$rc" <<EOF
provider_installation {
  filesystem_mirror {
    path    = "$mirror"
    include = ["registry.opentofu.org/hashicorp/aws"]
  }
  direct {
    exclude = ["registry.opentofu.org/hashicorp/aws"]
  }
}
EOF
echo "$rc"
