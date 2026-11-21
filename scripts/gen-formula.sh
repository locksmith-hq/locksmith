#!/usr/bin/env bash
# Usage: gen-formula.sh DIR [BASE_URL] > smith.rb
# Homebrew formula from DIR/manifest.json: release URLs and SHA-256 only.
set -euo pipefail
DIR="${1:?usage: gen-formula.sh DIR [BASE_URL]}"
BASE="${2:-https://github.com/locksmith-hq/locksmith/releases/download}"
command -v jq >/dev/null 2>&1 || { echo "gen-formula: jq is required" >&2; exit 1; }
M="$DIR/manifest.json"
[ -f "$M" ] || { echo "gen-formula: $M not found" >&2; exit 1; }
ver="$(jq -r .version "$M")"
[[ "$ver" =~ ^[A-Za-z0-9._+-]+$ ]] || { echo "gen-formula: unsafe version" >&2; exit 1; }
[[ "$BASE" =~ ^https://[A-Za-z0-9./_-]+$ ]] || { echo "gen-formula: unsafe base url" >&2; exit 1; }
ent() { # triple, cpu/os guard
  local t="$1" name sha
  name="$(jq -r --arg t "$t" '.targets[$t].name // empty' "$M")"
  sha="$(jq -r --arg t "$t" '.targets[$t].sha256 // empty' "$M")"
  [ -n "$name" ] && [ -n "$sha" ] || { echo "gen-formula: manifest lacks $t" >&2; exit 1; }
  [[ "$name" =~ ^[A-Za-z0-9._+-]+$ ]] && [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "gen-formula: unsafe entry for $t" >&2; exit 1; }
  printf '      url "%s/v%s/%s"\n      sha256 "%s"\n' "$BASE" "$ver" "$name" "$sha"
}
MAC_ARM="$(ent aarch64-apple-darwin)"; MAC_X86="$(ent x86_64-apple-darwin)"
LIN_ARM="$(ent aarch64-unknown-linux-gnu)"; LIN_X86="$(ent x86_64-unknown-linux-gnu)"
cat <<RB
class Smith < Formula
  desc "Locksmith command line for AI coding agents"
  homepage "https://github.com/locksmith-hq/locksmith"
  version "$ver"
  license "Apache-2.0"

  on_macos do
    on_arm do
$MAC_ARM
    end
    on_intel do
$MAC_X86
    end
  end
  on_linux do
    on_arm do
$LIN_ARM
    end
    on_intel do
$LIN_X86
    end
  end

  def install
    bin.install Dir["smith-*"].first => "smith"
  end

  test do
    system "#{bin}/smith", "--version"
  end
end
RB
