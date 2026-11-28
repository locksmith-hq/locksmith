# Install and verify `smith`

Every release is signed twice, so you can check what you run without trusting where you downloaded it.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/locksmith-hq/locksmith/main/scripts/install.sh | bash
# or pin a version and directory:
bash install.sh --version X.Y.Z --dir ~/.local/bin
```

The installer needs `curl`, `minisign`, `jq` (or `python3`) and `sha256sum` (or `shasum`). It verifies the minisign signature of `manifest.json` and the SHA-256 of the binary before installing, and stops (it never skips) if it cannot verify. It installs only the binary and reads no credential files. Each release also builds a Homebrew formula (`smith.rb`, from `scripts/gen-formula.sh`) as a release artifact. Until the owner publishes it to a tap repository, install with `install.sh`; once a tap exists, `brew install <tap>/smith`.

## Verify a release by hand

Download the release assets into one directory, then:

```sh
# 1. minisign: signature of the manifest, with the key embedded in smith
minisign -V -m manifest.json -x manifest.json.minisig -P "$(cat crates/ls-update/update-pubkey.txt)"

# 2. checksums: every archive against manifest.json
sha256sum -c <(jq -r '.targets[] | "\(.sha256)  \(.name)"' manifest.json)

# 3. cosign keyless: the manifest was signed by the release workflow
cosign verify-blob manifest.json --bundle manifest.json.bundle \
  --certificate-identity-regexp '^https://github.com/locksmith-hq/locksmith/\.github/workflows/release\.yml@refs/tags/.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 4. provenance: binds the asset to the commit and workflow
gh attestation verify <archive> --repo locksmith-hq/locksmith
```

`scripts/verify-release.sh <dir>` runs the whole set and exits non-zero, naming the asset, on any failure. The release also carries a CycloneDX SBOM.

## First-release checklist (owner)

1. Make the repository public.
2. Create the repository secret `MINISIGN_SECRET_KEY` (name only here; never commit its value).
3. Homebrew (optional, later): the release workflow only uploads `smith.rb` as an artifact and has no tap job or tap secret yet. Create a tap repository and copy `smith.rb` into it by hand, or add a tap step in a separate change.
4. Run the release workflow with `dry_run` first. A dry run signs with a throwaway key and publishes nothing, so check it with `scripts/verify-release.sh <dir> --pubkey dist/dry-run-pubkey.txt --skip-cosign`, not the default key.
5. Tag `vX.Y.Z`; confirm `gh attestation verify` and `cosign verify` pass on the published assets.
