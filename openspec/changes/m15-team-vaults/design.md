# Design: M15 Team Vaults

## Decisions

### D1. Crypto
Member identity is an X25519 static key, plus an Ed25519 signing key. The shared VK is wrapped per
member with HPKE (RFC 9180, `hpke` crate, mode base, X25519-HKDF-SHA256 + AES-256-GCM). Changes are
signed by the author's Ed25519 key and verified by every client. The server can neither read nor
forge.

### D2. Trust on first use plus verification
The server hands out public keys. The UI requires an admin to confirm a 6×5-digit safety number for
each member, or to trust on first use with a visible "unverified" badge. Key changes trigger a
blocking warning.

### D3. Policy merge
Effective policy = the strictest of (org policy, project binding, user config) per field. Org policy
is signed, and its version is monotonic to block rollback.

## Risks / Trade-offs
- A malicious server can withhold updates (availability) but cannot read or forge. Clients detect
  rollback through signed monotonic versions.
