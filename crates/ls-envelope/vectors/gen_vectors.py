#!/usr/bin/env python3
"""Independent generator for the ls-envelope known-answer vectors (v1.json).

Uses pyca/cryptography (50.0.2) AESGCM, not the Rust code under test, so the Rust KAT checks two
independent implementations of the same format. Re-run only when the format changes:

    python3 crates/ls-envelope/vectors/gen_vectors.py > crates/ls-envelope/vectors/v1.json

All keys, ids and plaintexts here are fixed test data, not secrets.
"""
import json
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LABEL = b"locksmith-ct"
PURPOSES = {"secret-payload": b"secret-payload", "dek-wrap": b"dek-wrap"}


def field(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def header(key_id: bytes) -> bytes:
    return b"LS" + bytes([1, 1]) + key_id


def aad(hdr, org_id, secret_id, version, purpose):
    return (field(LABEL) + field(hdr) + field(org_id) + field(secret_id)
            + field(struct.pack(">I", version)) + field(PURPOSES[purpose]))


CASES = [
    # Same inputs as the A0-7 spike KAT (crates/a0-spikes/src/header.rs).
    dict(name="a0-spike-payload", key=bytes(range(32)), key_id=b"\x11" * 16,
         nonce=bytes(range(0xA0, 0xAC)), org_id=b"\x01" * 16, secret_id=b"\x02" * 16,
         version=7, purpose="secret-payload", plaintext=b"kat-not-a-secret"),
    dict(name="empty-plaintext-version-0", key=b"\x42" * 32, key_id=bytes(range(16)),
         nonce=b"\x00" * 12, org_id=bytes(range(16, 32)), secret_id=bytes(range(32, 48)),
         version=0, purpose="secret-payload", plaintext=b""),
    dict(name="dek-wrap-max-version", key=bytes(range(255, 223, -1)), key_id=b"\xee" * 16,
         nonce=b"\xff" * 12, org_id=b"\xaa" * 16, secret_id=b"\xbb" * 16,
         version=0xFFFFFFFF, purpose="dek-wrap", plaintext=bytes(range(0x30, 0x50))),
    dict(name="multi-block-payload", key=bytes((7 * i + 3) % 256 for i in range(32)),
         key_id=bytes((11 * i) % 256 for i in range(16)),
         nonce=bytes((5 * i + 1) % 256 for i in range(12)),
         org_id=bytes((13 * i + 2) % 256 for i in range(16)),
         secret_id=bytes((17 * i + 9) % 256 for i in range(16)),
         version=0x01020304, purpose="secret-payload",
         plaintext=b"known-answer test vector spanning several AES blocks; not a secret." * 2),
]

out = []
for c in CASES:
    hdr = header(c["key_id"])
    a = aad(hdr, c["org_id"], c["secret_id"], c["version"], c["purpose"])
    ct_tag = AESGCM(c["key"]).encrypt(c["nonce"], c["plaintext"], a)
    out.append({
        "name": c["name"],
        "key": c["key"].hex(),
        "key_id": c["key_id"].hex(),
        "nonce": c["nonce"].hex(),
        "org_id": c["org_id"].hex(),
        "secret_id": c["secret_id"].hex(),
        "version": c["version"],
        "purpose": c["purpose"],
        "plaintext": c["plaintext"].hex(),
        "aad": a.hex(),
        "blob": (hdr + c["nonce"] + ct_tag).hex(),
    })

print(json.dumps({"format": "ls-envelope v1 (A0-7 header, AES-256-GCM)",
                  "generator": "vectors/gen_vectors.py (pyca/cryptography AESGCM)",
                  "vectors": out}, indent=2))
