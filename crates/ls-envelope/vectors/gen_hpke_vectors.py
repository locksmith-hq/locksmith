#!/usr/bin/env python3
"""Independent generator for the HPKE-wrapped DEK known-answer vectors (hpke-v1.json).

Writes out RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, over
pyca/cryptography primitives (X25519, HMAC-SHA256, AESGCM), not the Rust `hpke` crate under
test, so the Rust KAT checks two independent implementations of the same format. The HPKE
functions here (derive_keypair, encap, key_schedule_base) were checked against the CFRG RFC 9180
test vector for mode 0, kem 0x0020, kdf 0x0001, aead 0x0002 (test-vectors.json at
cfrg/draft-irtf-cfrg-hpke 5f503c5): pkRm, enc, shared_secret, key, base_nonce and the first ct
all match. Needs pyca/cryptography (checked with 46.0.3). Re-run only when the format changes:

    python3 crates/ls-envelope/vectors/gen_hpke_vectors.py > crates/ls-envelope/vectors/hpke-v1.json

All keys, ids and DEKs here are fixed test data, not secrets.
"""
import hashlib
import hmac
import json
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0002  # RFC 9180 section 7
KEM_SUITE = b"KEM" + struct.pack(">H", KEM_ID)
HPKE_SUITE = b"HPKE" + struct.pack(">HHH", KEM_ID, KDF_ID, AEAD_ID)
NK, NN, NSECRET = 32, 12, 32

AAD_LABEL = b"locksmith-ct"
ALG_HPKE = 2


def extract(salt, ikm):
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def labeled_extract(suite, salt, label, ikm):
    return extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return expand(prk, struct.pack(">H", length) + b"HPKE-v1" + suite + label + info, length)


def derive_keypair(ikm):
    prk = labeled_extract(KEM_SUITE, b"", b"dkp_prk", ikm)
    sk = labeled_expand(KEM_SUITE, prk, b"sk", b"", 32)
    priv = X25519PrivateKey.from_private_bytes(sk)
    return priv, pub_bytes(priv)


def pub_bytes(priv):
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def encap(pk_r, ikm_e):
    sk_e, enc = derive_keypair(ikm_e)
    dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk_r))
    prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh)
    shared = labeled_expand(KEM_SUITE, prk, b"shared_secret", enc + pk_r, NSECRET)
    return shared, enc


def key_schedule_base(shared, info):
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    ctx = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(HPKE_SUITE, shared, b"secret", b"")
    key = labeled_expand(HPKE_SUITE, secret, b"key", ctx, NK)
    nonce = labeled_expand(HPKE_SUITE, secret, b"base_nonce", ctx, NN)
    return key, nonce


def field(b):
    return struct.pack(">H", len(b)) + b


def info_bytes(org_id, secret_id, version):
    return field(org_id) + field(secret_id) + field(struct.pack(">I", version)) + field(b"dek-wrap")


def header(key_id):
    return b"LS" + bytes([1, ALG_HPKE]) + key_id


def aad(hdr, org_id, secret_id, version):
    return (field(AAD_LABEL) + field(hdr) + field(org_id) + field(secret_id)
            + field(struct.pack(">I", version)) + field(b"dek-wrap"))


CASES = [
    dict(name="basic", ikm_r=b"\x01" * 32, ikm_e=b"\x02" * 32, key_id=b"\x33" * 16,
         org_id=b"\x01" * 16, secret_id=b"\x02" * 16, version=7, dek=bytes(range(32))),
    dict(name="version-0", ikm_r=bytes(range(32)), ikm_e=bytes(range(32, 64)),
         key_id=bytes(range(16)), org_id=bytes(range(16, 32)), secret_id=bytes(range(32, 48)),
         version=0, dek=b"\x42" * 32),
    dict(name="max-version", ikm_r=bytes(range(255, 223, -1)), ikm_e=b"\xee" * 32,
         key_id=b"\xff" * 16, org_id=b"\xaa" * 16, secret_id=b"\xbb" * 16,
         version=0xFFFFFFFF, dek=bytes(range(0x30, 0x50))),
    dict(name="mixed", ikm_r=bytes((7 * i + 3) % 256 for i in range(32)),
         ikm_e=bytes((11 * i + 5) % 256 for i in range(32)),
         key_id=bytes([0x55, 0x66] * 8),
         org_id=bytes((13 * i + 2) % 256 for i in range(16)),
         secret_id=bytes((17 * i + 9) % 256 for i in range(16)),
         version=0x01020304, dek=bytes([0x11, 0x22, 0x33, 0x44] * 8)),
]

def main():
    out = []
    for c in CASES:
        sk_r, pk_r = derive_keypair(c["ikm_r"])
        sk_r_bytes = sk_r.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        shared, enc = encap(pk_r, c["ikm_e"])
        info = info_bytes(c["org_id"], c["secret_id"], c["version"])
        key, nonce = key_schedule_base(shared, info)
        hdr = header(c["key_id"])
        a = aad(hdr, c["org_id"], c["secret_id"], c["version"])
        ct_tag = AESGCM(key).encrypt(nonce, c["dek"], a)  # sequence 0: nonce = base_nonce
        wrapped = hdr + enc + ct_tag
        assert len(wrapped) == 100
        out.append({
            "name": c["name"],
            "sk_r": sk_r_bytes.hex(),
            "pk_r": pk_r.hex(),
            "ikm_e": c["ikm_e"].hex(),
            "key_id": c["key_id"].hex(),
            "org_id": c["org_id"].hex(),
            "secret_id": c["secret_id"].hex(),
            "version": c["version"],
            "dek": c["dek"].hex(),
            "info": info.hex(),
            "aad": a.hex(),
            "wrapped": wrapped.hex(),
        })

    print(json.dumps({
        "format": "ls-envelope HPKE-wrapped DEK (A0-7 header, alg_id 2; RFC 9180 base mode, "
                  "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM)",
        "generator": "vectors/gen_hpke_vectors.py (RFC 9180 over pyca/cryptography)",
        "vectors": out,
    }, indent=2))


if __name__ == "__main__":
    main()
