#!/usr/bin/env python3
"""Independent generator for the seal-key signature known-answer vectors (seal-key-sig-v1.json).

The message is written out by hand (length-prefixed fields, big-endian u16) and signed with
pyca/cryptography Ed25519 (deterministic, RFC 8032), not the Rust code under test. Re-run only
when the format changes:

    python3 crates/ls-envelope/vectors/gen_seal_key_sig_vectors.py > crates/ls-envelope/vectors/seal-key-sig-v1.json

All keys and ids are fixed test data, not secrets.
"""
import json
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DOMAIN = b"locksmith.seal-key.v1"


def field(b):
    return struct.pack(">H", len(b)) + b


def vec(name, seed, org, env, key_id, pk):
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    msg = field(DOMAIN) + field(org) + field(env) + field(key_id) + field(pk)
    return {
        "name": name,
        "signing_seed": seed.hex(),
        "verifying_key": sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "org_id": org.hex(),
        "environment_id": env.hex(),
        "key_id": key_id.hex(),
        "public_key": pk.hex(),
        "message": msg.hex(),
        "signature": sk.sign(msg).hex(),
    }


def b(n, start):
    return bytes((start + i) % 256 for i in range(n))


vectors = [
    vec("sequential", b(32, 0), b(16, 0x10), b(16, 0x20), b(16, 0x30), b(32, 0x40)),
    vec("other-environment", b(32, 0), b(16, 0x10), b(16, 0x21), b(16, 0x30), b(32, 0x40)),
    vec("other-key", b(32, 0x80), b(16, 0xA0), b(16, 0xB0), b(16, 0xC0), b(32, 0xD0)),
]
print(json.dumps({"domain": DOMAIN.decode(), "vectors": vectors}, indent=2))
