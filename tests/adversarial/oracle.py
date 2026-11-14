#!/usr/bin/env python3
"""Canary leak oracle. Run as: python3 -I oracle.py {gen,scan,selftest}.

The canary is 32 random bytes, printed as base64url without padding. The
oracle never prints the canary itself, only the encoding name and location.
"""
import argparse
import base64
import json
import math
import os
import secrets
import sys
import tempfile
import urllib.parse

MAX_BYTES = 50 * 1024 * 1024


def gen_canary():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def variants(canary):
    """Return (name, full_encoded_bytes, needle) for each encoding of the canary."""
    raw = b64url_decode(canary)
    out = [
        ("utf8", canary.encode(), canary.encode()),
        ("percent", urllib.parse.quote(canary, safe="").encode(), urllib.parse.quote(canary, safe="").encode()),
        ("json", json.dumps(canary)[1:-1].encode(), json.dumps(canary)[1:-1].encode()),
        ("hex-lower", raw.hex().encode(), raw.hex().encode()),
        ("hex-upper", raw.hex().upper().encode(), raw.hex().upper().encode()),
    ]
    for k in range(3):
        padded = b"\x00" * k + raw
        for label, enc in (("b64", base64.b64encode), ("b64url", base64.urlsafe_b64encode)):
            full = enc(padded).decode()
            # Keep only the characters that do not depend on the zero prefix or the padding.
            needle = full[math.ceil(4 * k / 3):-4]
            out.append(("%s-offset%d" % (label, k), full.encode(), needle.encode()))
    return out


def find_hits(data, needles):
    hits = []
    for name, needle in needles:
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            hits.append((name, i))
            start = i + 1
    return hits


def iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for dirpath, _dirnames, filenames in os.walk(p):
                for f in filenames:
                    yield os.path.join(dirpath, f)
        elif os.path.isfile(p):
            yield p
        else:
            raise OSError("no such file or directory: %s" % p)


def collect(canary, paths):
    """Return (hits, errors); hits are (encoding label, file, offset).

    Encodings that produce the same needle (for example plain, percent and JSON
    for a base64url canary) share one label joined with '+'.
    """
    by_needle = {}
    for name, _full, needle in variants(canary):
        by_needle.setdefault(needle, []).append(name)
    needles = [("+".join(names), needle) for needle, names in by_needle.items()]
    hits, errors = [], []
    try:
        files = list(iter_files(paths))
    except OSError as e:
        return [], [str(e)]
    for fp in files:
        try:
            if os.path.getsize(fp) > MAX_BYTES:
                print("skip over 50 MB: %s" % fp, file=sys.stderr)
                continue
            with open(fp, "rb") as fh:
                data = fh.read()
        except OSError as e:
            errors.append("cannot read %s: %s" % (fp, e.strerror))
            continue
        for name, off in find_hits(data, needles):
            hits.append((name, fp, off))
    return hits, errors


def cmd_gen(_args):
    print(gen_canary())
    return 0


def cmd_scan(args):
    try:
        with open(args.canary_file, "r") as fh:
            canary = fh.read().strip()
        if len(b64url_decode(canary)) != 32:
            raise ValueError("canary is not 32 bytes")
    except (OSError, ValueError) as e:
        print("error: bad canary file: %s" % e.__class__.__name__, file=sys.stderr)
        return 2
    hits, errors = collect(canary, args.paths)
    for e in errors:
        print("error: %s" % e, file=sys.stderr)
    for name, fp, off in hits:
        print("LEAK %s %s:%d" % (name, fp, off))
    if errors:
        return 2
    if hits:
        return 1
    print("clean")
    return 0


def cmd_selftest(_args):
    ok_all = True
    names = [name for name, _f, _n in variants(gen_canary())]
    with tempfile.TemporaryDirectory() as tmp:
        for name in names:
            canary = gen_canary()
            full = [f for n, f, _ in variants(canary) if n == name][0]
            path = os.path.join(tmp, "%s.bin" % name)
            with open(path, "wb") as fh:
                fh.write(b"preamble\n" + full + b"\ntrailer\n")
            hits, errors = collect(canary, [path])
            found = any(name in h[0].split("+") for h in hits) and not errors
            ok_all = ok_all and found
            print("%s %s" % ("ok" if found else "FAIL", name))
        canary = gen_canary()
        clean = os.path.join(tmp, "clean.txt")
        with open(clean, "wb") as fh:
            fh.write(b"nothing to see here\n")
        hits, errors = collect(canary, [clean])
        clean_ok = not hits and not errors
        ok_all = ok_all and clean_ok
        print("%s clean-file" % ("ok" if clean_ok else "FAIL"))
    print("selftest passed" if ok_all else "selftest FAILED")
    return 0 if ok_all else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen").set_defaults(func=cmd_gen)
    scan = sub.add_parser("scan")
    scan.add_argument("--canary-file", required=True)
    scan.add_argument("paths", nargs="+")
    scan.set_defaults(func=cmd_scan)
    sub.add_parser("selftest").set_defaults(func=cmd_selftest)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
