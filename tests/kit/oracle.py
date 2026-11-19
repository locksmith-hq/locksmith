#!/usr/bin/env python3
"""Canary leak oracle. Run as: python3 -I oracle.py {gen,scan,selftest,canary-new,canary-list}.

A canary is 32 random bytes, printed as base64url without padding. The oracle
never prints a canary, nor any fragment of one: every location it prints is
checked first and replaced by a hash if it contains part of an encoding.

Each canary is searched for, as its raw bytes and as its text, in fixed encodings
(plain, percent, JSON, hex, base64 and base64url at three offsets, base32 upper and
lower at five offsets, UTF-16LE, UTF-16BE, reversed) and in decoded views of the
scanned data, labelled `<view>/<encoding>`: `gzip/` (any gzip member, labelled
or not, nested up to three deep), `qp/` (quoted-printable), `json-u/` (\\uXXXX
escapes), `html-entity/` (numeric character references) and `stripped/` (the data
with whitespace and header framing such as `X-Part-2:` removed, which finds a
canary split across headers or written one character per line). A decoded view
reports only what the undecoded data does not already show.

scan searches files (positional paths, --dir, --transcript) and, with --stack,
the local F0 stack: Postgres (psql --csv), Loki (query_range) and Tempo (search,
then each trace) through the Grafana HTTP API on localhost. It prints one line
per hit, `LEAK <encoding> <source>:<locator>`, and `SOURCE-UNREACHABLE <name>`
for a source it could not read. Exit: 0 clean, 1 hits, 2 unreachable or error.

Stdlib only. Environment (all optional):
  LEAK_SCAN_GRAFANA   Grafana base URL (default http://127.0.0.1:3000)
  LEAK_SCAN_LOKI      Loki API base, bypassing Grafana (e.g. http://127.0.0.1:3100)
  LEAK_SCAN_TEMPO     Tempo API base, bypassing Grafana (e.g. http://127.0.0.1:3200)
  LEAK_SCAN_PSQL      psql command (default "psql"); libpq PG* variables pick the server
"""
import argparse
import base64
import csv
import datetime
import hashlib
import io
import json
import collections
import gzip
import math
import os
import quopri
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zlib

MAX_BYTES = 50 * 1024 * 1024
# A printed locator must not share this many consecutive bytes with any canary encoding.
GRAM = 8
LOKI_PAGE = 5000
TEMPO_LIMIT = 5000
HTTP_TIMEOUT = 30
# Column types that cannot hold a canary encoding; everything else is cast to text.
PG_SKIP_TYPES = {
    "smallint", "integer", "bigint", "numeric", "real", "double precision", "boolean", "date",
    "timestamp without time zone", "timestamp with time zone", "time without time zone",
    "time with time zone", "interval", "uuid", "oid", "money", "inet", "cidr", "macaddr",
}


def gen_canary():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def variants(canary):
    """Return (name, full_encoded_bytes, needle) for each encoding of the canary."""
    raw = b64url_decode(canary)
    out = [
        ("raw", raw, raw),
        ("utf8", canary.encode(), canary.encode()),
        ("percent", urllib.parse.quote(canary, safe="").encode(), urllib.parse.quote(canary, safe="").encode()),
        ("json", json.dumps(canary)[1:-1].encode(), json.dumps(canary)[1:-1].encode()),
        ("hex-lower", raw.hex().encode(), raw.hex().encode()),
        ("hex-upper", raw.hex().upper().encode(), raw.hex().upper().encode()),
    ]
    # The canary text itself (as a credential it travels as text) hex- and base64-encoded too,
    # e.g. inside `Authorization: Basic base64(user:<canary>)`.
    text = canary.encode()
    out += [
        ("text-hex-lower", text.hex().encode(), text.hex().encode()),
        ("text-hex-upper", text.hex().upper().encode(), text.hex().upper().encode()),
    ]
    for src, prefix in ((raw, ""), (text, "text-")):
        for k in range(3):
            padded = b"\x00" * k + src
            for label, enc in (("b64", base64.b64encode), ("b64url", base64.urlsafe_b64encode)):
                full = enc(padded).decode()
                # Keep only the characters that do not depend on the zero prefix or the padding.
                needle = full[math.ceil(4 * k / 3):-4]
                out.append(("%s%s-offset%d" % (prefix, label, k), full.encode(), needle.encode()))
        # base32 (RFC 4648 section 6) works in 5-byte groups, so five offsets; padded or not and
        # upper or lower case.
        for k in range(5):
            full = base64.b32encode(b"\x00" * k + src)
            needle = full[math.ceil(8 * k / 5):-8]
            out.append(("%sb32-offset%d" % (prefix, k), full, needle))
            out.append(("%sb32-lower-offset%d" % (prefix, k), full.lower(), needle.lower()))
        # UTF-16 of the text, and of the bytes read as Latin-1 code units.
        units = src.decode("latin-1")
        for label, codec in (("utf16le", "utf-16-le"), ("utf16be", "utf-16-be")):
            enc = units.encode(codec)
            out.append((prefix + label, enc, enc))
        out.append((prefix + "reversed", src[::-1], src[::-1]))
    return out


# --- decoded views ------------------------------------------------------------------------------
# A view rewrites the scanned data with one regex; every fixed needle is then searched in it.

def codepoint_bytes(cp):
    """A code point as one byte when it fits (a raw canary byte), else as UTF-8."""
    if cp <= 0xFF:
        return bytes([cp])
    if cp > 0x10FFFF:
        return None
    return chr(cp).encode("utf-8", "surrogatepass")


def qp_repl(m):
    return bytes([int(m.group(1), 16)]) if m.group(1) else b""


def json_u_repl(m):
    return codepoint_bytes(int(m.group(1), 16))


def html_repl(m):
    cp = int(m.group(1), 16) if m.group(1) else int(m.group(2))
    r = codepoint_bytes(cp)
    return m.group(0) if r is None else r


WS_RE = re.compile(rb"\s+")
# (label, pattern, replacement, a byte string the data must contain for the view to apply)
VIEWS = (
    # RFC 2045 section 6.7: `=XX` octets and `=` soft line breaks.
    ("qp", re.compile(rb"=(?:([0-9A-Fa-f]{2})|[ \t]*\r?\n)"), qp_repl, b"="),
    ("json-u", re.compile(rb"\\u([0-9A-Fa-f]{4})"), json_u_repl, b"\\u"),
    ("html-entity", re.compile(rb"&#(?:[xX]([0-9A-Fa-f]{1,6})|([0-9]{1,7}));?"), html_repl, b"&#"),
    # Whitespace, and an HTTP header name (RFC 9110 token) with its colon at a line start,
    # after any spaces or tabs.
    ("stripped", re.compile(rb"(?m)\s*^[ \t]*[!#$%&'*+.^_`|~0-9A-Za-z-]+:|\s+"), lambda m: b"", None),
)
GZIP_MAGIC = b"\x1f\x8b\x08"
GZIP_MAX_MEMBERS = 256
GZIP_MAX_ATTEMPTS = 4096  # gzip-looking offsets tried per buffer, decoded or not
GZIP_MAX_DEPTH = 3
# Compressed input fed to zlib across all gzip attempts in one scan. A gzip-looking header with
# no NUL after it makes zlib read to the end of the data, so without this cap repeated magic
# bytes cost attempts x size. Reaching the cap marks the scan incomplete (fail closed).
GZIP_MAX_INPUT = 2 * MAX_BYTES
GZIP_IN_CHUNK = 64 * 1024
# GNU gzip treats the window before a member's first byte as zeros; zlib refuses such a
# back-reference ("invalid distance too far back"). Inflating with this preset dictionary
# decodes what `gzip -dc` shows.
GZIP_ZERO_WINDOW = bytes(32768)


def view_offsets(pattern, repl, data, voffs):
    """Map sorted offsets in pattern.sub(repl, data) back to offsets in data."""
    out = []
    it = iter(voffs)
    v = next(it, None)
    vpos = opos = 0
    for m in pattern.finditer(data):
        if v is None:
            return out
        keep = m.start() - opos
        while v is not None and v < vpos + keep:
            out.append(opos + v - vpos)
            v = next(it, None)
        vpos += keep
        rlen = len(repl(m))
        while v is not None and v < vpos + rlen:
            out.append(m.start())
            v = next(it, None)
        vpos += rlen
        opos = m.end()
    while v is not None:
        out.append(opos + v - vpos)
        v = next(it, None)
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


def salvage(d, chunk, room):
    """Return what d decodes from chunk before the byte that makes zlib fail, found by bisection
    on copies of d, so a damaged member (bad CRC, corrupt tail) still shows what `gzip -dc` shows."""
    outs = []
    while chunk and room > 0:
        if len(chunk) == 1:
            try:
                outs.append(d.copy().decompress(chunk, room))
            except zlib.error:
                pass
            break
        half = len(chunk) // 2
        t = d.copy()
        try:
            piece = t.decompress(chunk[:half], room)
        except zlib.error:
            chunk = chunk[:half]
            continue
        outs.append(piece)
        room -= len(piece)
        if t.unconsumed_tail or t.eof:
            break
        d, chunk = t, chunk[half:]
    return b"".join(outs)


def gzip_body(data, i, state):
    """Return where the deflate data of the gzip header at data[i:] starts, or None if the
    header is malformed or cut short. Bytes searched for a name or comment end are charged to
    state["input"]; running out of it first marks the scan incomplete."""
    n = len(data)
    if i + 10 > n or data[i + 3] & 0xE0:  # reserved flag bits: gzip -dc refuses them
        return None
    flg, p = data[i + 3], i + 10
    if flg & 4:  # FEXTRA
        if p + 2 > n:
            return None
        p += 2 + data[p] + (data[p + 1] << 8)
    for bit in (8, 16):  # FNAME, FCOMMENT: NUL-terminated
        if flg & bit and p < n:
            limit = min(n, p + max(state["input"], 0))
            q = data.find(b"\0", p, limit)
            state["input"] -= (q + 1 if q >= 0 else limit) - p
            if q < 0:
                if limit < n:
                    state["incomplete"] = "gzip budget exhausted, not fully scanned"
                return None
            p = q + 1
    if flg & 2:  # FHCRC
        p += 2
    return p if p < n else None


def nul_run_start(data, i):
    """Return the start of the run of NUL bytes that ends at data[i] (i if there is none). Runs
    before distinct member starts do not overlap, so all calls together read the data once."""
    z = i
    while z > 0:
        block = data[max(0, z - 4096):z]
        kept = len(block.rstrip(b"\0"))
        z -= len(block) - kept
        if kept:
            break
    return z


def gunzip_member(buf, i, state):
    """Decode the gzip member at buf[i:] to (output, end), or None if it decodes to nothing.

    Input goes to zlib in GZIP_IN_CHUNK pieces, each charged to state["input"]; output is
    charged to state["budget"]. Stopping at either limit before the member's end sets
    state["incomplete"]. A member cut short by the end of the data, or damaged (zlib error), is
    returned as far as it decodes.
    """
    pos = gzip_body(buf.obj, i, state)
    if pos is None:
        return None
    # Raw deflate after the header; the trailer (CRC, size) is not checked, as a damaged
    # trailer does not stop `gzip -dc` from writing the data.
    d = zlib.decompressobj(-15, zdict=GZIP_ZERO_WINDOW)
    outs, got = [], 0
    while not d.eof:
        room = state["budget"] - got
        if room <= 0:  # max_length 0 would mean unlimited
            state["incomplete"] = "gzip budget exhausted, not fully scanned"
            break
        if d.unconsumed_tail:
            chunk = d.unconsumed_tail
        else:
            if pos >= len(buf):
                break
            if state["input"] <= 0:
                state["incomplete"] = "gzip budget exhausted, not fully scanned"
                break
            chunk = buf[pos:pos + GZIP_IN_CHUNK]
            pos += len(chunk)
            state["input"] -= len(chunk)
        snap = d.copy()  # a failed decompress leaves d mid-chunk; salvage replays from here
        try:
            piece = d.decompress(chunk, room)
        except zlib.error:
            piece = salvage(snap, chunk, room)
            outs.append(piece)
            got += len(piece)
            break
        outs.append(piece)
        got += len(piece)
    state["budget"] -= got
    if not got and not d.eof:
        return None
    # Where the member ends (deflate end plus the 8-byte trailer), so a member that starts
    # there joins it as `gzip -dc` joins them; None if the member did not end cleanly.
    end = pos - len(d.unused_data) + 8 if d.eof and not d.unconsumed_tail else None
    return b"".join(outs), end


class Matcher:
    """Needles for a set of canaries, plus a guard that keeps fragments out of printed text.

    Encodings that produce the same needle (for example plain, percent and JSON for a
    base64url canary) share one label joined with '+'.
    """

    def __init__(self, canaries):
        by_needle = {}
        self.grams = set()
        for canary in canaries:
            for name, full, needle in variants(canary):
                names = by_needle.setdefault(needle, [])
                if name not in names:
                    names.append(name)
                for s in (full, needle, canary.encode()):
                    for i in range(len(s) - GRAM + 1):
                        self.grams.add(s[i:i + GRAM])
        self.needles = [("+".join(names), needle) for needle, names in by_needle.items()]
        # The stripped view drops whitespace, so its needles do too (raw bytes can hold some).
        self.stripped = [(name, WS_RE.sub(b"", needle)) for name, needle in self.needles]

    def find(self, data, budget=MAX_BYTES, input_budget=GZIP_MAX_INPUT):
        """Return [(label, offset)]. A view hit's offset is where it starts in data (for a gzip
        member, where the member starts). Afterwards self.incomplete is None, or why the gzip
        views stopped before the end of the data (a member, attempt, output or input limit)."""
        state = {"budget": budget, "input": input_budget, "joined": 2 * budget, "incomplete": None}
        hits = self._find(data, 0, state)
        self.incomplete = state["incomplete"]
        return hits

    def _find(self, data, depth, state):
        hits = find_hits(data, self.needles)
        base = collections.Counter(name for name, _off in hits)
        base_offs = set(hits)
        for label, pattern, repl, trigger in VIEWS:
            if trigger is not None and trigger not in data:
                continue
            view = pattern.sub(repl, data)
            if view == data:
                continue
            vhits = find_hits(view, self.stripped if label == "stripped" else self.needles)
            counts = collections.Counter(name for name, _off in vhits)
            # Only what decoding adds: a canary the plain scan already found is not reported twice.
            new = sorted((off, name) for name, off in vhits if counts[name] > base[name])
            if not new:
                continue
            offs = view_offsets(pattern, repl, data, [off for off, _name in new])
            for (_voff, name), off in zip(new, offs):
                if (name, off) not in base_offs:
                    hits.append(("%s/%s" % (label, name), off))
        if depth < GZIP_MAX_DEPTH:
            # Only members that decode count toward the limits; junk that looks like a gzip
            # header costs an attempt. Stopping early on any limit marks the scan incomplete.
            start = members = attempts = 0
            buf = memoryview(data)
            # Back-to-back members decode to one stream (gzip -dc; Python's gzip also skips NUL
            # padding between them), so a canary split across them is whole there: each run of
            # adjacent members is scanned joined, at its first offset.
            runs = collections.defaultdict(list)  # end of a run's last member -> [(first, outputs)]
            done = []  # runs that cannot grow: their last member did not end cleanly
            while True:
                i = data.find(GZIP_MAGIC, start)
                if i < 0:
                    break
                if (members >= GZIP_MAX_MEMBERS or attempts >= GZIP_MAX_ATTEMPTS
                        or state["budget"] <= 0 or state["input"] <= 0):
                    state["incomplete"] = "gzip budget exhausted, not fully scanned"
                    break
                start = i + 1
                attempts += 1
                res = gunzip_member(buf, i, state)
                if res is None:
                    continue
                out, end = res
                members += 1
                # Join every run that ends here or before NUL padding up to here: a false member
                # inside another member's bytes can end where it does, and either may be the
                # one gzip -dc decodes.
                z = nul_run_start(data, i)
                joined = [(first, outs + [out])
                          for e in [e for e in runs if z <= e <= i]
                          for first, outs in runs.pop(e)]
                for run in joined or [(i, [out])]:
                    (done if end is None else runs[end]).append(run)
            for first, outs in done + [r for rs in runs.values() for r in rs]:
                # Tied runs share outputs, so the joined bytes are capped separately.
                state["joined"] -= sum(len(o) for o in outs)
                if state["joined"] < 0:
                    state["incomplete"] = "gzip budget exhausted, not fully scanned"
                    break
                for name, _off in self._find(b"".join(outs), depth + 1, state):
                    hits.append(("gzip/" + name, first))
        return hits

    def safe(self, text):
        """Return text, or a hash of it if it shares GRAM bytes with any canary encoding."""
        b = str(text).encode("utf-8", "surrogateescape")
        for i in range(len(b) - GRAM + 1):
            if b[i:i + GRAM] in self.grams:
                return "<redacted sha256:%s>" % hashlib.sha256(b).hexdigest()[:12]
        return str(text)


def iter_files(paths, onerror=None):
    for p in paths:
        if os.path.isdir(p):
            for dirpath, _dirnames, filenames in os.walk(p, onerror=onerror):
                for f in filenames:
                    yield os.path.join(dirpath, f)
        elif os.path.isfile(p):
            yield p
        else:
            raise OSError("no such file or directory: %s" % p)


def collect(canary, paths):
    """Return (hits, errors); hits are (encoding label, file, offset)."""
    m = Matcher([canary])
    hits, errors = [], []
    try:
        files = list(iter_files(paths))
    except OSError as e:
        return [], [str(e)]
    for fp in files:
        try:
            if os.path.getsize(fp) > MAX_BYTES:
                errors.append("over 50 MB, not scanned: %s" % fp)
                continue
            with open(fp, "rb") as fh:
                data = fh.read()
        except OSError as e:
            errors.append("cannot read %s: %s" % (fp, e.strerror))
            continue
        for name, off in m.find(data):
            hits.append((name, fp, off))
        if m.incomplete:
            errors.append("%s: %s" % (m.incomplete, fp))
    return hits, errors


def load_canaries(path):
    """Return [(id, value)]. One canary per line: `<id> <value>` or a bare `<value>`."""
    out = []
    with open(path, "r") as fh:
        for n, line in enumerate(fh, 1):
            parts = line.split()
            if not parts or parts[0].startswith("#"):
                continue
            if len(parts) == 1:
                cid, value = "line%d" % n, parts[0]
            elif len(parts) == 2:
                cid, value = parts
            else:
                raise ValueError("line %d is malformed" % n)
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value) or len(b64url_decode(value)) != 32:
                raise ValueError("line %d is not a 32-byte canary" % n)
            out.append((cid, value))
    return out


class SourceError(Exception):
    pass


class Report:
    def __init__(self, matcher):
        self.m = matcher
        self.seen = set()
        self.hits = 0
        self.unreachable = []
        self.errors = 0
        self.coverage = []  # (name, key count, "k=v ..." detail)

    def leak(self, encoding, locator):
        line = "LEAK %s %s" % (encoding, self.m.safe(locator))
        if line not in self.seen:
            self.seen.add(line)
            self.hits += 1
            print(line, flush=True)

    def scan(self, data, locator):
        for name, _off in self.m.find(data):
            self.leak(name, locator)
        self.incomplete(locator)

    def incomplete(self, locator):
        """Report a gzip view that stopped early as an error, like content over 50 MB: a scan
        that could not look everywhere never reports clean."""
        if self.m.incomplete:
            self.error("%s: %s" % (self.m.incomplete, locator))

    def unreach(self, name, why):
        self.unreachable.append(name)
        print("SOURCE-UNREACHABLE %s" % name, flush=True)
        print("  %s: %s" % (name, self.m.safe(why)), file=sys.stderr, flush=True)

    def error(self, msg):
        self.errors += 1
        print("error: %s" % self.m.safe(msg), file=sys.stderr, flush=True)

    def cover(self, name, key, **counts):
        detail = " ".join("%s=%s" % (k, self.m.safe(v)) for k, v in counts.items())
        self.coverage.append((name, counts.get(key, 0), detail))


# --- file sources -----------------------------------------------------------------------------

def read_capped(rep, fp):
    """Read a file. Over 50 MB is an error."""
    try:
        if os.path.getsize(fp) > MAX_BYTES:
            rep.error("over 50 MB, not scanned: %s" % fp)
            return None
        with open(fp, "rb") as fh:
            return fh.read()
    except OSError as e:
        rep.error("cannot read %s: %s" % (fp, e.strerror))
        return None


def scan_paths(rep, paths):
    """Positional paths (the adversarial suite's artifact dirs): LEAK <enc> <file>:<offset>."""
    try:
        files = list(iter_files(paths))
    except OSError as e:
        rep.error(str(e))
        return
    for fp in files:
        data = read_capped(rep, fp)
        if data is None:
            continue
        for name, off in rep.m.find(data):
            rep.leak(name, "%s:%d" % (fp, off))
        rep.incomplete(fp)


def scan_dir(rep, path):
    if not os.path.exists(path):
        rep.unreach("dir", "no such file or directory: %s" % path)
        return
    files = total = 0
    def walk_error(e):
        rep.error("cannot read %s: %s" % (e.filename, e.strerror))

    for fp in iter_files([path], onerror=walk_error):
        data = read_capped(rep, fp)
        if data is None:
            continue
        files += 1
        total += len(data)
        for name, off in rep.m.find(data):
            rep.leak(name, "dir:%s:%d" % (fp, off))
        rep.incomplete("dir:%s" % fp)
    rep.cover("dir", "files", path=path, files=files, bytes=total)


def json_strings(value, depth=0):
    """Yield every string (keys too) in a decoded JSON value, decoding JSON-in-strings once more."""
    if isinstance(value, str):
        yield value
        s = value.strip()
        if depth < 3 and s[:1] in ("{", "[") and len(s) < MAX_BYTES:
            try:
                yield from json_strings(json.loads(s), depth + 1)
            except ValueError:
                pass
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from json_strings(v, depth)
    elif isinstance(value, list):
        for v in value:
            yield from json_strings(v, depth)


def scan_transcript(rep, path):
    if not os.path.isfile(path):
        rep.unreach("transcript", "no such file: %s" % path)
        return
    data = read_capped(rep, path)
    if data is None:
        rep.unreach("transcript", "cannot read %s" % path)
        return
    lines = bad = 0
    for n, line in enumerate(data.split(b"\n"), 1):
        if not line.strip():
            continue
        lines += 1
        loc = "transcript:%s:%d" % (path, n)
        rep.scan(line, loc)
        try:
            decoded = json.loads(line)
        except ValueError:
            bad += 1
            continue
        # JSON escaping can hide an encoding (e.g. "\/" in base64); scan the decoded strings too.
        text = "\n".join(json_strings(decoded)).encode("utf-8", "surrogateescape")
        rep.scan(text, loc)
    rep.cover("transcript", "lines", path=path, lines=lines, non_json_lines=bad)


# --- Postgres ---------------------------------------------------------------------------------

def psql(sql, db=None):
    cmd = shlex.split(os.environ.get("LEAK_SCAN_PSQL", "psql"))
    cmd += ["-X", "-q", "-t", "--csv", "-v", "ON_ERROR_STOP=1", "-f", "-"]
    if db is not None:
        cmd += ["-d", db]
    env = dict(os.environ)
    env.setdefault("PGHOST", "127.0.0.1")
    env.setdefault("PGCONNECT_TIMEOUT", "5")
    try:
        r = subprocess.run(cmd, input=sql.encode(), capture_output=True, timeout=300, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SourceError("psql: %s" % e.__class__.__name__)
    if r.returncode != 0:
        tail = r.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["exit %d" % r.returncode]
        raise SourceError("psql: %s" % tail[0])
    return list(csv.reader(io.StringIO(r.stdout.decode("utf-8", "surrogateescape"), newline="")))


def qident(name):
    return '"%s"' % name.replace('"', '""')


COLUMNS_SQL = r"""
SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, NULL)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid
WHERE c.relkind IN ('r', 'm') AND a.attnum > 0 AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
ORDER BY 1, 2, a.attnum;
"""


def scan_postgres(rep):
    try:
        main_db = os.environ.get("PGDATABASE") or psql("SELECT current_database();")[0][0]
        dbs = [r[0] for r in psql("SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY 1;")]
    except (SourceError, IndexError) as e:
        rep.unreach("postgres", str(e) or "no database")
        return
    tables = rows = columns = 0
    failed = False
    for db in dbs:
        try:
            cols = psql(COLUMNS_SQL, db)
        except SourceError as e:
            rep.error("postgres %s: %s" % (db, e))
            failed = True
            continue
        by_table = {}
        for schema, table, column, typ in cols:
            by_table.setdefault((schema, table), []).append((column, typ))
        for (schema, table), tcols in sorted(by_table.items()):
            tables += 1
            prefix = table if schema == "public" else "%s.%s" % (schema, table)
            if db != main_db:
                prefix = "%s/%s" % (db, prefix)
            scan_cols = [(c, t) for c, t in tcols if t not in PG_SKIP_TYPES]
            exprs = ["encode(%s, 'hex')" % qident(c) if t == "bytea" else "%s::text" % qident(c)
                     for c, t in scan_cols]
            exprs.append("1")  # keeps a row visible when the table has nothing to scan
            sql = "SELECT %s FROM %s.%s;" % (", ".join(exprs), qident(schema), qident(table))
            try:
                result = psql(sql, db)
            except SourceError as e:
                rep.error("postgres %s: %s" % (prefix, e))
                failed = True
                continue
            rows += len(result)
            for i, (column, typ) in enumerate(scan_cols):
                columns += 1
                parts = []
                for row in result:
                    v = row[i] if i < len(row) else ""
                    if typ == "bytea":
                        try:
                            parts.append(bytes.fromhex(v))
                        except ValueError:
                            parts.append(v.encode("utf-8", "surrogateescape"))
                    else:
                        parts.append(v.encode("utf-8", "surrogateescape"))
                rep.scan(b"\n\x00".join(parts), "postgres:%s.%s" % (prefix, column))
    if failed:
        rep.unreach("postgres", "some tables could not be read")
    rep.cover("postgres", "rows", databases=len(dbs), tables=tables, columns=columns, rows=rows)


# --- Loki and Tempo (HTTP) --------------------------------------------------------------------

# Never use a proxy: these are localhost services and the canary must not leave the machine.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_get(url, params=None):
    if params:
        url = url + "?" + urllib.parse.urlencode(params, doseq=True)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with OPENER.open(req, timeout=HTTP_TIMEOUT) as r:
            body = r.read()
        return body, json.loads(body)
    except urllib.error.HTTPError as e:
        raise SourceError("HTTP %d from %s" % (e.code, urllib.parse.urlsplit(url).path))
    except (urllib.error.URLError, OSError) as e:
        raise SourceError("%s: %s" % (urllib.parse.urlsplit(url).netloc, getattr(e, "reason", e)))
    except ValueError:
        raise SourceError("non-JSON reply from %s" % urllib.parse.urlsplit(url).path)


def grafana():
    return os.environ.get("LEAK_SCAN_GRAFANA", "http://127.0.0.1:3000").rstrip("/")


def logql_escape(v):
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def scan_loki(rep, start_ns, end_ns):
    base = os.environ.get("LEAK_SCAN_LOKI", "").rstrip("/") or grafana() + "/api/datasources/proxy/uid/loki"
    base += "/loki/api/v1"
    window = {"start": start_ns, "end": end_ns}
    try:
        names = http_get(base + "/labels", window)[1].get("data") or []
        streams = set()
        for label in names:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", label):
                continue
            series = http_get(base + "/series", dict(window, **{"match[]": '{%s=~".+"}' % label}))[1]
            for labels in series.get("data") or []:
                streams.add(tuple(sorted(labels.items())))
        lines = 0
        for key in sorted(streams):
            selector = "{%s}" % ",".join('%s="%s"' % (k, logql_escape(v)) for k, v in key)
            cur = start_ns
            while True:
                params = {"query": selector, "start": cur, "end": end_ns, "limit": LOKI_PAGE, "direction": "forward"}
                body, res = http_get(base + "/query_range", params)
                n, last = 0, cur
                for result in (res.get("data") or {}).get("result") or []:
                    for value in result.get("values") or []:
                        n += 1
                        last = max(last, int(value[0]))
                # The raw reply holds the line and its structured metadata (OTLP attributes).
                rep.scan(body, "loki:" + selector)
                lines += n
                if n < LOKI_PAGE:
                    break
                cur = last if last > cur else last + 1
    except SourceError as e:
        rep.unreach("loki", str(e))
        return
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        rep.unreach("loki", "unexpected reply: %s" % e.__class__.__name__)
        return
    rep.cover("loki", "lines", streams=len(streams), lines=lines)


def tempo_search(rep, base, start_s, end_s):
    """Yield the trace ids found in [start_s, end_s]. A window that returns the search limit is
    split in half (a load test leaves more traces than one search returns), down to one second."""
    body, res = http_get(base + "/api/search", {"start": start_s, "end": end_s, "limit": TEMPO_LIMIT})
    traces = res.get("traces") or []
    if len(traces) >= TEMPO_LIMIT and end_s - start_s > 1:
        mid = (start_s + end_s) // 2
        yield from tempo_search(rep, base, start_s, mid)
        yield from tempo_search(rep, base, mid, end_s)
        return
    rep.scan(body, "tempo:search")
    if len(traces) >= TEMPO_LIMIT:
        rep.error("tempo: search returned the %d-trace limit for one second; traces were not scanned" % TEMPO_LIMIT)
    for t in traces:
        yield str(t.get("traceID", ""))


def scan_tempo(rep, start_s, end_s):
    base = os.environ.get("LEAK_SCAN_TEMPO", "").rstrip("/") or grafana() + "/api/datasources/proxy/uid/tempo"
    seen = set()
    spans = total = 0
    try:
        for tid in tempo_search(rep, base, start_s, end_s):
            if not re.fullmatch(r"[0-9a-fA-F]{1,32}", tid):
                rep.error("tempo: skipped a trace with an unexpected id")
                continue
            # Adjacent windows share their boundary second, so a trace can be found twice.
            if tid in seen:
                continue
            seen.add(tid)
            body, trace = http_get(base + "/api/traces/" + tid)
            total += len(body)
            spans += body.count(b'"spanId"')
            rep.scan(body, "tempo:" + tid)
    except SourceError as e:
        rep.unreach("tempo", str(e))
        return
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        rep.unreach("tempo", "unexpected reply: %s" % e.__class__.__name__)
        return
    rep.cover("tempo", "traces", traces=len(seen), spans=spans, bytes=total)


# --- commands ---------------------------------------------------------------------------------

def cmd_gen(_args):
    print(gen_canary())
    return 0


def cmd_scan(args):
    try:
        canaries = [v for _id, v in load_canaries(args.canary_file)]
        if not canaries:
            raise ValueError("no canaries; run `just canary new`")
    except (OSError, ValueError) as e:
        why = e.__class__.__name__ if isinstance(e, OSError) else str(e)
        print("error: bad canary file: %s" % why, file=sys.stderr)
        return 2
    if not (args.paths or args.dir or args.transcript or args.stack):
        print("error: nothing to scan: give paths, --dir, --transcript or --stack", file=sys.stderr)
        return 2
    rep = Report(Matcher(canaries))
    if args.paths:
        scan_paths(rep, args.paths)
    if args.stack:
        end = datetime.datetime.now(datetime.timezone.utc)
        start = end - datetime.timedelta(minutes=args.since_minutes)
        scan_postgres(rep)
        scan_loki(rep, int(start.timestamp()) * 10**9, int(end.timestamp() + 1) * 10**9)
        scan_tempo(rep, int(start.timestamp()), int(end.timestamp()) + 1)
    for d in args.dir:
        scan_dir(rep, d)
    for t in args.transcript:
        scan_transcript(rep, t)

    empty = [name for name, n, _ in rep.coverage if n == 0]
    if args.explain:
        for name, _n, detail in rep.coverage:
            print("COVERED %s %s" % (name, detail))
        for name in rep.unreachable:
            print("COVERED %s unreachable" % name)
    if args.require_coverage:
        for name in empty:
            print("COVERAGE-EMPTY %s" % name)
    if rep.unreachable or rep.errors or (args.require_coverage and empty):
        return 2
    if rep.hits:
        return 1
    print("clean")
    return 0


def view_plants(canary):
    """(form, planted bytes, label of the view that must find it, base encoding it decodes to)."""
    raw = b64url_decode(canary)
    text = canary.encode()
    half = len(canary) // 2
    qp_text = quopri.encodestring(b"x" * 60 + text)
    return [
        ("gzip", gzip.compress(raw), "gzip", "raw"),
        ("text-gzip", gzip.compress(text), "gzip", "utf8"),
        ("text-gzip-gzip", gzip.compress(gzip.compress(text)), "gzip/gzip", "utf8"),
        ("qp", quopri.encodestring(raw), "qp", "raw"),
        # A soft line break (`=` newline) falls inside the canary.
        ("text-qp", qp_text, "qp", "utf8"),
        ("json-u", "".join("\\u%04x" % b for b in raw).encode(), "json-u", "raw"),
        ("text-json-u", "".join("\\u%04X" % ord(c) for c in canary).encode(), "json-u", "utf8"),
        ("html-entity", "".join("&#%d;" % b for b in raw).encode(), "html-entity", "raw"),
        ("text-html-entity", "".join("&#x%x;" % ord(c) for c in canary).encode(), "html-entity", "utf8"),
        ("stripped", b"\n".join(raw[i:i + 1] for i in range(len(raw))), "stripped", "raw"),
        ("text-stripped-lines", "\r\n".join(canary).encode(), "stripped", "utf8"),
        ("text-stripped-headers", ("HTTP/1.1 200 OK\r\nDate: x\r\nX-Part-1: %s\r\nX-Part-2: %s\r\n\r\n"
                                   % (canary[:half], canary[half:])).encode(), "stripped", "utf8"),
        ("text-stripped-tab-headers", ("X-Part-1: %s\r\n\tX-Part-2: %s\r\n"
                                       % (canary[:half], canary[half:])).encode(), "stripped", "utf8"),
        # 256 gzip-looking markers that do not decode must not use up the member limit.
        ("text-gzip-after-junk", GZIP_MAGIC * GZIP_MAX_MEMBERS + gzip.compress(text), "gzip", "utf8"),
    ]


def clean_corpus():
    """Random bytes and text in every form a view decodes, with no canary in it."""
    rnd = secrets.token_bytes(1 << 16)
    words = base64.urlsafe_b64encode(secrets.token_bytes(4096))
    text = b" ".join(words[i:i + 9] for i in range(0, len(words), 9))
    parts = [
        rnd, text, words, rnd.hex().encode(), base64.b32encode(rnd[:4096]),
        rnd[:4096].decode("latin-1").encode("utf-16-le"), words.decode().encode("utf-16-be"),
        gzip.compress(text), gzip.compress(rnd), quopri.encodestring(rnd[:4096]), quopri.encodestring(text),
        "".join("\\u%04x" % b for b in rnd[:2048]).encode(), "".join("&#%d;" % b for b in rnd[:2048]).encode(),
        b"\n".join(words[i:i + 1] for i in range(2048)),
        b"".join(b"X-Part-%d: %s\r\n" % (i, words[i * 7:i * 7 + 7]) for i in range(256)),
        rnd[::-1], words[::-1],
    ]
    return b"\n".join(parts)


def gzip_limit_checks(tmp):
    """Yield (name, ok) for gzip inputs that hit the member, attempt and byte limits."""
    canary = gen_canary()
    text = canary.encode()
    member = gzip.compress(text)
    cases = [
        ("gzip-members-exhausted", gzip.compress(b"") * GZIP_MAX_MEMBERS + member),
        ("gzip-attempts-exhausted", GZIP_MAGIC * GZIP_MAX_ATTEMPTS + member),
        # Real size: 60 MB of zeros in front uses up the 50 MB budget.
        ("gzip-budget-exhausted", gzip.compress(bytes(60 << 20)) + member),
    ]
    for name, data in cases:
        path = os.path.join(tmp, "%s.bin" % name)
        with open(path, "wb") as fh:
            fh.write(data)
        _hits, errors = collect(canary, [path])
        yield name, any(e.startswith("gzip budget exhausted") for e in errors)
    # A small budget: one byte short of the padding fails closed; enough budget finds the canary.
    m = Matcher([canary])
    data = gzip.compress(bytes(4096)) + member
    m.find(data, budget=4095)
    short_ok = bool(m.incomplete)
    hits = m.find(data, budget=4096 + len(text))
    yield "gzip-small-budget", short_ok and not m.incomplete and any(h[0].startswith("gzip/") for h in hits)
    # Input cap: a gzip-looking header with no NUL after it reads to the end of the data, so
    # repeated magic stops at the input cap and fails closed; enough input finds the canary.
    data = GZIP_MAGIC * 64 + b"\x01" * (1 << 20) + member
    m.find(data, input_budget=4 << 20)
    capped_ok = bool(m.incomplete)
    hits = m.find(GZIP_MAGIC * 4 + member, input_budget=4 * GZIP_IN_CHUNK)
    # A canary split across back-to-back members, as gzip -dc joins them: 2 and one per byte.
    # Python's gzip also joins members across NUL padding.
    for name, parts, sep in (
            ("gzip-split-2", (text[:20], text[20:]), b""),
            ("gzip-split-bytes", [text[k:k + 1] for k in range(len(text))], b""),
            ("gzip-split-nul-1", (text[:20], text[20:]), b"\0"),
            ("gzip-split-nul-8192", (text[:20], text[20:]), bytes(8192))):
        hits = m.find(sep.join(gzip.compress(x) for x in parts))
        yield name, not m.incomplete and any(h[0].startswith("gzip/") for h in hits)
    # Two members tie: a false member inside the first (a gzip header in a stored block) ends
    # where the first does. The second must join the first, which holds the canary's start.
    hdr = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
    stored = lambda b: b"\x00" + len(b).to_bytes(2, "little") + (len(b) ^ 0xFFFF).to_bytes(2, "little") + b
    pre = b"Q" * 10 + text[:20] + b"R" * 50 + hdr + stored(b"S" * 40)
    c = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=pre)
    tail = c.compress(text[:20]) + c.flush()
    first = (hdr + stored(pre) + tail + zlib.crc32(pre + text[:20]).to_bytes(4, "little")
             + (len(pre) + 20).to_bytes(4, "little"))
    for name, sep in (("gzip-split-tie", b""), ("gzip-split-tie-nul", bytes(16))):
        hits = m.find(first + sep + gzip.compress(text[20:]))
        yield name, not m.incomplete and any(h[0].startswith("gzip/") for h in hits)
    # A back-reference into the zeros before the member: zlib refuses it, gzip -dc decodes it.
    c = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=GZIP_ZERO_WINDOW)
    body = c.compress(bytes(300) + text) + c.flush()
    zero_ref = (b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + body
                + zlib.crc32(bytes(300) + text).to_bytes(4, "little") + (300 + len(text)).to_bytes(4, "little"))
    try:
        zlib.decompress(zero_ref, 31)
        zero_ok = False  # the plant must be one plain zlib refuses
    except zlib.error:
        hits = m.find(zero_ref)
        zero_ok = not m.incomplete and any(h[0].startswith("gzip/") for h in hits)
    yield "gzip-zero-window", zero_ok
    # A damaged member still shows what it decodes to, as `gzip -dc` does: a bad CRC, and a
    # corrupt byte after the canary in a member larger than one input chunk.
    pad = secrets.token_bytes(GZIP_IN_CHUNK).hex().encode()
    bad_crc = bytearray(gzip.compress(text))
    bad_crc[-6] ^= 0x55
    corrupt = bytearray(gzip.compress(pad + text + pad))
    corrupt[-200] ^= 0x55
    for name, data in (("gzip-bad-crc", bad_crc), ("gzip-corrupt-tail", corrupt)):
        hits = m.find(bytes(data))
        yield name, not m.incomplete and any(h[0].startswith("gzip/") for h in hits)
    yield "gzip-input-exhausted", capped_ok and not m.incomplete and any(h[0].startswith("gzip/") for h in hits)


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
        for i in range(len(view_plants(gen_canary()))):
            canary = gen_canary()
            name, planted, view, enc = view_plants(canary)[i]
            path = os.path.join(tmp, "%s.bin" % name)
            with open(path, "wb") as fh:
                fh.write(b"preamble\n" + planted + b"\ntrailer\n")
            hits, errors = collect(canary, [path])
            found = not errors and any(
                h[0].rsplit("/", 1)[0] == view and enc in h[0].rsplit("/", 1)[1].split("+") for h in hits)
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
        # Random bytes and text, in every form above, under a canary that was never written.
        corpus = os.path.join(tmp, "clean-corpus.bin")
        with open(corpus, "wb") as fh:
            fh.write(clean_corpus())
        hits, errors = collect(gen_canary(), [corpus])
        corpus_ok = not hits and not errors
        ok_all = ok_all and corpus_ok
        print("%s clean-corpus%s" % ("ok" if corpus_ok else "FAIL", "" if corpus_ok else " (%d hits)" % len(hits)))
        # A gzip view that stops at a limit says so: as an error from collect, and as
        # m.incomplete; the canary after the limit is not reported as clean.
        for name, ok in gzip_limit_checks(tmp):
            ok_all = ok_all and ok
            print("%s %s" % ("ok" if ok else "FAIL", name))
        # The locator guard hides any 8-byte fragment of an encoding and passes ordinary text.
        m = Matcher([canary])
        frag = [f for n, f, _ in variants(canary) if n == "hex-lower"][0][10:18].decode()
        guard_ok = m.safe("t_" + frag).startswith("<redacted") and m.safe("users.note") == "users.note"
        ok_all = ok_all and guard_ok
        print("%s locator-guard" % ("ok" if guard_ok else "FAIL"))
    print("selftest passed" if ok_all else "selftest FAILED")
    return 0 if ok_all else 1


def secure_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.fchmod(fd, 0o600)
    return fd


def cmd_canary_new(args):
    parent = os.path.dirname(os.path.abspath(args.file))
    os.makedirs(parent, exist_ok=True)
    cid = "c-%s-%s" % (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(3))
    fd = secure_file(args.file)
    try:
        os.write(fd, ("%s %s\n" % (cid, gen_canary())).encode())
    finally:
        os.close(fd)
    print(cid)
    return 0


def cmd_canary_list(args):
    if not os.path.exists(args.file):
        print("no canaries yet; run `just canary new`", file=sys.stderr)
        return 0
    if os.stat(args.file).st_mode & 0o077:
        os.chmod(args.file, 0o600)
        print("warning: %s was readable by others; set to 0600" % args.file, file=sys.stderr)
    try:
        canaries = load_canaries(args.file)
    except (OSError, ValueError) as e:
        print("error: bad canary file: %s" % (e if isinstance(e, ValueError) else e.__class__.__name__), file=sys.stderr)
        return 2
    for cid, _value in canaries:
        print(cid)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen").set_defaults(func=cmd_gen)
    scan = sub.add_parser("scan")
    scan.add_argument("--canary-file", required=True, help="one canary per line: `<id> <value>` or `<value>`")
    scan.add_argument("--stack", action="store_true", help="scan Postgres, Loki and Tempo")
    scan.add_argument("--dir", action="append", default=[], metavar="P", help="scan a directory tree (repeatable)")
    scan.add_argument("--transcript", action="append", default=[], metavar="P", help="scan a JSONL transcript (repeatable)")
    scan.add_argument("--since-minutes", type=int, default=1440, help="Loki/Tempo window (default 1440)")
    scan.add_argument("--explain", action="store_true", help="print the sources covered with their counts")
    scan.add_argument("--require-coverage", action="store_true", help="fail when a source had nothing to scan")
    scan.add_argument("paths", nargs="*")
    scan.set_defaults(func=cmd_scan)
    sub.add_parser("selftest").set_defaults(func=cmd_selftest)
    for name, func in (("canary-new", cmd_canary_new), ("canary-list", cmd_canary_list)):
        p = sub.add_parser(name)
        p.add_argument("--file", required=True)
        p.set_defaults(func=func)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
