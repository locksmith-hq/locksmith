#!/usr/bin/env python3
"""Canary leak oracle. Run as: python3 -I oracle.py {gen,scan,selftest,canary-new,canary-list}.

A canary is 32 random bytes, printed as base64url without padding. The oracle
never prints a canary, nor any fragment of one: every location it prints is
checked first and replaced by a hash if it contains part of an encoding.

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
import math
import os
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

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

    def find(self, data):
        return find_hits(data, self.needles)

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
                continue
            with open(fp, "rb") as fh:
                data = fh.read()
        except OSError as e:
            errors.append("cannot read %s: %s" % (fp, e.strerror))
            continue
        for name, off in m.find(data):
            hits.append((name, fp, off))
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

def read_capped(rep, fp, strict=True):
    """Read a file. Over 50 MB is an error, or (legacy positional paths) a skip notice."""
    try:
        if os.path.getsize(fp) > MAX_BYTES:
            if strict:
                rep.error("over 50 MB, not scanned: %s" % fp)
            else:
                print("skip over 50 MB: %s" % rep.m.safe(fp), file=sys.stderr)
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
        data = read_capped(rep, fp, strict=False)
        if data is None:
            continue
        for name, off in rep.m.find(data):
            rep.leak(name, "%s:%d" % (fp, off))


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
