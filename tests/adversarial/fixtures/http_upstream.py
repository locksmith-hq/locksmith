#!/usr/bin/env python3
"""Fixture API upstream for gate A3b: reflects everything it receives back to the caller.

Usage: python3 -I http_upstream.py ROLE PORT_FILE HITS_FILE [CANARY_FILE]
ROLE is `api` (the real provider, which the relay may send the key to) or `evil` (an attacker's
host). Listens on 127.0.0.1 (random port, written to PORT_FILE). Every request appends one line
to HITS_FILE. For `api` the line has the method, path, header names and `key=ok` when the
canary (CANARY_FILE) arrived in a header or the query, `key=no` otherwise, then `where=` and the
places the canary arrived in (header names, `path`, `query`, `body`; `-` for none). For `evil` the
line holds the whole raw request, because whatever reaches an attacker's host is the
attacker's: if the real key ever got there, the oracle finds it in HITS_FILE.

The response reflects the request head and body in many forms: raw, base64, base64url, hex,
percent and JSON escapes of every header, the decoded user:pass of Basic auth, and the parts of
the Authorization value. The same text goes into response headers (X-Echo-*, Set-Cookie,
Location, WWW-Authenticate). The query selects how the body is sent:
  enc=gzip|deflate|br|zstd   Content-Encoding (br and zstd are stored blocks: stdlib only)
  enc=gzip,gzip              two codings stacked
  dup=1                      `Content-Encoding: gzip` on two header lines, gzipped twice
  te=gzip                    Transfer-Encoding: gzip, chunked (no Content-Encoding)
  split=1                    chunked, one byte per chunk with pauses (cross-chunk redaction)
  sse=1                      text/event-stream, dripped in pieces 60 ms apart
  redirect=301|302|303|307|308 &to=URL   that status with `Location: URL` and the usual echo
"""
import base64
import gzip
import json
import struct
import sys
import time
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

role, port_file, hits_file = sys.argv[1:4]
canary = open(sys.argv[4]).read().strip() if len(sys.argv) > 4 else None


def brotli_stored(data):
    """A valid brotli stream made of uncompressed meta-blocks (RFC 7932 section 9.2)."""
    out = bytearray()
    acc = nbits = 0

    def bits(v, n):
        nonlocal acc, nbits
        acc |= v << nbits
        nbits += n
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8

    def align():
        nonlocal acc, nbits
        if nbits:
            out.append(acc & 0xFF)
            acc = nbits = 0

    bits(0, 1)  # WBITS = 16
    for i in range(0, len(data), 16384):
        part = data[i:i + 16384]
        bits(0, 1)  # ISLAST = 0
        bits(0, 2)  # MNIBBLES = 4
        bits(len(part) - 1, 16)
        bits(1, 1)  # ISUNCOMPRESSED
        align()
        out += part
    bits(1, 1)  # ISLAST
    bits(1, 1)  # ISLASTEMPTY
    align()
    return bytes(out)


def zstd_raw(data):
    """A single-segment zstd frame of raw blocks (RFC 8878)."""
    out = bytearray(b"\x28\xb5\x2f\xfd")
    out.append(0xA0)  # FCS 4 bytes, single segment, no checksum, no dictionary
    out += struct.pack("<I", len(data))
    blocks = [data[i:i + 65536] for i in range(0, len(data), 65536)] or [b""]
    for n, b in enumerate(blocks):
        last = 1 if n == len(blocks) - 1 else 0
        out += struct.pack("<I", (len(b) << 3) | last)[:3]
        out += b
    return bytes(out)


ENCODE = {
    "gzip": gzip.compress,
    "deflate": zlib.compress,
    "br": brotli_stored,
    "zstd": zstd_raw,
}


def forms(name, value):
    """One header value in every encoding an echo could use."""
    raw = value.encode("latin-1")
    lines = [
        "%s: %s" % (name, value),
        "%s.b64: %s" % (name, base64.b64encode(raw).decode()),
        "%s.b64url: %s" % (name, base64.urlsafe_b64encode(raw).decode()),
        "%s.hex: %s" % (name, raw.hex()),
        "%s.pct: %s" % (name, urllib.parse.quote(value, safe="")),
    ]
    if name.lower() == "authorization":
        scheme, _, cred = value.partition(" ")
        lines.append("auth.scheme: %s" % scheme)
        lines.append("auth.credential: %s" % cred)
        if scheme.lower() == "basic":
            try:
                lines.append("auth.basic-decoded: %s" % base64.b64decode(cred).decode("latin-1"))
            except ValueError:
                pass
    return lines


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        pass

    def body(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            out = b""
            while True:
                n = int(self.rfile.readline().split(b";")[0].strip(), 16)
                if n == 0:
                    while self.rfile.readline().strip():
                        pass
                    return out
                out += self.rfile.read(n)
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def hit(self, data):
        with open(hits_file, "ab") as f:
            if role == "evil":
                head = "%s %s %s\r\n%s\r\n" % (self.command, self.path, self.request_version, self.headers)
                f.write(b"===== evil host received:\n" + head.encode("latin-1") + data + b"\n")
            else:
                names = ",".join(sorted(k.lower() for k in self.headers.keys()))
                seen = [self.path] + [v for _k, v in self.headers.items()]
                seen += [base64.b64decode(v.split(" ", 1)[1] + "==").decode("latin-1", "replace")
                         for v in self.headers.get_all("Authorization", []) if v.lower().startswith("basic ")]
                ok = "ok" if canary and any(canary in v for v in seen) else "no"
                where = []
                if canary:
                    path, _, query = self.path.partition("?")
                    for k, v in self.headers.items():
                        dec = v
                        if v.lower().startswith("basic "):
                            try:
                                dec = base64.b64decode(v.split(" ", 1)[1] + "==").decode("latin-1", "replace")
                            except ValueError:
                                pass
                        if canary in v or canary in dec:
                            where.append(k.lower())
                    if canary in urllib.parse.unquote(path):
                        where.append("path")
                    if canary in urllib.parse.unquote(query):
                        where.append("query")
                    if canary.encode() in data:
                        where.append("body")
                f.write(("%s %s headers=%s key=%s where=%s\n" % (
                    self.command, self.path.split("?")[0], names, ok, ",".join(where) or "-")).encode())

    def serve(self):
        data = self.body()
        self.hit(data)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        lines = ["role: %s" % role, "request: %s %s" % (self.command, self.path)]
        for k, v in self.headers.items():
            lines += forms(k, v)
        lines.append("body: %s" % data.decode("latin-1"))
        lines.append("json: %s" % json.dumps({k: v for k, v in self.headers.items()}))
        text = ("\n".join(lines) + "\n").encode("latin-1")

        auth = self.headers.get("Authorization", "")
        hdrs = [
            ("Content-Type", "text/event-stream" if q.get("sse") else "text/plain; charset=utf-8"),
            ("X-Echo-Authorization", auth),
            ("X-Echo-Authorization-B64", base64.b64encode(auth.encode("latin-1")).decode()),
            ("X-Echo-Api-Key", self.headers.get("X-Api-Key", "")),
            ("Set-Cookie", "session=%s; Path=/" % urllib.parse.quote(auth, safe="")),
            ("Location", "https://example.invalid/back?auth=%s" % urllib.parse.quote(auth, safe="")),
            ("WWW-Authenticate", 'Bearer error="invalid_token", token="%s"' % auth),
            ("Connection", "close"),
        ]
        self.close_connection = True
        enc = q.get("enc", [""])[0]
        if q.get("split") or q.get("sse"):
            return self.drip(hdrs, text, one_byte=bool(q.get("split")))
        if q.get("te"):
            self.send_response(200)
            for k, v in hdrs:
                self.send_header(k, v)
            self.send_header("Transfer-Encoding", "gzip, chunked")
            self.end_headers()
            z = gzip.compress(text)
            self.wfile.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(z), z))
            return
        if q.get("dup"):
            # The same coding named on two header lines, applied twice.
            self.send_response(200)
            for k, v in hdrs + [("Content-Encoding", "gzip"), ("Content-Encoding", "gzip")]:
                self.send_header(k, v)
            payload = gzip.compress(gzip.compress(text))
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if q.get("redirect"):
            # A redirect toward another host; the relay must not follow it.
            code = int(q["redirect"][0])
            self.send_response(code)
            for k, v in hdrs:
                if k != "Location":
                    self.send_header(k, v)
            self.send_header("Location", q.get("to", ["/"])[0])
            self.send_header("Content-Length", str(len(text)))
            self.end_headers()
            self.wfile.write(text)
            return
        payload = text
        if enc:
            for e in enc.split(","):
                payload = ENCODE[e](payload)
            hdrs.append(("Content-Encoding", ", ".join(enc.split(","))))
        self.send_response(200)
        for k, v in hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def drip(self, hdrs, text, one_byte):
        self.send_response(200)
        for k, v in hdrs:
            self.send_header(k, v)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        step = 1 if one_byte else 29
        for i in range(0, len(text), step):
            part = text[i:i + step]
            self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.flush()
            # Pauses longer than the relay's 20 ms idle flush, often enough to split the key.
            if not one_byte or i % 16 == 0:
                time.sleep(0.03)
        self.wfile.write(b"0\r\n\r\n")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = serve


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
open(port_file, "w").write(str(srv.server_address[1]))
srv.serve_forever()
