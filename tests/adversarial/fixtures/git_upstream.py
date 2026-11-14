#!/usr/bin/env python3
"""Fixture Git upstream for gate A1: `git http-backend` behind Basic auth (x-access-token:<canary>).

Usage: python3 -I git_upstream.py ROOT CANARY_FILE PORT_FILE
Serves ROOT/<owner>/<repo>.git on 127.0.0.1 (random port, written to PORT_FILE). Never logs credentials.
"""
import base64
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

root, canary_file, port_file = sys.argv[1:4]
canary = open(canary_file).read().strip()
WANT = "Basic " + base64.b64encode(("x-access-token:" + canary).encode()).decode()


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

    def send(self, status, headers, data):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def serve(self):
        data = self.body()
        ok = self.headers.get("Authorization") == WANT
        sys.stderr.write("%s %s auth=%s\n" % (self.command, self.path, "ok" if ok else "bad"))
        sys.stderr.flush()
        if not ok:
            return self.send(401, [("WWW-Authenticate", 'Basic realm="upstream"')], b"auth required")
        path, _, query = self.path.partition("?")
        env = {
            "GIT_PROJECT_ROOT": root,
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": self.command,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(data)),
            "REMOTE_USER": "x-access-token",
            "REMOTE_ADDR": "127.0.0.1",
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        }
        for h, e in (("Git-Protocol", "HTTP_GIT_PROTOCOL"), ("Content-Encoding", "HTTP_CONTENT_ENCODING")):
            if self.headers.get(h):
                env[e] = self.headers[h]
        p = subprocess.run(["git", "http-backend"], input=data, env=env, capture_output=True)
        head, _, out = p.stdout.partition(b"\r\n\r\n")
        status, hdrs = 200, []
        for line in head.decode("latin-1").split("\r\n"):
            k, _, v = line.partition(":")
            if k.lower() == "status":
                status = int(v.split()[0])
            elif k:
                hdrs.append((k, v.strip()))
        self.send(status, hdrs, out)

    do_GET = do_POST = serve


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
open(port_file, "w").write(str(srv.server_address[1]))
srv.serve_forever()
