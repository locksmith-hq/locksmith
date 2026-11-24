#!/usr/bin/env python3
"""Mock gateway for the agent client and framework adapter tests (p5 task 1.4).

Standard library only; run as `python3 -I tests/kit/mock_gateway.py`. Everything it serves comes from
`tests/kit/agent-contract/`. It logs method, path and status only (never headers or bodies) and prints
`port=<n>` on its first stdout line.

Routes: POST /v1/agent-tokens, GET /v1/grants, POST /v1/relay and POST /mcp (Streamable HTTP, JSON
replies). Gateway routes check `Authorization: Bearer <token>` against the last token issued.
"""
import argparse
import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "agent-contract"


def load(name):
    return json.loads((FIXTURES / name).read_text())


class State:
    def __init__(self, args):
        self.ttl = args.token_ttl
        self.tools_file = "mcp-tools-unsafe.json" if args.tools == "unsafe" else "mcp-tools.json"
        self.fail = args.fail
        self.errors = {e["slug"]: e["status"] for e in load("errors.json")}
        if self.fail and self.fail not in self.errors:
            sys.exit("unknown error slug: " + self.fail)
        self.lock = threading.Lock()
        self.issued = 0
        self.current = None  # the one valid token
        self.expires = 0.0

    def issue(self):
        with self.lock:
            self.issued += 1
            base = load("agent-token.json")
            token = "%s-%d" % (base["access_token"], self.issued)
            self.current = token
            self.expires = time.time() + self.ttl
            exp = datetime.now(timezone.utc) + timedelta(seconds=self.ttl)
            return dict(
                base,
                access_token=token,
                expires_in=self.ttl,
                expires_at=exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )

    def valid(self, header):
        with self.lock:
            return (
                self.current is not None
                and time.time() < self.expires
                and header == "Bearer " + self.current
            )

    def revoke(self):
        with self.lock:
            self.current = None


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *a):  # replaced by log_done: method, path, status only
            pass

        def send_json(self, status, body, extra=None):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)
            sys.stderr.write("%s %s %d\n" % (self.command, self.path.split("?")[0], status))
            sys.stderr.flush()

        def fail(self, slug):
            self.send_json(state.errors[slug], {"error": slug, "request_id": "mock-request"})

        def body(self):
            n = int(self.headers.get("content-length") or 0)
            return self.rfile.read(n) if n else b""

        def gateway_auth(self):
            """True when the request may proceed; otherwise the reply is already sent."""
            if state.fail:
                self.body()
                self.fail(state.fail)
                return False
            if not state.valid(self.headers.get("authorization")):
                self.body()
                self.fail("unauthenticated")
                return False
            return True

        def do_GET(self):
            if self.path.split("?")[0] == "/v1/grants":
                if self.gateway_auth():
                    self.send_json(200, load("grants.json"))
            else:
                self.send_json(404, {"error": "not_found", "request_id": "mock-request"})

        def do_POST(self):
            path = self.path.split("?")[0]
            if path == "/v1/agent-tokens":
                raw = self.body()
                try:
                    secret = json.loads(raw).get("enrollment_secret")
                except (ValueError, AttributeError):
                    secret = None
                if state.fail:
                    self.fail(state.fail)
                elif not isinstance(secret, str) or not secret:
                    self.fail("bad_request")
                else:
                    self.send_json(200, state.issue())
            elif path == "/v1/relay":
                if not self.gateway_auth():
                    return
                try:
                    req = json.loads(self.body())
                    ok = isinstance(req, dict) and {"secret_id", "method", "url"} <= req.keys()
                except ValueError:
                    ok = False
                if ok:
                    self.send_json(200, load("relay-response.json"))
                else:
                    self.fail("bad_request")
            elif path == "/mcp":
                if self.gateway_auth():
                    self.mcp()
            else:
                self.body()
                self.send_json(404, {"error": "not_found", "request_id": "mock-request"})

        def do_DELETE(self):  # MCP session close
            if self.path.split("?")[0] == "/mcp":
                self.send_json(200, {})
            else:
                self.send_json(404, {"error": "not_found", "request_id": "mock-request"})

        def mcp(self):
            try:
                msg = json.loads(self.body())
            except ValueError:
                return self.send_json(400, {"jsonrpc": "2.0", "id": None,
                                            "error": {"code": -32700, "message": "parse error"}})
            if not isinstance(msg, dict):
                return self.send_json(400, {"jsonrpc": "2.0", "id": None,
                                            "error": {"code": -32600, "message": "invalid request"}})
            mid, method = msg.get("id"), msg.get("method")
            if mid is None:  # notification, e.g. notifications/initialized
                self.send_response(202)
                self.send_header("content-length", "0")
                self.end_headers()
                sys.stderr.write("POST /mcp 202\n")
                return
            if method == "initialize":
                result = {
                    "protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "mock-gateway", "version": "0"},
                }
                return self.send_json(200, {"jsonrpc": "2.0", "id": mid, "result": result},
                                      {"mcp-session-id": "mock-session"})
            if method == "tools/list":
                return self.send_json(200, {"jsonrpc": "2.0", "id": mid,
                                            "result": {"tools": load(state.tools_file)}})
            if method == "tools/call":
                name = (msg.get("params") or {}).get("name")
                known = {t["name"] for t in load(state.tools_file)}
                if name not in known:
                    return self.send_json(200, {"jsonrpc": "2.0", "id": mid,
                                                "error": {"code": -32602, "message": "unknown tool"}})
                if name == "list_my_keys":
                    grants = load("grants.json")["grants"]
                    out = {"items": [
                        {"secret_id": g["secret_id"], "name": g["secret_name"], "mode": g["mode"],
                         "allowed_origin": g["allowed_origin"], "grant_expires_at": g["expires_at"]}
                        for g in grants], "next_cursor": None}
                elif name == "relay_http_request":
                    out = load("relay-response.json")
                elif name == "explain_block":
                    out = {"explanation": "mock", "next_step": "none", "rule": None}
                else:
                    out = {}
                return self.send_json(200, {"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": json.dumps(out)}],
                    "structuredContent": out, "isError": False}})
            self.send_json(200, {"jsonrpc": "2.0", "id": mid,
                                 "error": {"code": -32601, "message": "method not found"}})

    return Handler


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--token-ttl", type=int, default=900, help="seconds a token stays valid")
    p.add_argument("--tools", choices=["safe", "unsafe"], default="safe")
    p.add_argument("--fail", metavar="SLUG", help="answer every gateway route with this error slug")
    args = p.parse_args()
    state = State(args)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(state))
    print("port=%d" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
