#!/usr/bin/env python3
"""Fixture upstream MCP server (Streamable HTTP) for the gateway's MCP proxy (change m2-mcp-gateway).

Usage: python3 -I mcp_upstream.py MODE PORT_FILE HEADERS_LOG [REDIRECT_URL]
       python3 -I mcp_upstream.py --selftest

Listens on 127.0.0.1 (random port, written to PORT_FILE). POST /mcp (or any path) takes one JSON-RPC
message and answers with JSON, or with a `text/event-stream` body when the query has `sse=1`.
Handled methods: initialize, notifications/* (202), ping, tools/list, tools/call; anything else is a
JSON-RPC error -32601. Tools: list_issues (readOnlyHint), create_issue, delete_repository
(destructiveHint) and echo (returns its `text` argument).

MODE:
  normal           plain answers.
  echo-credential  the received credential (the Authorization value after its scheme, or the value of
                   X-Api-Key) is put into a tool result, a tool description in tools/list, structured
                   content, a tool error, a JSON-RPC error and, in SSE mode, an extra SSE event, raw and
                   base64 (the proxy's redaction must catch every one of them).
  echo-credential-sse  as echo-credential, every answer as a `text/event-stream` body (the gateway's URL
                   cannot carry `?sse=1`).
  huge             normal, but `echo` returns 2 MiB of text (a body the redactor cannot scan).
  redirect         every request answers 307 with `Location: REDIRECT_URL` (default
                   http://127.0.0.1:1/never) and nothing else.

HEADERS_LOG gets one JSON line per request: method, path and the received header names with values.
It holds the very credential the proxy injects, so keep it in a private directory, never in
ARTIFACT_DIR; the adversarial runner reads it and deletes it.
"""
import base64
import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PROTOCOL = "2025-06-18"

TOOLS = [
    {
        "name": "list_issues",
        "description": "List open issues.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "create_issue",
        "description": "Create an issue.",
        "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}}},
    },
    {
        "name": "delete_repository",
        "description": "Delete a repository.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"destructiveHint": True},
    },
    {
        "name": "echo",
        "description": "Return the text argument.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    },
]


def credential_of(headers):
    """The credential the caller sent: the Authorization value without its scheme, or X-Api-Key."""
    auth = headers.get("Authorization")
    if auth:
        return auth.split(" ", 1)[1] if " " in auth else auth
    return headers.get("X-Api-Key") or ""


def forms(cred):
    """The credential raw and base64, the two forms the echo modes plant."""
    return cred, base64.b64encode(cred.encode()).decode()


def rpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def rpc_error(req_id, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def handle(msg, mode, cred):
    """One JSON-RPC message in, `(response or None, extra SSE events)` out."""
    method = msg.get("method")
    req_id = msg.get("id")
    echo = mode == "echo-credential" and cred
    raw, b64 = forms(cred) if echo else ("", "")
    if req_id is None:  # a notification
        return None, []
    if method == "initialize":
        return rpc_result(req_id, {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-upstream-fixture", "version": "0"},
        }), []
    if method == "ping":
        return rpc_result(req_id, {}), []
    if method == "tools/list":
        tools = json.loads(json.dumps(TOOLS))
        if echo:
            tools[0]["description"] += f" token={raw} b64={b64}"
        return rpc_result(req_id, {"tools": tools}), []
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        known = {t["name"] for t in TOOLS}
        if name not in known:
            data = {"credential": raw, "b64": b64} if echo else None
            return rpc_error(req_id, -32602, f"unknown tool {name}" + (f" ({raw})" if echo else ""), data), []
        text = str(args.get("text", "ok")) if name == "echo" else "ok"
        if mode == "huge" and name == "echo":
            text = "x" * (2 * 1024 * 1024)  # over the redactor's 1 MiB bound: unscannable
        result = {"content": [{"type": "text", "text": text}]}
        extra = []
        if echo:
            result["content"].append({"type": "text", "text": f"credential={raw}"})
            result["content"].append({"type": "text", "text": f"b64={b64}"})
            result["content"].append({"type": "text", "text": f"hex={raw.encode().hex()}"})
            result["content"].append({"type": "text", "text": json.dumps({"nested": json.dumps({"credential": raw})})})
            result["structuredContent"] = {"credential": raw, "b64": b64}
            extra.append(rpc_notification_with(raw, b64))
            if name == "create_issue":
                result["isError"] = True
                result["content"].append({"type": "text", "text": f"failed with {raw}"})
        return rpc_result(req_id, result), extra
    return rpc_error(req_id, -32601, "method not found"), []


def rpc_notification_with(raw, b64):
    return {"jsonrpc": "2.0", "method": "notifications/message",
            "params": {"level": "info", "data": f"credential={raw} b64={b64}"}}


def make_handler(mode, headers_log, redirect_url):
    lock = threading.Lock()
    force_sse = mode == "echo-credential-sse"
    if force_sse:
        mode = "echo-credential"

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def _record(self, rpc=None, tool=None):
            line = json.dumps({"method": self.command, "path": self.path, "rpc": rpc, "tool": tool,
                               "headers": dict(self.headers.items())})
            with lock, os.fdopen(os.open(headers_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a") as f:
                f.write(line + "\n")

        def _send(self, status, body=b"", ctype="application/json", extra=()):
            self.send_response(status)
            if body:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._record()
            self._send(405, b"", extra=[("Allow", "POST")])

        def do_DELETE(self):
            self._record()
            self._send(200)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            try:
                first = json.loads(body)
                rpc = first.get("method") if isinstance(first, dict) else "batch"
                tool = (first.get("params") or {}).get("name") if isinstance(first, dict) else None
            except ValueError:
                rpc, tool = None, None
            self._record(rpc, tool if isinstance(tool, str) else None)
            if mode == "redirect":
                self._send(307, b"", extra=[("Location", redirect_url)])
                return
            try:
                msg = json.loads(body)
            except ValueError:
                self._send(400, json.dumps(rpc_error(None, -32700, "parse error")).encode())
                return
            if not isinstance(msg, dict):  # batches are not part of this fixture
                self._send(400, json.dumps(rpc_error(None, -32600, "invalid request")).encode())
                return
            cred = credential_of(self.headers)
            response, extra = handle(msg, mode, cred)
            if response is None:
                self._send(202)
                return
            sse = force_sse or parse_qs(urlsplit(self.path).query).get("sse") == ["1"]
            if not sse:
                self._send(200, json.dumps(response).encode())
                return
            events = [*extra, response]
            if mode == "echo-credential" and cred:
                events.insert(0, {"jsonrpc": "2.0", "method": "notifications/message",
                                  "params": {"level": "debug", "data": cred}})
            payload = "".join(f"event: message\ndata: {json.dumps(e)}\n\n" for e in events).encode()
            self._send(200, payload, "text/event-stream")

    return Handler


def serve(mode, headers_log, redirect_url="http://127.0.0.1:1/never"):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(mode, headers_log, redirect_url))
    server.daemon_threads = True
    return server


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_a, **_k):
        return None


def post(port, msg, headers=None, query=""):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp{query}", data=json.dumps(msg).encode(), method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **(headers or {})})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def selftest():
    import tempfile
    canary = "canary-credential-0123456789abcdef"
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "headers.log")

        def start(mode, redirect_url="http://127.0.0.1:1/never"):
            s = serve(mode, log, redirect_url)
            threading.Thread(target=s.serve_forever, daemon=True).start()
            return s, s.server_address[1]

        def call(port, name, args=None, headers=None, query=""):
            return post(port, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                               "params": {"name": name, "arguments": args or {}}}, headers, query)

        auth = {"Authorization": f"Bearer {canary}"}
        b64 = base64.b64encode(canary.encode()).decode()

        s, port = start("normal")
        st, _, body = post(port, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, auth)
        assert st == 200 and json.loads(body)["result"]["protocolVersion"] == PROTOCOL
        st, _, _ = post(port, {"jsonrpc": "2.0", "method": "notifications/initialized"}, auth)
        assert st == 202
        st, _, body = post(port, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, auth)
        tools = {t["name"]: t for t in json.loads(body)["result"]["tools"]}
        assert set(tools) == {"list_issues", "create_issue", "delete_repository", "echo"}
        assert tools["list_issues"]["annotations"]["readOnlyHint"] is True
        assert tools["delete_repository"]["annotations"]["destructiveHint"] is True
        assert "annotations" not in tools["create_issue"]
        st, _, body = call(port, "echo", {"text": "hello"}, auth)
        assert json.loads(body)["result"]["content"][0]["text"] == "hello"
        st, _, body = call(port, "echo", {"text": "hello"}, auth, "?sse=1")
        assert st == 200 and body.startswith("event: message\ndata: ") and body.endswith("\n\n")
        st, _, body = post(port, {"jsonrpc": "2.0", "id": 3, "method": "resources/list"}, auth)
        assert json.loads(body)["error"]["code"] == -32601
        assert canary not in body
        # normal mode never repeats the credential anywhere
        for q in ("", "?sse=1"):
            for name in ("echo", "create_issue", "nope"):
                assert canary not in call(port, name, {"text": "x"}, auth, q)[2]
        s.shutdown()

        s, port = start("echo-credential")
        st, _, body = post(port, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, auth)
        assert canary in body and b64 in body  # description
        st, _, body = call(port, "echo", {"text": "x"}, auth)
        msg = json.loads(body)["result"]
        assert canary in json.dumps(msg["content"]) and msg["structuredContent"]["credential"] == canary
        assert msg["structuredContent"]["b64"] == b64
        st, _, body = call(port, "create_issue", {}, auth)
        assert json.loads(body)["result"]["isError"] is True and canary in body
        st, _, body = call(port, "nope", {}, auth)
        err = json.loads(body)["error"]
        assert canary in err["message"] and err["data"]["b64"] == b64
        st, _, body = call(port, "echo", {"text": "x"}, auth, "?sse=1")
        assert body.count(canary) >= 3 and b64 in body
        st, _, body = call(port, "echo", {"text": "x"}, {"X-Api-Key": canary})
        assert canary in body
        st, _, body = call(port, "echo", {"text": "x"})  # no credential, nothing to echo
        assert "credential=" not in body
        s.shutdown()

        s, port = start("redirect", "http://127.0.0.1:1/elsewhere")
        st, hdrs, body = call(port, "echo", {}, auth)
        assert st == 307 and hdrs["Location"] == "http://127.0.0.1:1/elsewhere" and body == ""
        s.shutdown()

        lines = [json.loads(line) for line in open(log)]
        assert lines and all(line["method"] == "POST" for line in lines)
        assert any(line["headers"].get("Authorization") == f"Bearer {canary}" for line in lines)
    print("mcp_upstream selftest ok")


def main():
    if sys.argv[1:] == ["--selftest"]:
        selftest()
        return
    if len(sys.argv) not in (4, 5) or sys.argv[1] not in ("normal", "echo-credential", "echo-credential-sse", "huge", "redirect"):
        sys.exit(__doc__)
    mode, port_file, headers_log = sys.argv[1:4]
    server = serve(mode, headers_log, *(sys.argv[4:5]))
    with open(port_file, "w") as f:
        f.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
