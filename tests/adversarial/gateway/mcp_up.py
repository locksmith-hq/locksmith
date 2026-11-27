#!/usr/bin/env python3
"""Helper for the upstream-MCP adversarial cases (G15-G17; change m2-mcp-gateway, group 7).
Standard library only; it never prints a token. Run as `python3 -I mcp_up.py <command>`.

  call BASE_URL AUTH_HDR_FILE PATH CALLS_JSONL OUT_PREFIX
      MCP Streamable HTTP client for BASE_URL+PATH (for example /mcp/upstream/github). Sends
      `initialize` and `notifications/initialized`, then each line of CALLS_JSONL (a JSON-RPC
      request or a JSON array, which goes out as one batch), in one session. Every reply body
      (a JSON document, or each `data:` event of an SSE body) is one line of OUT_PREFIX.out, and
      `<id|batch> <http status>` goes to OUT_PREFIX.http. AUTH_HDR_FILE holds one
      `Authorization: Bearer ...` line. Exit 1 when `initialize` does not answer 200.
  tools REPLIES_FILE ID
      Prints the tool names of the `tools/list` reply with that id, one per line.
  outcome REPLIES_FILE ID
      Prints a one-line classification of the reply with that id: `error:<message>` for a JSON-RPC
      error, `tool-error` for a result with isError, `ok` for a result, `none` when absent.
"""
import json
import sys
import urllib.error
import urllib.request


def read_auth(path):
    line = open(path).read().strip()
    name, _, value = line.partition(": ")
    return name, value


def parse_body(raw, ctype):
    """Every JSON document in one HTTP body: the body itself, or each SSE `data:` payload."""
    text = raw.decode("utf-8", "replace")
    docs = []
    if "text/event-stream" in (ctype or ""):
        for block in text.split("\n\n"):
            data = "\n".join(l[5:].lstrip() for l in block.splitlines() if l.startswith("data:"))
            if data:
                docs.append(data)
    elif text.strip():
        docs.append(text.strip())
    return docs


class Client:
    def __init__(self, base, auth):
        self.base, self.auth, self.session = base, auth, None

    def post(self, path, payload):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                self.auth[0]: self.auth[1],
            },
        )
        if self.session:
            req.add_header("Mcp-Session-Id", self.session)
            req.add_header("MCP-Protocol-Version", "2025-06-18")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                sid = r.headers.get("Mcp-Session-Id")
                if sid and not self.session:
                    self.session = sid
                return r.status, parse_body(r.read(), r.headers.get("Content-Type"))
        except urllib.error.HTTPError as e:
            return e.code, parse_body(e.read(), e.headers.get("Content-Type"))
        except (urllib.error.URLError, OSError) as e:
            return 0, [json.dumps({"transport_error": type(e).__name__})]


def call(base, auth_file, path, calls_file, prefix):
    c = Client(base, read_auth(auth_file))
    out, http = open(prefix + ".out", "w"), open(prefix + ".http", "w")
    init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "adversarial", "version": "0"}}}
    st, docs = c.post(path, init)
    out.write("".join(d + "\n" for d in docs))
    http.write(f"0 {st}\n")
    if st != 200:
        sys.exit(1)
    c.post(path, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    for line in open(calls_file):
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        st, docs = c.post(path, msg)
        out.write("".join(d + "\n" for d in docs))
        http.write(f"{'batch' if isinstance(msg, list) else msg.get('id')} {st}\n")
    out.close()
    http.close()


def replies(path, rid):
    for line in open(path, errors="replace"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        for m in d if isinstance(d, list) else [d]:
            if isinstance(m, dict) and str(m.get("id")) == rid:
                yield m


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "call" and len(sys.argv) == 7:
        call(*sys.argv[2:])
    elif cmd == "tools" and len(sys.argv) == 4:
        for m in replies(sys.argv[2], sys.argv[3]):
            for t in (m.get("result") or {}).get("tools", []):
                print(t["name"])
    elif cmd == "outcome" and len(sys.argv) == 4:
        found = list(replies(sys.argv[2], sys.argv[3]))
        if not found:
            print("none")
        else:
            m = found[0]
            if "error" in m:
                print("error:" + str(m["error"].get("message")))
            elif (m.get("result") or {}).get("isError"):
                print("tool-error")
            else:
                print("ok")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
