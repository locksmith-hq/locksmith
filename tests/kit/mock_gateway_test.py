#!/usr/bin/env python3
"""Self-test of mock_gateway.py. Run: python3 -I tests/kit/mock_gateway_test.py"""
import json
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATEWAY = HERE / "mock_gateway.py"
FIX = HERE / "agent-contract"


class Mock:
    def __init__(self, *args):
        self.proc = subprocess.Popen(
            [sys.executable, "-I", str(GATEWAY), *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.port = int(self.proc.stdout.readline().strip().split("=")[1])
        self.base = "http://127.0.0.1:%d" % self.port

    def call(self, method, path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("content-type", "application/json")
        if token:
            req.add_header("authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def token(self):
        return self.call("POST", "/v1/agent-tokens", {"enrollment_secret": "canary-enroll"})[1]["access_token"]

    def mcp(self, token, method, params=None, mid=1):
        return self.call("POST", "/mcp", {"jsonrpc": "2.0", "id": mid, "method": method,
                                          "params": params or {}}, token)

    def stop(self):
        self.proc.terminate()
        _, err = self.proc.communicate(timeout=5)
        return err


class T(unittest.TestCase):
    def setUp(self):
        self.m = None

    def tearDown(self):
        if self.m:
            self.m.stop()

    def test_token_grants_relay_round_trip(self):
        self.m = Mock()
        st, tok = self.m.call("POST", "/v1/agent-tokens", {"enrollment_secret": "canary-enroll"})
        self.assertEqual(st, 200)
        self.assertEqual(tok["token_type"], "Bearer")
        st, grants = self.m.call("GET", "/v1/grants", token=tok["access_token"])
        self.assertEqual((st, grants), (200, json.loads((FIX / "grants.json").read_text())))
        req = json.loads((FIX / "relay-request.json").read_text())
        st, resp = self.m.call("POST", "/v1/relay", req, tok["access_token"])
        self.assertEqual((st, resp), (200, json.loads((FIX / "relay-response.json").read_text())))

    def test_bearer_is_checked(self):
        self.m = Mock()
        self.assertEqual(self.m.call("GET", "/v1/grants")[0], 401)
        st, body = self.m.call("GET", "/v1/grants", token="wrong")
        self.assertEqual((st, body["error"]), (401, "unauthenticated"))
        self.assertEqual(self.m.call("POST", "/mcp", {}, "wrong")[0], 401)

    def test_token_expires_and_renews(self):
        self.m = Mock("--token-ttl", "1")
        t1 = self.m.token()
        self.assertEqual(self.m.call("GET", "/v1/grants", token=t1)[0], 200)
        time.sleep(1.3)
        self.assertEqual(self.m.call("GET", "/v1/grants", token=t1)[0], 401)
        t2 = self.m.token()
        self.assertNotEqual(t1, t2)
        self.assertEqual(self.m.call("GET", "/v1/grants", token=t2)[0], 200)
        self.assertEqual(self.m.call("GET", "/v1/grants", token=t1)[0], 401)

    def test_mcp_initialize_and_tools(self):
        self.m = Mock()
        t = self.m.token()
        st, r = self.m.mcp(t, "initialize", {"protocolVersion": "2025-03-26"})
        self.assertEqual(st, 200)
        self.assertIn("tools", r["result"]["capabilities"])
        st, r = self.m.mcp(t, "tools/list", mid=2)
        names = [x["name"] for x in r["result"]["tools"]]
        self.assertEqual(names, [x["name"] for x in json.loads((FIX / "mcp-tools.json").read_text())])
        st, r = self.m.mcp(t, "tools/call", {"name": "list_my_keys", "arguments": {}}, mid=3)
        self.assertEqual(r["result"]["structuredContent"]["items"][0]["name"], "stripe-test")
        st, r = self.m.mcp(t, "tools/call", {"name": "get_secret_value"}, mid=4)
        self.assertIn("error", r)

    def test_unsafe_tools(self):
        self.m = Mock("--tools", "unsafe")
        t = self.m.token()
        _, r = self.m.mcp(t, "tools/list")
        names = [x["name"] for x in r["result"]["tools"]]
        self.assertIn("get_secret_value", names)
        self.assertIn("issue_short_lived_credential", names)

    def test_fail_slug(self):
        self.m = Mock("--fail", "no_grant")
        st, body = self.m.call("GET", "/v1/grants", token="x")
        self.assertEqual((st, body["error"]), (403, "no_grant"))

    def test_log_has_method_path_status_only(self):
        self.m = Mock()
        t = self.m.token()
        self.m.call("GET", "/v1/grants", token=t)
        err = self.m.stop()
        self.m = None
        self.assertNotIn(t, err)
        self.assertIn("GET /v1/grants 200", err)
        for line in err.strip().splitlines():
            self.assertEqual(len(line.split()), 3, line)


if __name__ == "__main__":
    unittest.main()
