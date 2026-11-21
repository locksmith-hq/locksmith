#!/usr/bin/env python3 -I
"""A stub STS for the AWS adversarial case (G11). Usage: sts_stub.py PORT_FILE HITS_LOG MODE_FILE CANARY_FILE

Serves `POST /` (an AssumeRole query call) on a free loopback port (written to PORT_FILE). Per
request it reads the mode from MODE_FILE:
  ok    a valid AssumeRole answer: fresh fake credentials, Expiration = now + DurationSeconds;
  err   HTTP 403 with an error body that echoes request details: the role ARN, a marker and the
        canary (as a broken or hostile STS could);
  leak  a valid-looking answer whose SessionToken contains the canary.
HITS_LOG gets one JSON line per request: Action, RoleArn, DurationSeconds, ExternalId, Policy and
the mode. Never the Authorization header or any credential. Fake credentials only.
"""
import datetime
import http.server
import json
import secrets
import sys
import urllib.parse

port_file, hits_log, mode_file, canary_file = sys.argv[1:5]
canary = open(canary_file).read().strip()
MARKER = "STS-ERR-MARKER-" + secrets.token_hex(6)
with open(mode_file + ".marker", "w") as fh:
    fh.write(MARKER)


def mode():
    try:
        return open(mode_file).read().strip() or "ok"
    except OSError:
        return "ok"


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        one = lambda k: (form.get(k) or [None])[0]
        m = mode()
        with open(hits_log, "a") as fh:
            fh.write(json.dumps({
                "mode": m, "Action": one("Action"), "RoleArn": one("RoleArn"),
                "DurationSeconds": one("DurationSeconds"), "ExternalId": one("ExternalId"),
                "Policy": one("Policy"),
            }) + "\n")
        if m == "err":
            body = ("<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>"
                    "<Message>%s role=%s detail=%s</Message></Error></ErrorResponse>"
                    % (MARKER, one("RoleArn"), canary)).encode()
            status = 403
        else:
            secs = int(one("DurationSeconds") or 900)
            exp = (datetime.datetime.now(datetime.timezone.utc)
                   + datetime.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
            token = ("tok" + secrets.token_hex(24)) + (canary if m == "leak" else "")
            body = ("<AssumeRoleResponse><AssumeRoleResult><Credentials>"
                    "<AccessKeyId>ASIA%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey>"
                    "<SessionToken>%s</SessionToken><Expiration>%s</Expiration>"
                    "</Credentials></AssumeRoleResult></AssumeRoleResponse>"
                    % (secrets.token_hex(8).upper(), secrets.token_urlsafe(30), token, exp)).encode()
            status = 200
        self.send_response(status)
        self.send_header("content-type", "text/xml")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
with open(port_file, "w") as fh:
    fh.write(str(srv.server_address[1]))
srv.serve_forever()
