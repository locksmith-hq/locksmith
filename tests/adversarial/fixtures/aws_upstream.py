#!/usr/bin/env python3
"""Fixture AWS for gate A2: a fake STS + S3 that verifies SigV4, and a small SigV4 client.

  serve PORT_FILE CANARY_FILE AKID_FILE LOG_FILE TEMP_FILE
      Listens on 127.0.0.1 (random port, written to PORT_FILE). Accepts only requests signed with
      the real key (AKID_FILE + the canary as secret) or with STS credentials it issued itself.
      Speaks sts GetCallerIdentity / AssumeRole and S3 ListObjectsV2 (anything else: 200 empty).
      One line per request in LOG_FILE: method, host, path, action, auth=real|sts|bad:<why>, and
      for AssumeRole duration=<n> policy=yes|no. Never logs keys or signatures. The secret of the
      last issued STS credentials goes to TEMP_FILE (it is not the canary; the case checks that
      the contained child's output redacts it).
  sign PORT RAW_OUT [ACTION]
      Sends sts:<ACTION> (default GetCallerIdentity) to 127.0.0.1:PORT, signed with
      AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the environment, and saves the raw request
      bytes in RAW_OUT. Prints `status=<code> <AWS error code or ok>`.
  replay PORT RAW_IN
      Sends RAW_IN unchanged and prints the same summary.
"""
import datetime
import hashlib
import hmac
import os
import re
import secrets
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REGION = "us-east-1"


def enc(s, safe="-_.~"):
    return urllib.parse.quote(s, safe=safe)


def canonical_query(q):
    kv = []
    for p in q.split("&"):
        if not p:
            continue
        k, _, v = p.partition("=")
        kv.append((enc(urllib.parse.unquote(k)), enc(urllib.parse.unquote(v))))
    return "&".join("%s=%s" % x for x in sorted(kv))


def canonical_uri(path, service):
    if service == "s3":
        return path  # already encoded on the wire; S3 does not double-encode
    return enc(path, safe="-_.~/")


def signature(secret, date, region, service, string_to_sign):
    k = ("AWS4" + secret).encode()
    for part in (date, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    return hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()


def string_to_sign(method, path, query, headers, signed, payload_hash, amz_date, scope, service):
    lines = [method, canonical_uri(path, service), canonical_query(query)]
    for name in signed:
        vals = [" ".join(v.split()) for k, v in headers if k.lower() == name]
        lines.append("%s:%s" % (name, ",".join(vals)))
    creq = "\n".join(lines) + "\n\n" + ";".join(signed) + "\n" + payload_hash
    return "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (amz_date, scope, hashlib.sha256(creq.encode()).hexdigest())


def serve(port_file, canary_file, akid_file, log_file, temp_file):
    creds = {open(akid_file).read().strip(): (open(canary_file).read().strip(), "real")}
    log = open(log_file, "a", buffering=1)

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, code, body, ctype="text/xml"):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b)

        def deny(self, line, why):
            log.write("%s auth=bad:%s\n" % (line, why))
            self.reply(403, "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code>"
                            "<Message>fake upstream: %s</Message></Error></ErrorResponse>" % why)

        def handle_any(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            hs = list(self.headers.items())
            host = self.headers.get("Host", "")
            path, _, query = self.path.partition("?")
            form = dict(urllib.parse.parse_qsl(body.decode("utf-8", "replace"))) \
                if "x-www-form-urlencoded" in (self.headers.get("Content-Type") or "") else {}
            action = form.get("Action") or ("s3:" + self.command)
            line = "%s %s %s action=%s" % (self.command, host, path, action)
            m = re.match(r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request,"
                         r"\s*SignedHeaders=([^,]+),\s*Signature=([0-9a-f]{64})$",
                         self.headers.get("Authorization", ""))
            if not m:
                return self.deny(line, "no-sigv4")
            akid, date, region, service, signed, sig = m.groups()
            if akid not in creds:
                return self.deny(line, "unknown-key")
            secret, kind = creds[akid]
            amz_date = self.headers.get("X-Amz-Date", "")
            try:
                t = datetime.datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                return self.deny(line, "no-date")
            if abs((datetime.datetime.now(datetime.timezone.utc) - t).total_seconds()) > 900 or amz_date[:8] != date:
                return self.deny(line, "stale")
            if kind == "sts" and not self.headers.get("X-Amz-Security-Token"):
                return self.deny(line, "no-session-token")
            ph = self.headers.get("X-Amz-Content-SHA256") or hashlib.sha256(body).hexdigest()
            scope = "%s/%s/%s/aws4_request" % (date, region, service)
            sts_ = string_to_sign(self.command, path, query, hs, signed.split(";"), ph, amz_date, scope, service)
            if not hmac.compare_digest(signature(secret, date, region, service, sts_), sig):
                return self.deny(line, "signature")
            line += " auth=" + kind
            if action == "AssumeRole":
                line += " duration=%s policy=%s" % (form.get("DurationSeconds"), "yes" if form.get("Policy") else "no")
                tid = "ASIA" + secrets.token_hex(8).upper()
                tsec, ttok = secrets.token_urlsafe(30), secrets.token_urlsafe(60)
                creds[tid] = (tsec, "sts")
                with open(temp_file, "w") as f:
                    f.write(tsec)
                exp = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
                log.write(line + "\n")
                return self.reply(200, "<AssumeRoleResponse><AssumeRoleResult><Credentials>"
                                       "<AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey>"
                                       "<SessionToken>%s</SessionToken><Expiration>%s</Expiration>"
                                       "</Credentials><AssumedRoleUser><Arn>%s</Arn><AssumedRoleId>AROAFAKE:s</AssumedRoleId>"
                                       "</AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>"
                                  % (tid, tsec, ttok, exp, form.get("RoleArn", "")))
            log.write(line + "\n")
            if action == "GetCallerIdentity":
                arn = "arn:aws:iam::123456789012:user/dev" if kind == "real" else "arn:aws:sts::123456789012:assumed-role/ops/locksmith"
                return self.reply(200, "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>%s</Arn>"
                                       "<UserId>AIDAFAKEUSER</UserId><Account>123456789012</Account>"
                                       "</GetCallerIdentityResult><ResponseMetadata><RequestId>fake</RequestId>"
                                       "</ResponseMetadata></GetCallerIdentityResponse>" % arn)
            if service == "s3" and self.command == "GET" and "list-type=2" in query:
                bucket = host.split(".s3.")[0] if ".s3." in host else path.strip("/").split("/")[0]
                return self.reply(200, '<?xml version="1.0" encoding="UTF-8"?>'
                                       '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                                       "<Name>%s</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys>"
                                       "<Delimiter>/</Delimiter><IsTruncated>false</IsTruncated><Contents><Key>x</Key>"
                                       "<LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag>"
                                       "<Size>0</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>" % bucket,
                                  "application/xml")
            self.reply(200, "")

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = handle_any

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    with open(port_file + ".tmp", "w") as f:
        f.write(str(srv.server_address[1]))
    os.rename(port_file + ".tmp", port_file)
    srv.serve_forever()


def summary(data):
    status = data.split(b"\r\n", 1)[0].decode("latin-1")
    code = re.search(rb"<Code>([^<]+)</Code>", data)
    print("status=%s %s" % (status.split(" ")[1] if " " in status else "none",
                            code.group(1).decode() if code else "ok"))


def send(port, raw):
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.sendall(raw)
    data = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
    summary(data)


def sign(port, raw_out, action="GetCallerIdentity"):
    akid, secret = os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"]
    body = "Action=%s&Version=2011-06-15" % action
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    host = "127.0.0.1:%d" % port
    ctype = "application/x-www-form-urlencoded; charset=utf-8"
    hs = [("host", host), ("content-type", ctype), ("x-amz-date", amz_date)]
    signed = ["content-type", "host", "x-amz-date"]
    scope = "%s/%s/sts/aws4_request" % (date, REGION)
    sts_ = string_to_sign("POST", "/", "", hs, signed, hashlib.sha256(body.encode()).hexdigest(), amz_date, scope, "sts")
    auth = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
        akid, scope, ";".join(signed), signature(secret, date, REGION, "sts", sts_))
    raw = ("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nX-Amz-Date: %s\r\nAuthorization: %s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (host, ctype, amz_date, auth, len(body), body)).encode()
    with open(raw_out, "wb") as f:
        f.write(raw)
    send(port, raw)


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "serve":
        serve(*args)
    elif cmd == "sign":
        sign(int(args[0]), *args[1:])
    elif cmd == "replay":
        send(int(args[0]), open(args[1], "rb").read())
    else:
        sys.exit("usage: aws_upstream.py serve|sign|replay ...")
