#!/usr/bin/env python3
"""Generate crates/ls-proxy/src/aws/data/aws-model.json from botocore service models.

The output is a compact operation table used by `ls_proxy::aws::model` to map a request to an
IAM action. It is derived from botocore's service-2.json files (Apache-2.0, Copyright Amazon.com,
Inc. or its affiliates; https://github.com/boto/botocore).

Regenerate:
    python3 scripts/gen-aws-model.py [BOTOCORE_DATA_DIR]

BOTOCORE_DATA_DIR defaults to an installed `botocore` package's data dir, then to the AWS CLI v2
bundle at /usr/local/aws-cli/awscli/botocore/data.
"""

import json
import os
import re
import sys

# botocore directory name -> overrides. Keys are botocore dirs; the table is keyed by signing name.
SERVICES = [
    "s3", "sts", "dynamodb", "sqs", "sns", "lambda", "ssm", "secretsmanager", "kms", "logs",
    "ec2", "iam", "ecr", "cloudformation", "events", "stepfunctions",
]
SUPPORTED = {"json", "query", "rest-json", "rest-xml", "ec2"}
# SQS moved from query to JSON (AmazonSQS target) in 2024; current SDKs send either form.
EXTRA = {"sqs": {"protocols": ["json", "query"], "targets": ["AmazonSQS"]}}

OUT = os.path.join(os.path.dirname(__file__), "..", "crates", "ls-proxy", "src", "aws", "data",
                   "aws-model.json")


def data_dir():
    if len(sys.argv) > 1:
        return sys.argv[1]
    try:
        import botocore  # noqa: PLC0415
        return os.path.join(os.path.dirname(botocore.__file__), "data")
    except ImportError:
        return "/usr/local/aws-cli/awscli/botocore/data"


def source_version(root):
    for p in (os.path.join(root, "..", "__init__.py"), os.path.join(root, "..", "..", "__init__.py")):
        try:
            m = re.search(r"__version__\s*=\s*['\"]([^'\"]+)", open(p).read())
            if m:
                return os.path.basename(os.path.dirname(os.path.abspath(p))) + " " + m.group(1)
        except OSError:
            pass
    if "aws-cli" in os.path.abspath(root):  # frozen AWS CLI v2 bundle: no .py sources
        try:
            import subprocess  # noqa: PLC0415
            return subprocess.run(["aws", "--version"], capture_output=True, text=True).stdout.split()[0]
        except (OSError, IndexError):
            pass
    return "unknown"


def rest_op(model, op):
    http = op["http"]
    path, _, query = http["requestUri"].partition("?")
    keys = [q for q in query.split("&") if q and not q.startswith("x-id=")]
    headers = []
    shape = model["shapes"].get(op.get("input", {}).get("shape", ""), {})
    for name in shape.get("required", []):
        member = shape["members"][name]
        loc = member.get("location")
        if loc == "querystring":
            keys.append(member["locationName"])
        elif loc == "header":
            headers.append(member["locationName"].lower())
    uri = path + ("?" + "&".join(sorted(set(keys))) if keys else "")
    entry = {"m": http["method"], "u": uri}
    if headers:
        entry["h"] = sorted(headers)
    return entry


def main():
    root = data_dir()
    services = {}
    for name in SERVICES:
        versions = sorted(os.listdir(os.path.join(root, name)))
        versions = [v for v in versions if os.path.exists(os.path.join(root, name, v, "service-2.json"))]
        model = json.load(open(os.path.join(root, name, versions[-1], "service-2.json")))
        meta = model["metadata"]
        signing = meta.get("signingName") or meta["endpointPrefix"]
        protocols = [p for p in meta.get("protocols", [meta["protocol"]]) if p in SUPPORTED]
        targets = [meta["targetPrefix"]] if meta.get("targetPrefix") else []
        extra = EXTRA.get(name, {})
        protocols = sorted(set(protocols) | set(extra.get("protocols", [])))
        targets = sorted(set(targets) | set(extra.get("targets", [])))
        rest = any(p.startswith("rest-") for p in protocols)
        ops = {n: (rest_op(model, o) if rest else None) for n, o in sorted(model["operations"].items())}
        services[signing] = {
            "endpoint": meta["endpointPrefix"],
            "iam": signing,
            "protocols": protocols,
            "targets": targets,
            "ops": ops,
        }
    out = {
        "_license": "Derived from botocore service models, Apache-2.0, Copyright Amazon.com, Inc. "
                    "or its affiliates. Regenerate with scripts/gen-aws-model.py.",
        "_source": source_version(root),
        "services": services,
    }
    with open(OUT, "w") as f:
        json.dump(out, f, separators=(",", ":"), sort_keys=True)
        f.write("\n")
    print(f"wrote {os.path.normpath(OUT)} ({os.path.getsize(OUT)} bytes, {len(services)} services)")


if __name__ == "__main__":
    main()
