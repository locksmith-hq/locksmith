#!/usr/bin/env python3
"""Reject banned resources in an OpenTofu plan JSON (`tofu show -json plan`).

Usage: check_plan.py plan.json [plan.json ...]; exit 1 on any violation.
Bans (decision A0-16): ALB/NLB, NAT gateway, interface VPC endpoints, Secrets
Manager, Route 53 zones, log retention over 1 day, large instances.
"""
import json
import re
import sys

BANNED_TYPES = {
    "aws_lb": "load balancer (ALB/NLB)",
    "aws_alb": "load balancer (ALB)",
    "aws_nat_gateway": "NAT gateway",
    "aws_secretsmanager_secret": "Secrets Manager secret",
    "aws_route53_zone": "Route 53 hosted zone",
}
# Instance classes allowed: nothing larger than "medium" (and Aurora serverless).
SMALL = re.compile(r"\.(nano|micro|small|medium)$")


def resources(node):
    for r in node.get("resources", []):
        yield r
    for child in node.get("child_modules", []):
        yield from resources(child)


def check(plan):
    errs = []
    root = (plan.get("planned_values") or {}).get("root_module") or {}
    for r in resources(root):
        t, addr, v = r["type"], r["address"], r.get("values") or {}
        if t in BANNED_TYPES:
            errs.append(f"{addr}: {BANNED_TYPES[t]} is banned")
        if t == "aws_vpc_endpoint" and v.get("vpc_endpoint_type") == "Interface":
            errs.append(f"{addr}: interface VPC endpoint is banned")
        if t == "aws_cloudwatch_log_group":
            days = v.get("retention_in_days")
            if days is None or days == 0 or days > 1:
                errs.append(f"{addr}: log retention must be 1 day, got {days}")
        for key in ("instance_class", "instance_type"):
            cls = v.get(key)
            if cls and cls != "db.serverless" and not SMALL.search(cls):
                errs.append(f"{addr}: {key} {cls} is too large")
    return errs


def main(paths):
    bad = False
    for p in paths:
        with open(p) as f:
            errs = check(json.load(f))
        for e in errs:
            print(f"{p}: {e}", file=sys.stderr)
        bad = bad or bool(errs)
    print("policy: FAILED" if bad else "policy: OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
