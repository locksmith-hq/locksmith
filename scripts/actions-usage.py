#!/usr/bin/env python3
"""GitHub Actions minutes: month-to-date use against the free quota, and which workflows spend them.

Usage: scripts/actions-usage.py   (env: REPO, ACTIONS_QUOTA_MIN; default 2000, the free private-org plan)
Exits 1 when the month is projected above 80% of the quota.
"""
import calendar
import datetime as dt
import json
import math
import os
import subprocess
import sys
from collections import defaultdict

REPO = os.environ.get("REPO", "locksmith-hq/locksmith")
QUOTA = int(os.environ.get("ACTIONS_QUOTA_MIN", "2000"))
MULT = {"linux": 1, "windows": 2, "macos": 10}  # GitHub's quota multipliers per runner OS


def gh(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else None


def ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def runs_since(day):
    out, page = [], 1
    while True:
        d = gh(f"repos/{REPO}/actions/runs?created=>={day}&status=completed&per_page=100&page={page}")
        batch = (d or {}).get("workflow_runs", [])
        out += batch
        if len(batch) < 100:
            return out
        page += 1


def run_minutes(r):
    # shortcut: run wall time rounded up, not billing; ~2x high on short runs (2026-11). Billing API is preferred.
    if not r.get("run_started_at"):
        return 0
    return math.ceil((ts(r["updated_at"]) - ts(r["run_started_at"])).total_seconds() / 60)


def billed_by_day(org, now):
    """{date: quota minutes} from the billing API, or None if the token can't read billing."""
    d = gh(f"organizations/{org}/settings/billing/usage?year={now.year}&month={now.month}")
    if not d or "usageItems" not in d:
        return None
    days = defaultdict(float)
    for it in d["usageItems"]:
        if it.get("product") == "actions" and it.get("unitType") == "Minutes":
            sku = it.get("sku", "").lower()
            days[it["date"][:10]] += it["quantity"] * next((m for k, m in MULT.items() if k in sku), 1)
    return days


def main():
    now = dt.datetime.now(dt.timezone.utc)
    month_start = now.date().replace(day=1)
    month = runs_since(month_start.isoformat())
    by_day, src = billed_by_day(REPO.split("/")[0], now), "billing API"
    if by_day is None:
        by_day, src = defaultdict(float), "estimate from run times"
        for r in month:
            by_day[r["created_at"][:10]] += run_minutes(r)
    used = round(sum(by_day.values()))
    # Included minutes reset on the 1st (UTC) on GitHub's calendar-month billing.
    month_days = calendar.monthrange(now.year, now.month)[1]
    elapsed = max((now - dt.datetime.combine(month_start, dt.time(), dt.timezone.utc)).total_seconds() / 86400, 1)
    days_left = month_days - now.day + 1  # including today
    week_start = (now - dt.timedelta(days=7)).date().isoformat()
    avg_month = used / elapsed
    avg_week = sum(v for k, v in by_day.items() if k >= week_start) / min(7, elapsed)
    rate = max(avg_month, avg_week)  # the recent trend wins when usage is climbing
    projected = round(used + rate * days_left)
    pct = round(100 * projected / QUOTA)
    left = QUOTA - used
    print(f"Today {now:%Y-%m-%d} (UTC). Quota resets {month_start.replace(day=month_days) + dt.timedelta(days=1)}: {days_left} days left.")
    print(f"Used {used} of {QUOTA} min ({src}); {left} left.")
    print(f"Daily average: {avg_month:.0f} min this month, {avg_week:.0f} min last 7 days.")
    print(f"Projected month end: {projected} min ({pct}% of quota). Safe daily budget: {left / days_left:.0f} min.")
    if pct > 80:
        print(f"ALERT: on track to use {pct}% of the quota. Cut CI time now: path filters, caching, concurrency cancel, fewer triggers on the top workflows below.")

    week = now - dt.timedelta(days=7)
    per = defaultdict(list)
    for r in month:
        if ts(r["created_at"]) >= week:
            per[r["name"]].append(r)
    print("\nLast 7 days by workflow: runs, minutes, avg, max")
    for name, rs in sorted(per.items(), key=lambda kv: -sum(map(run_minutes, kv[1]))):
        mins = [run_minutes(r) for r in rs]
        print(f"  {name}: {len(rs)} runs, {sum(mins)} min, avg {sum(mins) / len(mins):.1f}, max {max(mins)}")
    slow = sorted((r for rs in per.values() for r in rs), key=run_minutes, reverse=True)[:5]
    print("\nSlowest runs (7 days):")
    for r in slow:
        print(f"  {run_minutes(r)} min  {r['name']}  {r['html_url']}")
    return 1 if pct > 80 else 0


if __name__ == "__main__":
    sys.exit(main())
