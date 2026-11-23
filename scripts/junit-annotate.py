#!/usr/bin/env python3
"""Turn a nextest JUnit report into check-run annotations, the one place cloud agents can read a test failure
(their proxy blocks job logs). Usage: python3 scripts/junit-annotate.py target/nextest/<profile>/junit.xml"""
import os, sys, xml.etree.ElementTree as ET

path = sys.argv[1]
if not os.path.exists(path):
    sys.exit(0)
for tc in ET.parse(path).iter("testcase"):
    name = f"{tc.get('classname')} {tc.get('name')}"
    bad = next((e for e in tc if e.tag in ("failure", "error")), None)
    if bad is not None:
        print(f"::error title=test failed::{name}: {(bad.get('message') or '')[:300]}")
    elif tc.find("flakyFailure") is not None:
        print(f"::warning title=flaky test, passed on retry::{name}")
