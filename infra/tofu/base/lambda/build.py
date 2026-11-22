#!/usr/bin/env python3
"""Rebuild presignup.zip deterministically (no archive provider needed in the tofu mirror)."""
import pathlib
import zipfile

d = pathlib.Path(__file__).parent
zi = zipfile.ZipInfo("presignup.py", date_time=(1980, 1, 1, 0, 0, 0))
zi.external_attr = 0o644 << 16
with zipfile.ZipFile(d / "presignup.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr(zi, (d / "presignup.py").read_bytes())
