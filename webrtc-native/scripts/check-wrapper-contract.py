#!/usr/bin/env python3
"""Check wrapper coverage matches the generated header exports exactly.

Offline drift check: every implemented export must appear in both wrappers;
wrappers must not claim exports the header does not declare.
"""
import re
import sys
from pathlib import Path

pkg = Path(__file__).resolve().parent.parent
header = (pkg / "native" / "hs_webrtc.h").read_text(encoding="utf-8")
swift = (pkg / "native" / "wrappers" / "HsWebRtcWrapper.swift").read_text(encoding="utf-8")
csharp = (pkg / "native" / "wrappers" / "HsWebRtcWrapper.cs").read_text(encoding="utf-8")

hdr_exports = set(re.findall(r"\b(hs_[A-Za-z0-9_]+)\s*\(", header))
# Unavailable stubs are exported from the bridge but wrappers may omit them.
optional = {"hs_capture_begin", "hs_admission_begin", "hs_media_frame_acquire"}

required = hdr_exports - optional
for name in sorted(required):
    if name not in swift:
        raise SystemExit(f"swift wrapper missing export {name}")
    if name not in csharp:
        raise SystemExit(f"csharp wrapper missing export {name}")

# Wrappers must not invent exports (function-call form only).
for label, body in (("swift", swift), ("csharp", csharp)):
    for name in re.findall(r"\b(hs_[A-Za-z0-9_]+)\s*\(", body):
        if name not in hdr_exports:
            raise SystemExit(f"{label} wrapper claims undeclared export {name}")

# ABI version constant must be present in both wrappers.
if "abiVersion" not in swift and "ABI_VERSION" not in swift:
    raise SystemExit("swift wrapper missing ABI version gate")
if "hs_abi_version" not in csharp:
    raise SystemExit("csharp wrapper missing hs_abi_version gate")

print(f"wrapper contract ok: {len(required)} exports covered")
