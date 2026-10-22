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
# Struct/type names declared in the header are not call exports; wrappers may
# construct them (Swift memberwise init / C# struct).
hdr_types = set(re.findall(r"typedef struct (hs_[A-Za-z0-9_]+)", header))
required = hdr_exports
for name in sorted(required):
    if name not in swift:
        raise SystemExit(f"swift wrapper missing export {name}")
    if name not in csharp:
        raise SystemExit(f"csharp wrapper missing export {name}")

# Wrappers must not invent exports (function-call form only).
allowed = hdr_exports | hdr_types
for label, body in (("swift", swift), ("csharp", csharp)):
    for name in re.findall(r"\b(hs_[A-Za-z0-9_]+)\s*\(", body):
        if name not in allowed:
            raise SystemExit(f"{label} wrapper claims undeclared export {name}")

# ABI version constant must be present in both wrappers.
if "abiVersion" not in swift and "ABI_VERSION" not in swift:
    raise SystemExit("swift wrapper missing ABI version gate")
if "hs_abi_version" not in csharp:
    raise SystemExit("csharp wrapper missing hs_abi_version gate")

print(f"wrapper contract ok: {len(required)} exports covered")
