#!/usr/bin/env python3
"""Portable deterministic GN target setup (used by both macOS and Windows).

Same contract as setup-gn-target.sh:
  - verify src / depot_tools / DEPS pins from inventory/upstream-pins.json
  - stage checked-in gn/BUILD.gn + native sources into hs_native_build/
  - idempotent registration of //hs_native_build:hs_webrtc_harness in root BUILD.gn
  - reject unexpected patch contexts

Usage: python3 scripts/setup-gn-target.py <webrtc-upstream-root> [--check-only]
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def git_head(repo: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()


def main() -> int:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--check-only"):
        print(
            "usage: setup-gn-target.py <webrtc-upstream-root> [--check-only]",
            file=sys.stderr,
        )
        return 2
    root = Path(sys.argv[1])
    check_only = len(sys.argv) == 3
    here = Path(__file__).resolve().parent.parent
    src = root / "webrtc-checkout" / "src"
    depot = root / "depot_tools"
    pins_path = here / "inventory" / "upstream-pins.json"

    if not src.is_dir() or not depot.is_dir():
        print("error: pinned checkout or depot_tools missing", file=sys.stderr)
        return 1

    pins = json.loads(pins_path.read_text())
    head = git_head(src)
    depot_head = git_head(depot)
    deps_sha = hashlib.sha256((src / "DEPS").read_bytes()).hexdigest()
    if head != pins["webrtc_src_commit"]:
        print(f"pin mismatch: src {head} != {pins['webrtc_src_commit']}", file=sys.stderr)
        return 1
    if depot_head != pins["depot_tools"]["commit"]:
        print(
            f"pin mismatch: depot_tools {depot_head} != {pins['depot_tools']['commit']}",
            file=sys.stderr,
        )
        return 1
    if deps_sha != pins["deps_sha256"]:
        print(f"pin mismatch: DEPS sha {deps_sha} != {pins['deps_sha256']}", file=sys.stderr)
        return 1
    print(f"pins ok: src={head} depot_tools={depot_head} deps={deps_sha}")

    # Read and validate every staging input and the root GN patch context
    # before the first scratch-checkout write.
    source_names = (
        "hs_webrtc_bridge.cpp",
        "harness.cpp",
        "hs_webrtc.h",
        "relay_harness.cpp",
        "channel_binding.h",
        "secure_memory.h",
    )
    try:
        build_gn = (here / "gn" / "BUILD.gn").read_bytes()
        source_bytes = {
            name: (here / "native" / name).read_bytes() for name in source_names
        }
        root_gn = src / "BUILD.gn"
        text = root_gn.read_text()
    except (OSError, UnicodeError) as error:
        print(f"error: required GN staging input is unavailable: {error}", file=sys.stderr)
        return 1

    label = '"//hs_native_build:hs_webrtc_harness",'
    patched_text = text
    register_target = "//hs_native_build:hs_webrtc_harness" not in text
    if register_target and "hs_native_build" in text:
        print(
            "error: root BUILD.gn contains an unexpected hs_native_build registration",
            file=sys.stderr,
        )
        return 1
    if register_target:
        marker = 'group("default") {'
        idx = text.find(marker)
        if idx < 0:
            print("root BUILD.gn has no group(\"default\")", file=sys.stderr)
            return 1
        deps_idx = text.find("deps = [", idx)
        if deps_idx < 0:
            print("root BUILD.gn default group has no deps list", file=sys.stderr)
            return 1
        insert_at = deps_idx + len("deps = [")
        patched_text = text[:insert_at] + "\n    " + label + text[insert_at:]

    if (src / "hs_webrtc_native").is_dir() or (src / "helicoid").is_dir():
        print("error: unexpected lab directory in checkout (patch context)", file=sys.stderr)
        return 1

    if check_only:
        print("setup-gn-target.py: preflight passed; no files were changed")
        return 0

    build_dir = src / "hs_native_build"
    build_dir.mkdir(parents=True, exist_ok=True)
    (build_dir / "BUILD.gn").write_bytes(build_gn)
    for name, contents in source_bytes.items():
        (build_dir / name).write_bytes(contents)

    if register_target:
        root_gn.write_text(patched_text)
        print("root BUILD.gn registered hs_native_build")
    else:
        print("root BUILD.gn already registers hs_native_build")

    print(f"setup-gn-target.py: staged {build_dir} and registered harness target")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
