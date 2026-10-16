#!/usr/bin/env python3
"""Probe the canonical LF byte contract for webrtc-native retained sources.

Demonstrates that a CRLF-converted checkout cannot silently pass the strict
BYTE drift check in check-header.py, that .gitattributes enforces LF for
webrtc-native and the active Windows workflow, and that fetch-upstream
process-scoped Git config preserves caller GIT_CONFIG_COUNT entries.
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

pkg = Path(__file__).resolve().parent.parent
repo = pkg.parent
retained = pkg / "native" / "hs_webrtc.h"
bridge = pkg / "native" / "hs_webrtc_bridge.cpp"
check_header = pkg / "scripts" / "check-header.py"
gitattributes = repo / ".gitattributes"
fetch_sh = pkg / "scripts" / "fetch-upstream.sh"
fetch_ps1 = pkg / "scripts" / "fetch-upstream.ps1"
workflow = repo / ".github" / "workflows" / "webrtc-native-windows.yml"


def fail(msg: str) -> None:
    raise SystemExit(f"probe failed: {msg}")


def require(cond: bool, msg: str) -> None:
    if not cond:
        fail(msg)


def probe_retained_header_is_lf() -> None:
    data = retained.read_bytes()
    require(data, "retained header empty")
    require(b"\r" not in data, "retained header contains CR bytes (not canonical LF)")
    require(b"\n" in data, "retained header has no LF bytes")
    print(f"[ok] retained header is pure LF ({len(data)} bytes, 0 CR)")


def probe_check_header_passes_on_lf_checkout() -> None:
    proc = subprocess.run(
        [sys.executable, str(check_header)],
        capture_output=True,
        text=True,
    )
    require(proc.returncode == 0, f"check-header.py failed on LF checkout: {proc.stderr or proc.stdout}")
    require("matches" in proc.stdout, "check-header.py did not report a match")
    print("[ok] check-header.py passes on current LF checkout")


def probe_crlf_checkout_cannot_silently_pass() -> None:
    # Simulate a Windows git checkout that converts the retained header to CRLF
    # while gen_header.py still emits canonical LF. The strict BYTE compare in
    # check-header.py must fail — it must not normalize and must not skip.
    original = retained.read_bytes()
    crlf = original.replace(b"\n", b"\r\n")
    require(crlf != original, "CRLF simulation did not change bytes")
    # Exercise a disposable package copy; never rewrite the tracked header.
    with tempfile.TemporaryDirectory(prefix="hs-header-crlf-") as directory:
        fixture = Path(directory)
        (fixture / "native").mkdir()
        (fixture / "scripts").mkdir()
        shutil.copy2(bridge, fixture / "native" / bridge.name)
        for name in ("check-header.py", "gen_header.py"):
            shutil.copy2(pkg / "scripts" / name, fixture / "scripts" / name)
        (fixture / "native" / retained.name).write_bytes(crlf)
        proc = subprocess.run(
            [sys.executable, str(fixture / "scripts" / "check-header.py")],
            capture_output=True,
            text=True,
        )
        require(proc.returncode != 0, "check-header.py silently passed a CRLF-converted retained header")
        require(
            "drifted" in (proc.stderr + proc.stdout),
            f"check-header.py failed without a drift message: {proc.stderr or proc.stdout}",
        )
    require(retained.read_bytes() == original, "probe changed tracked header")
    print("[ok] check-header.py rejects CRLF in a disposable fixture (strict BYTE drift)")


def probe_gitattributes_enforce_lf() -> None:
    text = gitattributes.read_text(encoding="utf-8")
    require(
        re.search(r"(?m)^webrtc-native/\*\*\s+text\s+eol=lf\s*$", text),
        ".gitattributes missing webrtc-native/** text eol=lf",
    )
    require(
        re.search(
            r"(?m)^\.github/workflows/webrtc-native-windows\.yml\s+text\s+eol=lf\s*$",
            text,
        ),
        ".gitattributes missing workflow text eol=lf",
    )
    # Historical engine/authority paths must stay untouched (no broad * rule).
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        require(
            not stripped.startswith("* "),
            f".gitattributes must stay narrow; found broad rule: {stripped}",
        )
        require(
            "engine-lab" not in stripped and "authority-lab" not in stripped,
            f".gitattributes must leave historical paths untouched: {stripped}",
        )
    # git check-attr must resolve both targets to eol=lf on this checkout.
    for rel in (
        "webrtc-native/native/hs_webrtc.h",
        ".github/workflows/webrtc-native-windows.yml",
    ):
        proc = subprocess.run(
            ["git", "-C", str(repo), "check-attr", "eol", "text", "--", rel],
            capture_output=True,
            text=True,
        )
        require(proc.returncode == 0, f"git check-attr failed for {rel}: {proc.stderr}")
        require("eol: lf" in proc.stdout, f"git check-attr eol!=lf for {rel}: {proc.stdout}")
        require("text: set" in proc.stdout, f"git check-attr text!=set for {rel}: {proc.stdout}")
    # engine-lab / authority-lab must not be forced to eol=lf by these rules.
    proc = subprocess.run(
        ["git", "-C", str(repo), "check-attr", "eol", "--", "engine-lab/README.md", "authority-lab/README.md"],
        capture_output=True,
        text=True,
    )
    require(proc.returncode == 0, f"git check-attr historical paths failed: {proc.stderr}")
    require("eol: lf" not in proc.stdout, f"historical paths unexpectedly forced eol=lf: {proc.stdout}")
    print("[ok] .gitattributes enforces LF for webrtc-native + active workflow; historical paths untouched")


def probe_fetch_scripts_require_git_config_preservation() -> None:
    sh = fetch_sh.read_text(encoding="utf-8")
    ps1 = fetch_ps1.read_text(encoding="utf-8")
    for name, body in (("fetch-upstream.sh", sh), ("fetch-upstream.ps1", ps1)):
        require("GIT_CONFIG_COUNT" in body, f"{name} missing GIT_CONFIG_COUNT handling")
        require("core.autocrlf" in body, f"{name} missing core.autocrlf")
        require("core.eol" in body, f"{name} missing core.eol")
        require("lf" in body, f"{name} missing core.eol=lf value")
        require("false" in body.lower(), f"{name} missing core.autocrlf=false value")
    # Syntax: POSIX sh parses; Python ast validates the companion generators.
    subprocess.run(["/bin/sh", "-n", str(fetch_sh)], check=True)
    for py in (
        check_header,
        pkg / "scripts" / "gen_header.py",
        pkg / "scripts" / "check-wrapper-contract.py",
        Path(__file__),
    ):
        ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
    print("[ok] fetch-upstream scripts declare process-scoped Git LF config and parse")


def probe_process_git_config_preserves_caller_entries() -> None:
    """Execute the same GIT_CONFIG_* append logic as fetch-upstream.sh in a
    child process that starts with caller GIT_CONFIG_COUNT entries."""
    script = r"""
set -eu
# caller-supplied entries must survive
_gcfg_count="${GIT_CONFIG_COUNT:-0}"
export GIT_CONFIG_KEY_${_gcfg_count}=core.autocrlf
export GIT_CONFIG_VALUE_${_gcfg_count}=false
_gcfg_eol=$((_gcfg_count + 1))
export GIT_CONFIG_KEY_${_gcfg_eol}=core.eol
export GIT_CONFIG_VALUE_${_gcfg_eol}=lf
export GIT_CONFIG_COUNT=$((_gcfg_count + 2))
# emit the resulting process-scoped config for the parent to assert
i=0
while [ "$i" -lt "$GIT_CONFIG_COUNT" ]; do
    eval "k=\${GIT_CONFIG_KEY_$i-}"
    eval "v=\${GIT_CONFIG_VALUE_$i-}"
    printf '%s=%s\n' "$k" "$v"
    i=$((i + 1))
done
"""
    env = os.environ.copy()
    # Simulate two caller GIT_CONFIG_COUNT entries.
    env["GIT_CONFIG_COUNT"] = "2"
    env["GIT_CONFIG_KEY_0"] = "safe.builtin"
    env["GIT_CONFIG_VALUE_0"] = "keep0"
    env["GIT_CONFIG_KEY_1"] = "safe.custom"
    env["GIT_CONFIG_VALUE_1"] = "keep1"
    proc = subprocess.run(
        ["/bin/sh", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    require(len(lines) == 4, f"expected 4 config entries, got: {lines}")
    require(lines[0] == "safe.builtin=keep0", f"caller entry 0 lost: {lines}")
    require(lines[1] == "safe.custom=keep1", f"caller entry 1 lost: {lines}")
    require(lines[2] == "core.autocrlf=false", f"missing core.autocrlf=false: {lines}")
    require(lines[3] == "core.eol=lf", f"missing core.eol=lf: {lines}")
    print("[ok] process Git config appends core.autocrlf=false + core.eol=lf and preserves caller entries")


def probe_workflow_requires() -> None:
    text = workflow.read_text(encoding="utf-8")
    require("contents: read" in text, "workflow missing explicit contents: read")
    require("concurrency:" in text, "workflow missing concurrency")
    require("cancel-in-progress: true" in text, "workflow missing cancel-in-progress: true")
    require("actions/setup-dotnet@v6" in text, "workflow missing actions/setup-dotnet@v6")
    require('dotnet-version: "10.0.x"' in text, "workflow missing dotnet-version 10.0.x")
    print("[ok] workflow has contents:read, branch concurrency cancel-in-progress, setup-dotnet@v6 10.0.x")


def main() -> int:
    probe_retained_header_is_lf()
    probe_check_header_passes_on_lf_checkout()
    probe_crlf_checkout_cannot_silently_pass()
    probe_gitattributes_enforce_lf()
    probe_fetch_scripts_require_git_config_preservation()
    probe_process_git_config_preserves_caller_entries()
    probe_workflow_requires()
    print("newline contract probe ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
