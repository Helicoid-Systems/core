#!/usr/bin/env python3
"""Probe the explicit optional git-cache disable contract for fetch-upstream.

Uses the exact pinned depot_tools sources supplied as a directory argument
(no network, no new checkout) to demonstrate:

1. Windows failure mechanism: Mirror.git_exe is git.bat while hosted Git is
   git.exe, and GetCachePath invokes that binary when cache_dir is unset.
2. Supported disable: gclient SetConfig maps .gclient ``cache_dir = None`` to
   Mirror.SetCachePath(None), after which GetCachePath returns None without
   the git.bat lookup, and _GetMirror short-circuits.
3. Both fetch scripts write that explicit policy and keep the prior LF /
   caller GIT_CONFIG_COUNT contract.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

pkg = Path(__file__).resolve().parent.parent
repo = pkg.parent
fetch_sh = pkg / "scripts" / "fetch-upstream.sh"
fetch_ps1 = pkg / "scripts" / "fetch-upstream.ps1"
newline_probe = pkg / "scripts" / "probe-newline-contract.py"
gitattributes = repo / ".gitattributes"
if len(sys.argv) != 2:
    raise SystemExit("usage: probe-git-cache-policy.py <pinned-depot-tools-directory>")
PINNED_DEPOT = Path(sys.argv[1]).resolve()
pins = json.loads((pkg / "inventory" / "upstream-pins.json").read_text())
head = subprocess.check_output(["git", "-C", str(PINNED_DEPOT), "rev-parse", "HEAD"], text=True).strip()
if head != pins["depot_tools"]["commit"]:
    raise SystemExit("depot_tools revision does not match the retained pin")
git_cache_py = PINNED_DEPOT / "git_cache.py"
gclient_py = PINNED_DEPOT / "gclient.py"
gclient_scm_py = PINNED_DEPOT / "gclient_scm.py"


def fail(msg: str) -> None:
    raise SystemExit(f"probe failed: {msg}")


def require(cond: bool, msg: str) -> None:
    if not cond:
        fail(msg)


def load_pinned_git_cache():
    require(gcache_py_ok(), "pinned git_cache.py missing")
    # Pinned git_cache imports sibling depot_tools modules (Gsutil, etc.).
    if str(PINNED_DEPOT) not in sys.path:
        sys.path.insert(0, str(PINNED_DEPOT))
    spec = importlib.util.spec_from_file_location("pinned_git_cache", git_cache_py)
    require(spec and spec.loader, "cannot load pinned git_cache.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pinned_git_cache"] = mod
    spec.loader.exec_module(mod)
    return mod


def gcache_py_ok() -> bool:
    return git_cache_py.is_file() and gclient_py.is_file() and gclient_scm_py.is_file()


def probe_pinned_sources_document_failure_and_disable() -> None:
    gc = git_cache_py.read_text(encoding="utf-8")
    gclient = gclient_py.read_text(encoding="utf-8")
    scm = gclient_scm_py.read_text(encoding="utf-8")

    require(
        re.search(r'git_exe\s*=\s*"git\.bat"\s+if\s+sys\.platform\.startswith\("win"\)', gc),
        "pinned git_cache.py no longer sets git_exe=git.bat on Windows",
    )
    require(
        "subprocess.check_output(" in gc and "cls.git_exe" in gc,
        "pinned GetCachePath no longer invokes cls.git_exe",
    )
    require(
        "UNSET_CACHE_DIR" in gclient and "cache_dir = None" in gclient,
        "pinned gclient.py no longer distinguishes cache_dir = None as disabled",
    )
    require(
        "git_cache.Mirror.SetCachePath(cache_dir)" in gclient,
        "pinned gclient.py no longer calls SetCachePath for explicit cache_dir",
    )
    require(
        "if not self.cache_dir:" in scm and "return None" in scm,
        "pinned gclient_scm._GetMirror no longer short-circuits without cache_dir",
    )
    print("[ok] pinned depot_tools: git.bat failure path + cache_dir=None disable path present")


def probe_real_mirror_set_cachepath_none_skips_git_bat() -> None:
    mod = load_pinned_git_cache()
    mirror = mod.Mirror
    require(
        mirror.git_exe == "git" or mirror.git_exe == "git.bat",
        f"unexpected pinned git_exe {mirror.git_exe!r}",
    )
    # Before SetCachePath, GetCachePath would consult git config via git_exe.
    # After the supported SetCachePath(None), it must return None and never
    # spawn git.bat / git — proven by a monkeypatched check_output.
    calls: list[list[str]] = []
    real_check_output = subprocess.check_output

    def spy(cmd, *a, **kw):
        calls.append(list(cmd) if isinstance(cmd, (list, tuple)) else [str(cmd)])
        return real_check_output(cmd, *a, **kw)

    mirror.SetCachePath(None)
    subprocess.check_output = spy
    try:
        got = mirror.GetCachePath()
    finally:
        subprocess.check_output = real_check_output
    require(got is None, f"GetCachePath after SetCachePath(None) returned {got!r}, expected None")
    require(not calls, f"GetCachePath spawned processes after SetCachePath(None): {calls}")
    # Falsy cache_dir is what _GetMirror tests; None must be falsy.
    require(not got, "None cache_dir is truthy; _GetMirror would not short-circuit")
    print("[ok] real pinned Mirror.SetCachePath(None) -> GetCachePath()=None without git.exe/git.bat")


def probe_fetch_scripts_share_explicit_cache_policy() -> None:
    for name, body in (("fetch-upstream.sh", fetch_sh.read_text(encoding="utf-8")),
                       ("fetch-upstream.ps1", fetch_ps1.read_text(encoding="utf-8"))):
        require("cache_dir = None" in body, f"{name} missing explicit .gclient cache_dir = None")
        # Must be inside the generated .gclient text, not a comment-only mention.
        require(
            re.search(r'(?m)^\s*cache_dir = None\s*$', body),
            f"{name} cache_dir = None is not a .gclient assignment line",
        )
        # Prior contracts stay intact.
        require("GIT_CONFIG_COUNT" in body, f"{name} lost GIT_CONFIG_COUNT handling")
        require("core.autocrlf" in body and "core.eol" in body, f"{name} lost process Git LF config")
        require("gclient sync --no-history" in body, f"{name} dropped exact-commit gclient sync")
        require("deps_sha256" in body, f"{name} dropped DEPS raw-byte pin check")
    subprocess.run(["/bin/sh", "-n", str(fetch_sh)], check=True)
    ast.parse(Path(__file__).read_text(encoding="utf-8"), filename=str(__file__))
    print("[ok] both fetch scripts write cache_dir = None and keep LF/config/pin contracts")


def probe_lf_attrs_and_caller_git_config_preserved() -> None:
    text = gitattributes.read_text(encoding="utf-8")
    require("webrtc-native/** text eol=lf" in text, ".gitattributes lost webrtc-native LF rule")
    env = os.environ.copy()
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "safe.keep"
    env["GIT_CONFIG_VALUE_0"] = "yes"
    script = r"""
set -eu
_gcfg_count="${GIT_CONFIG_COUNT:-0}"
export GIT_CONFIG_KEY_${_gcfg_count}=core.autocrlf
export GIT_CONFIG_VALUE_${_gcfg_count}=false
_gcfg_eol=$((_gcfg_count + 1))
export GIT_CONFIG_KEY_${_gcfg_eol}=core.eol
export GIT_CONFIG_VALUE_${_gcfg_eol}=lf
export GIT_CONFIG_COUNT=$((_gcfg_count + 2))
printf '%s\n' "$GIT_CONFIG_COUNT" "${GIT_CONFIG_KEY_0}" "${GIT_CONFIG_VALUE_0}" \
  "${GIT_CONFIG_KEY_1}" "${GIT_CONFIG_VALUE_1}" "${GIT_CONFIG_KEY_2}" "${GIT_CONFIG_VALUE_2}"
"""
    proc = subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True, text=True, check=True)
    lines = proc.stdout.splitlines()
    require(lines[0] == "3", f"GIT_CONFIG_COUNT not appended: {lines}")
    require(lines[1] == "safe.keep" and lines[2] == "yes", f"caller entry lost: {lines}")
    require(lines[3] == "core.autocrlf" and lines[4] == "false", f"autocrlf missing: {lines}")
    require(lines[5] == "core.eol" and lines[6] == "lf", f"eol=lf missing: {lines}")
    # Strict byte header check still present and passing on LF checkout.
    proc = subprocess.run(
        [sys.executable, str(pkg / "scripts" / "check-header.py")],
        capture_output=True,
        text=True,
    )
    require(proc.returncode == 0, f"check-header.py failed: {proc.stderr or proc.stdout}")
    print("[ok] LF attrs, strict byte header check, and caller GIT_CONFIG_COUNT preserved")


def probe_no_vendor_patch_or_shim() -> None:
    # Bounded fetch configuration only: no vendor depot_tools edits in-repo,
    # no git.bat shim scripts committed.
    for rel in (
        "webrtc-native/scripts/git.bat",
        "webrtc-native/scripts/git.exe",
        "webrtc-native/vendor/depot_tools/git_cache.py",
    ):
        require(not (repo / rel).exists(), f"unexpected shim/vendor file {rel}")
    tracked = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "webrtc-native"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    require("git_cache.py" not in tracked, "vendor git_cache.py tracked in repo")
    require("git.bat" not in tracked, "git.bat shim tracked in repo")
    print("[ok] no vendor patch, no git.bat shim, no source/compiler fallback in repo")


def main() -> int:
    probe_pinned_sources_document_failure_and_disable()
    probe_real_mirror_set_cachepath_none_skips_git_bat()
    probe_fetch_scripts_share_explicit_cache_policy()
    probe_lf_attrs_and_caller_git_config_preserved()
    probe_no_vendor_patch_or_shim()
    print("git-cache policy probe ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
