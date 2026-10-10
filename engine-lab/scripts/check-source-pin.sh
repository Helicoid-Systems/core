#!/bin/sh
# Verify recorded source/submodule/lock pins without applying changes.
set -eu
if [ $# -ne 1 ]; then
    echo "usage: $0 <path-to-upstream-checkout>" >&2
    exit 2
fi
UPSTREAM="$1"
HERE=$(cd "$(dirname "$0")/.." && pwd)
PATCH="$HERE/patches/0001-hs-native-bridge.patch"
PIN="$HERE/inventory/source-pin.txt"
if [ ! -d "$UPSTREAM" ]; then
    echo "error: upstream path not found: $UPSTREAM" >&2
    exit 1
fi
if [ ! -f "$PATCH" ]; then
    echo "error: patch not found: $PATCH" >&2
    exit 1
fi
if [ ! -f "$PIN" ]; then
    echo "error: pin file not found: $PIN" >&2
    exit 1
fi
if ! git -C "$UPSTREAM" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: upstream is not a git checkout: $UPSTREAM" >&2
    exit 1
fi

expected_head=$(sed -n 's/^upstream_commit: //p' "$PIN" | head -1)
expected_sub=$(sed -n 's/^submodule_hbb_common: //p' "$PIN" | head -1)
expected_lock=$(sed -n 's/^lockfile_sha256: //p' "$PIN" | head -1)

if [ -z "$expected_head" ] || [ -z "$expected_sub" ] || [ -z "$expected_lock" ]; then
    echo "error: inventory/source-pin.txt must record upstream_commit, submodule_hbb_common, and lockfile_sha256" >&2
    exit 1
fi

actual_head=$(git -C "$UPSTREAM" rev-parse HEAD)
if [ "$actual_head" != "$expected_head" ]; then
    echo "error: wrong upstream HEAD" >&2
    echo "  expected: $expected_head" >&2
    echo "  actual:   $actual_head" >&2
    exit 1
fi

actual_sub=$(git -C "$UPSTREAM/libs/hbb_common" rev-parse HEAD)
if [ "$actual_sub" != "$expected_sub" ]; then
    echo "error: wrong hbb_common submodule pin" >&2
    echo "  expected: $expected_sub" >&2
    echo "  actual:   $actual_sub" >&2
    exit 1
fi

actual_lock=$(shasum -a 256 "$UPSTREAM/Cargo.lock" | awk '{print $1}')
if [ "$actual_lock" != "$expected_lock" ]; then
    echo "error: Cargo.lock hash mismatch (lock must be unchanged)" >&2
    echo "  expected: $expected_lock" >&2
    echo "  actual:   $actual_lock" >&2
    exit 1
fi

echo "pins OK: HEAD=$actual_head hbb_common=$actual_sub lock=$actual_lock"
