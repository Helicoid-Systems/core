#!/bin/sh
# Apply the retained RD02 hs-native bridge patch to a clean upstream checkout.
#
# Usage:
#   ./scripts/apply-patch.sh <path-to-upstream-checkout>
#
# Enforces the exact recorded pins BEFORE applying:
#   - upstream HEAD must equal inventory/source-pin.txt's upstream_commit
#   - libs/hbb_common submodule must equal the recorded submodule pin
#   - Cargo.lock sha256 must match the recorded lock hash
# Wrong pins are refused (exit 1), not merely printed.
#
# This script does not fetch, clone, commit, or push.

set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <path-to-upstream-checkout>" >&2
    exit 2
fi

UPSTREAM="$1"
HERE=$(cd "$(dirname "$0")/.." && pwd)
PATCH="$HERE/patches/0001-hs-native-bridge.patch"
PIN="$HERE/inventory/source-pin.txt"

sh "$HERE/scripts/check-source-pin.sh" "$UPSTREAM"

# --check first so we do not leave a half-applied tree.
if git -C "$UPSTREAM" apply --check "$PATCH"; then
    git -C "$UPSTREAM" apply "$PATCH"
    echo "applied: $PATCH"
else
    echo "error: patch does not apply cleanly (already applied? wrong tree?)" >&2
    exit 1
fi

echo "next: scripts/build-macos-arm64.sh $UPSTREAM"
