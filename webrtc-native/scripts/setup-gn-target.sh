#!/bin/sh
# Both platforms use one pinned, deterministic GN staging implementation.
set -eu
ROOT="${1:?usage: setup-gn-target.sh <webrtc-upstream-root>}"
HERE=$(cd "$(dirname "$0")" && pwd)
exec python3 "$HERE/setup-gn-target.py" "$ROOT"
