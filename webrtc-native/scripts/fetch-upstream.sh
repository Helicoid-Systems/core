#!/bin/sh
# Fetch the PINNED Google WebRTC checkout + depot_tools into dedicated scratch.
# Exact commits come from inventory/upstream-pins.json. Prevents depot_tools
# self-update drift. Never stores the checkout in the repo.
# Usage: ./scripts/fetch-upstream.sh <scratch-root>
set -eu
ROOT="${1:?usage: fetch-upstream.sh <scratch-root>}"
HERE=$(cd "$(dirname "$0")/.." && pwd)
PINS="$HERE/inventory/upstream-pins.json"
SRC_URL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["webrtc_src_url"])' "$PINS")
SRC_COMMIT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["webrtc_src_commit"])' "$PINS")
DEPOT_URL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["depot_tools"]["url"])' "$PINS")
DEPOT_COMMIT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["depot_tools"]["commit"])' "$PINS")

mkdir -p "$ROOT/webrtc-checkout"
DEPOT="$ROOT/depot_tools"
if [ ! -d "$DEPOT/.git" ]; then
    git init -q "$DEPOT"
    git -C "$DEPOT" remote add origin "$DEPOT_URL"
    git -C "$DEPOT" fetch --depth 1 origin "$DEPOT_COMMIT"
    git -C "$DEPOT" checkout -q FETCH_HEAD
fi
DEPOT_HEAD=$(git -C "$DEPOT" rev-parse HEAD)
[ "$DEPOT_HEAD" = "$DEPOT_COMMIT" ] || { echo "error: depot_tools $DEPOT_HEAD != $DEPOT_COMMIT" >&2; exit 1; }

export DEPOT_TOOLS_UPDATE=0
export PATH="$DEPOT:$PATH"

# Process-scoped Git config inherited by gclient child Git: canonical LF for
# DEPS raw-byte hashing on Windows. Appends to any caller GIT_CONFIG_COUNT
# entries; never writes machine/user/global git config.
_gcfg_count="${GIT_CONFIG_COUNT:-0}"
export GIT_CONFIG_KEY_${_gcfg_count}=core.autocrlf
export GIT_CONFIG_VALUE_${_gcfg_count}=false
_gcfg_eol=$((_gcfg_count + 1))
export GIT_CONFIG_KEY_${_gcfg_eol}=core.eol
export GIT_CONFIG_VALUE_${_gcfg_eol}=lf
export GIT_CONFIG_COUNT=$((_gcfg_count + 2))

cd "$ROOT/webrtc-checkout"
cat > .gclient << EOF
solutions = [
  {
    "name": "src",
    "url": "$SRC_URL@$SRC_COMMIT",
    "deps_file": "DEPS",
    "managed": False,
    "custom_deps": {},
    "custom_vars": {},
  },
]
target_os = ["mac"]
EOF

# Run the exact pinned DEPS hooks (clang/SDK download etc.) in a bounded way.
# DEPOT_TOOLS_UPDATE=0 prevents depot self-update drift; DEPOT_TOOLS_WIN_TOOLCHAIN=0
# prefers the hosted installed VS when present instead of a depot-managed one.
export DEPOT_TOOLS_WIN_TOOLCHAIN=0
gclient sync --no-history --revision "src@$SRC_COMMIT"
[ $? -eq 0 ] || { echo "error: gclient sync (with hooks) failed" >&2; exit 1; }
SRC_HEAD=$(git -C src rev-parse HEAD)
[ "$SRC_HEAD" = "$SRC_COMMIT" ] || { echo "error: src $SRC_HEAD != $SRC_COMMIT" >&2; exit 1; }

DEPS_SHA=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' src/DEPS)
EXPECT_SHA=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deps_sha256"])' "$PINS")
[ "$DEPS_SHA" = "$EXPECT_SHA" ] || { echo "error: DEPS $DEPS_SHA != $EXPECT_SHA" >&2; exit 1; }

echo "src=$SRC_HEAD"
echo "depot_tools=$DEPOT_HEAD"
echo "deps_sha256=$DEPS_SHA"
