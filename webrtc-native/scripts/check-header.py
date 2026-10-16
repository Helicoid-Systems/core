#!/usr/bin/env python3
"""Check that the retained generated header matches a fresh generation."""
import subprocess, sys, tempfile
from pathlib import Path

pkg = Path(__file__).resolve().parent.parent
bridge = pkg / "native" / "hs_webrtc_bridge.cpp"
retained = pkg / "native" / "hs_webrtc.h"
if not bridge.is_file() or not retained.is_file():
    raise SystemExit("missing bridge or retained header")
with tempfile.TemporaryDirectory(prefix="hs-webrtc-header-") as d:
    out = Path(d) / "hs_webrtc.h"
    subprocess.run(
        [sys.executable, str(pkg / "scripts" / "gen_header.py"), str(bridge), str(out)],
        check=True,
    )
    if out.read_bytes() != retained.read_bytes():
        raise SystemExit("generated native header drifted from retained source")
print("generated header matches bridge exports")
