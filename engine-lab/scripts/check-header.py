#!/usr/bin/env python3
"""Check the retained native source hash and generated ABI header offline.

This checks artifact drift only; the platform build/harness proves linkage.
"""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

lab = Path(__file__).resolve().parent.parent
patch = (lab / 'patches/0001-hs-native-bridge.patch').read_text()
section = patch.split('diff --git a/src/hs_native.rs b/src/hs_native.rs\n', 1)[1]
section = section.split('\ndiff --git ', 1)[0]
source = '\n'.join(line[1:] for line in section.splitlines()
                   if line.startswith('+') and not line.startswith('+++')) + '\n'
expected = next(line.split()[0] for line in
                (lab / 'inventory/patched-files.sha256').read_text().splitlines()
                if line.endswith('  src/hs_native.rs'))
if hashlib.sha256(source.encode()).hexdigest() != expected:
    raise SystemExit('Retained native source does not match its recorded hash.')
with tempfile.TemporaryDirectory(prefix='helicoid-header-check-') as directory:
    rust = Path(directory) / 'hs_native.rs'
    header = Path(directory) / 'hs_native.h'
    rust.write_text(source)
    subprocess.run([sys.executable, str(lab / 'scripts/gen_header.py'),
                    str(rust), str(header)], check=True)
    if header.read_bytes() != (lab / 'native/hs_native.h').read_bytes():
        raise SystemExit('Generated native header drifted from retained source.')
print('Native patch source hash and generated header match; linkage is a separate platform check.')
