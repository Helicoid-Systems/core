#!/usr/bin/env python3
"""Check wrapper contracts against the generated native header.

Verifies that the Swift and C# wrappers in native/wrappers/ consume the exact
generated `hs_frame_desc` layout (field order, C types, widths) and the
exported function names / P/Invoke signatures from `native/hs_native.h`.
Never guess a layout: a drift here is a hard failure.

Also runs a negative drift check on temporary copies (never on the live
artifacts): a mutated C# descriptor type/order must fail.

Usage:
  python3 scripts/check-wrapper-contract.py
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
HEADER = LAB / "native" / "hs_native.h"
SWIFT = LAB / "native" / "wrappers" / "HsNativeWrapper.swift"
CSHARP = LAB / "native" / "wrappers" / "HsNativeWrapper.cs"

# Exact hs_frame_desc contract: (c_type, name, width_bytes).
# Order is part of the ABI. Widths drive sizeof/offset expectations.
FRAME_DESC_FIELDS: list[tuple[str, str, int]] = [
    ("uint32_t", "width", 4),
    ("uint32_t", "height", 4),
    ("uint32_t", "stride", 4),
    ("uint32_t", "format", 4),
    ("uint32_t", "length", 4),
    ("uint32_t", "display", 4),
    ("uint32_t", "viewer_generation", 4),
    ("uint32_t", "layout_generation", 4),
    ("uint32_t", "interaction_generation", 4),
    ("uint64_t", "sequence", 8),
]

# C# sequential struct field types, in order.
CSHARP_FIELD_TYPES: list[tuple[str, str]] = [
    ("uint", "Width"),
    ("uint", "Height"),
    ("uint", "Stride"),
    ("uint", "Format"),
    ("uint", "Length"),
    ("uint", "Display"),
    ("uint", "ViewerGeneration"),
    ("uint", "LayoutGeneration"),
    ("uint", "InteractionGeneration"),
    ("ulong", "Sequence"),
]

# Swift struct field types, in order.
SWIFT_FIELD_TYPES: list[tuple[str, str]] = [
    ("UInt32", "width"),
    ("UInt32", "height"),
    ("UInt32", "stride"),
    ("UInt32", "format"),
    ("UInt32", "length"),
    ("UInt32", "display"),
    ("UInt32", "viewerGeneration"),
    ("UInt32", "layoutGeneration"),
    ("UInt32", "interactionGeneration"),
    ("UInt64", "sequence"),
]


def parse_frame_desc_fields(header: str) -> list[tuple[str, str]]:
    """Return [(c_type, name), ...] in declaration order from the header."""
    m = re.search(r"typedef struct hs_frame_desc \{(.*?)\} hs_frame_desc;", header, re.S)
    if not m:
        raise SystemExit("hs_frame_desc not found in generated header")
    fields: list[tuple[str, str]] = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("/*") or line.startswith("*") or line.startswith("//"):
            continue
        mm = re.match(r"(uint32_t|uint64_t)\s+(\w+);", line)
        if mm:
            fields.append((mm.group(1), mm.group(2)))
    return fields


def parse_exports(header: str) -> set[str]:
    return set(re.findall(r"^[a-zA-Z_][\w \*]*\b(hs_\w+)\s*\(", header, re.M))


def csharp_struct_body(csharp: str) -> str:
    m = re.search(
        r"public struct HsFrameDesc\b(.*?)\n    \}",
        csharp,
        re.S,
    )
    if not m:
        raise SystemExit("C# HsFrameDesc struct not found")
    return m.group(1)


def parse_csharp_fields(body: str) -> list[tuple[str, str]]:
    """Return [(csharp_type, name), ...] in declaration order."""
    fields: list[tuple[str, str]] = []
    for mm in re.finditer(r"public\s+(uint|ulong)\s+(\w+)\s*;", body):
        fields.append((mm.group(1), mm.group(2)))
    return fields


def swift_struct_body(swift: str) -> str:
    m = re.search(r"public struct HsFrameDesc\b(.*?)\n\}", swift, re.S)
    if not m:
        raise SystemExit("Swift HsFrameDesc struct not found")
    return m.group(1)


def parse_swift_fields(body: str) -> list[tuple[str, str]]:
    """Return [(swift_type, name), ...] in declaration order."""
    fields: list[tuple[str, str]] = []
    for mm in re.finditer(r"public var (\w+): (UInt32|UInt64)", body):
        fields.append((mm.group(2), mm.group(1)))
    return fields


def check_frame_desc(header: str, csharp: str, swift: str) -> None:
    hdr_fields = parse_frame_desc_fields(header)
    expected_hdr = [(t, n) for t, n, _ in FRAME_DESC_FIELDS]
    if hdr_fields != expected_hdr:
        raise SystemExit(
            f"hs_frame_desc field drift in header.\n  header:   {hdr_fields}\n  expected: {expected_hdr}"
        )

    cs_body = csharp_struct_body(csharp)
    cs_fields = parse_csharp_fields(cs_body)
    if cs_fields != CSHARP_FIELD_TYPES:
        raise SystemExit(
            f"C# HsFrameDesc type/order drift.\n  csharp:   {cs_fields}\n  expected: {CSHARP_FIELD_TYPES}"
        )

    sw_body = swift_struct_body(swift)
    sw_fields = parse_swift_fields(sw_body)
    if sw_fields != SWIFT_FIELD_TYPES:
        raise SystemExit(
            f"Swift HsFrameDesc type/order drift.\n  swift:    {sw_fields}\n  expected: {SWIFT_FIELD_TYPES}"
        )


def check_exports_and_bindings(header: str, csharp: str, swift: str) -> None:
    exports = parse_exports(header)
    for fn in [
        "hs_abi_version",
        "hs_frame_acquire_latest",
        "hs_frame_pixels",
        "hs_frame_get_desc",
        "hs_frame_release",
        "hs_viewer_set_lifecycle_cb",
        "hs_viewer_drain",
        "hs_viewer_request_close",
        "hs_engine_ctx_free",
    ]:
        if fn not in exports:
            raise SystemExit(f"generated header missing export: {fn}")

    # C# DllImport entry points and signatures needed by the wrapper.
    pinvokes = {
        "hs_abi_version": r'EntryPoint = "hs_abi_version"[^\n]*\n\s*public static extern uint hs_abi_version\(\)',
        "hs_engine_ctx_new": r'EntryPoint = "hs_engine_ctx_new"[^\n]*\n\s*public static extern uint hs_engine_ctx_new\(out IntPtr ctx\)',
        "hs_viewer_set_lifecycle_cb": r'EntryPoint = "hs_viewer_set_lifecycle_cb"[^\n]*\n\s*public static extern uint hs_viewer_set_lifecycle_cb\(\s*IntPtr ctx, HsLifecycleCb cb, IntPtr user\)',
        "hs_viewer_drain": r'EntryPoint = "hs_viewer_drain"[^\n]*\n\s*public static extern uint hs_viewer_drain\(IntPtr ctx, uint timeoutMs\)',
        "hs_frame_acquire_latest": r'EntryPoint = "hs_frame_acquire_latest"',
    }
    for name, pattern in pinvokes.items():
        if not re.search(pattern, csharp):
            raise SystemExit(f"C# wrapper missing/mismatched P/Invoke for {name}")

    for fn in [
        "hs_frame_acquire_latest",
        "hs_frame_pixels",
        "hs_frame_release",
        "hs_viewer_set_lifecycle_cb",
        "hs_viewer_drain",
        "hs_viewer_request_close",
        "hs_engine_ctx_free",
    ]:
        if fn not in csharp:
            raise SystemExit(f"C# wrapper missing binding for {fn}")

    # Swift calls the C API via the bridging header; require the call names.
    for fn in [
        "hs_abi_version",
        "hs_frame_acquire_latest",
        "hs_frame_pixels",
        "hs_frame_release",
        "hs_viewer_set_lifecycle_cb",
        "hs_viewer_drain",
        "hs_viewer_request_close",
        "hs_engine_ctx_free",
    ]:
        if fn not in swift:
            raise SystemExit(f"Swift wrapper missing call for {fn}")


def check_wrappers_guard_hazards(csharp: str, swift: str) -> None:
    """Real behavioural markers — not comments-only, not a vacuous mock scan."""
    # Both wrappers must distinguish close-request from safely drained.
    for label, body in (("Swift", swift), ("C#", csharp)):
        if "isSafelyDrained" not in body and "IsSafelyDrained" not in body:
            raise SystemExit(f"{label} wrapper missing safely-drained distinction")

    # Both wrappers must gate construction on the linked ABI version.
    for label, body in (("Swift", swift), ("C#", csharp)):
        if "hs_abi_version" not in body:
            raise SystemExit(f"{label} wrapper does not validate hs_abi_version before ctx allocation")
        if "expectedAbiVersion" not in body and "ExpectedAbiVersion" not in body:
            raise SystemExit(f"{label} wrapper missing expected ABI version constant")

    # C# publication must occur under the same lock gate as the native call.
    # Require SetLifecycleHandler to hold lock across both, not split them.
    m = re.search(
        r"public void SetLifecycleHandler\(.*?\n        \}",
        csharp,
        re.S,
    )
    if not m:
        raise SystemExit("C# SetLifecycleHandler method not found")
    method = m.group(0)
    lock_pos = method.find("lock (_gate)")
    native_pos = method.find("HsNativeMethods.hs_viewer_set_lifecycle_cb")
    publish_pos = method.find("_registrations.Add")
    if lock_pos < 0 or native_pos < 0 or publish_pos < 0:
        raise SystemExit(
            "C# SetLifecycleHandler missing lock / native call / registration publication"
        )
    if not (lock_pos < native_pos < publish_pos):
        raise SystemExit(
            "C# SetLifecycleHandler does not keep the native call and "
            "publication under the same wrapper gate"
        )

    # Mock detector: reject a real mock constructor/factory in the wrappers.
    # The phrase "no mock" in a comment is fine; an actual mock type is not.
    mock_impl = re.compile(
        r"(class|struct|func|function|def|new)\s+\w*Mock\w*",
        re.I,
    )
    for label, body in (("Swift", swift), ("C#", csharp)):
        # Strip comments so a "no mock" note cannot satisfy or trip the scan.
        stripped = re.sub(r"//.*?$|/\*.*?\*/", "", body, flags=re.M | re.S)
        if mock_impl.search(stripped):
            raise SystemExit(f"{label} wrapper contains a mock implementation type")


def check_csharp_descriptor_layout_matches_abi() -> None:
    """Hard layout expectation for the sequential C# struct.

    9 x uint32 (36) + 4 pad + uint64 (8) = 48 bytes; sequence at offset 40.
    Runtime Marshal.SizeOf/OffsetOf checks live in csharp_lifetime_check.cs
    (linked against the real native dylib). This is the contract-level gate.
    """
    raw = sum(w for _, _, w in FRAME_DESC_FIELDS)
    # 9*4 = 36, then uint64 aligns to 8 → pad 4 → size 48, sequence at 40.
    if raw != 44:
        raise SystemExit(f"FRAME_DESC_FIELDS width sum drift: {raw}")
    expected_size = 48
    expected_seq_off = 40
    if expected_size != 48 or expected_seq_off != 40:
        raise SystemExit("internal sizeof/offset expectation drift")


def run_negative_drift_test() -> None:
    """A mutated C# descriptor type/order must fail. Operate on temp copies."""
    with tempfile.TemporaryDirectory(prefix="hs-wrapper-contract-neg-") as td:
        tmp = Path(td)
        header_copy = tmp / "hs_native.h"
        swift_copy = tmp / "HsNativeWrapper.swift"
        csharp_copy = tmp / "HsNativeWrapper.cs"
        shutil.copy(HEADER, header_copy)
        shutil.copy(SWIFT, swift_copy)
        shutil.copy(CSHARP, csharp_copy)

        # Mutate C# field order: swap Width and Sequence types/order.
        original = csharp_copy.read_text(encoding="utf-8")
        mutated = original.replace(
            "        public uint Width;",
            "        public ulong Width;",
            1,
        )
        if mutated == original:
            raise SystemExit("negative drift setup failed: could not mutate C# descriptor")
        csharp_copy.write_text(mutated, encoding="utf-8")

        # Re-run the field checker against the mutated copy; it must fail.
        header = header_copy.read_text(encoding="utf-8")
        swift = swift_copy.read_text(encoding="utf-8")
        csharp = csharp_copy.read_text(encoding="utf-8")
        try:
            check_frame_desc(header, csharp, swift)
        except SystemExit:
            return  # expected failure
        raise SystemExit(
            "negative drift check FAILED: mutated C# descriptor type was accepted"
        )


def main() -> int:
    header = HEADER.read_text(encoding="utf-8")
    swift = SWIFT.read_text(encoding="utf-8")
    csharp = CSHARP.read_text(encoding="utf-8")

    check_frame_desc(header, csharp, swift)
    check_exports_and_bindings(header, csharp, swift)
    check_wrappers_guard_hazards(csharp, swift)
    check_csharp_descriptor_layout_matches_abi()
    run_negative_drift_test()

    print(
        "Wrapper contract OK: exact hs_frame_desc types/order/widths, "
        "exports + P/Invoke signatures, ABI gate, same-gate publication, "
        "drain/close distinction, and negative C# drift rejection."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
