#!/usr/bin/env python3
"""Narrow regression for check-pe-exports.py.

Builds minimal PE32+ images in memory and exercises the structural/export
contract without a compiler. Function fixtures use a genuinely executable
raw-backed section (IMAGE_SCN_MEM_EXECUTE). Run:

  python3 test-pe-exports.py
"""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-pe-exports.py"

# IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
TEXT_CHARS = 0x60000020
# IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
DATA_CHARS = 0x40000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000


def build_pe(
    names: list[str],
    *,
    machine: int = 0x8664,
    magic: int = 0x20B,
    forward: dict[str, str] | None = None,
    truncate: int | None = None,
    drop_names: set[str] | None = None,
    func_rva_overrides: dict[str, int] | None = None,
    text_chars: int = TEXT_CHARS,
    export_size_override: int | None = None,
) -> bytes:
    """Construct a tiny PE32+ DLL with an export directory.

    Layout (headers region + .text):
      0x000 DOS+PE+section+optional  (SizeOfHeaders=0x200)
      0x200 export directory + strings + name/ordinal/EAT tables
      0x600 .text at VA=0x1000 (executable raw-backed function RVAs)
      0x800 .data at VA=0x2000 (non-exec; used for bad-RVA cases)
    """
    forward = forward or {}
    drop_names = drop_names or set()
    func_rva_overrides = func_rva_overrides or {}
    export_names = [n for n in names if n not in drop_names]
    n = len(export_names)
    if n == 0:
        raise ValueError("need at least one export")

    exp_off = 0x200
    cursor = exp_off + MIN_EXPORT_DIR

    fwd_rvas: dict[str, int] = {}
    placements: list[tuple[int, bytes]] = []
    for name, target in forward.items():
        raw = target.encode("ascii") + b"\x00"
        fwd_rvas[name] = cursor
        placements.append((cursor, raw))
        cursor += len(raw)

    dll_name = b"hs_webrtc_shared.dll\x00"
    dll_name_rva = cursor
    placements.append((cursor, dll_name))
    cursor += len(dll_name)

    name_rvas: dict[str, int] = {}
    # Export names must be lexically ordered in the name pointer table.
    for name in export_names:
        raw = name.encode("ascii") + b"\x00"
        name_rvas[name] = cursor
        placements.append((cursor, raw))
        cursor += len(raw)

    cursor = (cursor + 3) & ~3
    eat_off = cursor
    npt_off = eat_off + 4 * n
    ot_off = npt_off + 4 * n
    cursor = ot_off + 2 * n

    text_rva = 0x1000
    data_rva = 0x2000
    func_rvas = []
    for i, name in enumerate(export_names):
        if name in func_rva_overrides:
            func_rvas.append(func_rva_overrides[name])
        elif name in forward:
            func_rvas.append(fwd_rvas[name])
        else:
            func_rvas.append(text_rva + i * 16)

    # Name pointer table is lexically ordered (loader binary search).
    sorted_names = sorted(export_names)
    npt_bytes = b"".join(struct.pack("<I", name_rvas[name]) for name in sorted_names)
    ot_bytes = b"".join(
        struct.pack("<H", export_names.index(name)) for name in sorted_names
    )
    eat_bytes = b"".join(struct.pack("<I", r) for r in func_rvas)
    placements.append((eat_off, eat_bytes))
    placements.append((npt_off, npt_bytes))
    placements.append((ot_off, ot_bytes))

    export_dir = struct.pack(
        "<IIHHIIIIIII",
        0,
        0,
        0,
        0,
        dll_name_rva,
        1,
        n,
        n,
        eat_off,
        npt_off,
        ot_off,
    )
    export_end = cursor
    export_size = (export_end - exp_off) if export_size_override is None else export_size_override

    # Headers cover DOS+PE+section table plus export/strings/tables at 0x200.
    size_of_headers = 0x400
    image = bytearray(max(0x800 + 0x200, cursor + 16))
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    nsec = 2
    optsz = 0xF0
    struct.pack_into(
        "<HHIIIHH",
        image,
        coff,
        machine,
        nsec,
        0,
        0,
        0,
        optsz,
        0x2022,
    )
    opt = coff + 20
    struct.pack_into("<H", image, opt, magic)
    struct.pack_into("<I", image, opt + 0x3C, size_of_headers)  # SizeOfHeaders
    struct.pack_into("<I", image, opt + 0x6C, 16)
    struct.pack_into("<I", image, opt + 0x70, exp_off)
    struct.pack_into("<I", image, opt + 0x74, export_size)
    so = opt + optsz
    # .text executable
    image[so : so + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", image, so + 8, 0x200, text_rva, 0x200, 0x600)
    struct.pack_into("<I", image, so + 36, text_chars)
    # .data non-exec
    so2 = so + 40
    image[so2 : so2 + 8] = b".data\x00\x00\x00"
    struct.pack_into("<IIII", image, so2 + 8, 0x200, data_rva, 0x200, 0x800)
    struct.pack_into("<I", image, so2 + 36, DATA_CHARS)

    image[exp_off : exp_off + MIN_EXPORT_DIR] = export_dir
    for off, blob in placements:
        image[off : off + len(blob)] = blob
    for i in range(n):
        off = 0x600 + i * 16
        image[off : off + 4] = b"\xC3\x90\x90\x90"

    raw = bytes(image)
    if truncate is not None:
        return raw[:truncate]
    return raw


MIN_EXPORT_DIR = 40


def write_header(path: Path, names: list[str]) -> None:
    lines = ["/* test header */", "#ifndef HS_WEBRTC_H", "#define HS_WEBRTC_H"]
    for name in names:
        lines.append(f"HS_API uint32_t {name}(void);")
    lines += ["#endif", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def run_checker(dll: Path, header: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(dll), str(header)],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def expect_pass(label: str, dll: Path, header: Path) -> None:
    code, out = run_checker(dll, header)
    if code != 0:
        raise SystemExit(f"FAIL {label}: expected pass, got exit {code}\n{out}")
    print(f"ok   {label}")


def expect_fail(label: str, dll: Path, header: Path, needle: str | None = None) -> None:
    code, out = run_checker(dll, header)
    if code == 0:
        raise SystemExit(f"FAIL {label}: expected fail, got pass\n{out}")
    if needle and needle not in out:
        raise SystemExit(f"FAIL {label}: missing {needle!r} in output\n{out}")
    print(f"ok   {label} (exit {code})")


def main() -> int:
    names = [
        "hs_abi_version",
        "hs_engine_init",
        "hs_engine_shutdown",
        "hs_peer_create",
        "hs_verified_channel_acquire",
    ]
    with tempfile.TemporaryDirectory(prefix="hs-pe-export-test-") as td:
        t = Path(td)
        header = t / "hs_webrtc.h"
        write_header(header, names)

        good = t / "good.dll"
        good.write_bytes(build_pe(names))
        expect_pass("matching implemented exports (exec section)", good, header)

        miss = t / "missing.dll"
        miss.write_bytes(build_pe(names, drop_names={"hs_peer_create"}))
        expect_fail("missing header export", miss, header, "missing from DLL")

        extra = t / "extra.dll"
        extra.write_bytes(build_pe(names + ["hs_not_in_header"]))
        expect_fail("unexpected hs_ export", extra, header, "unexpected hs_")

        hook = t / "hook.dll"
        hook.write_bytes(build_pe(names + ["hs_test_force_drain_timeout"]))
        expect_fail("forbidden test hook", hook, header, "forbidden test hook")

        # Forwarded expected export is not implemented.
        fwd = t / "forwarded.dll"
        fwd.write_bytes(
            build_pe(names, forward={"hs_abi_version": "OTHER.dll.hs_abi_version"})
        )
        expect_fail("forwarded export not implemented", fwd, header, "forwarded")

        # Forwarded unexpected hs_ export must also fail.
        fwd_unexp = t / "forwarded-unexpected.dll"
        fwd_unexp.write_bytes(
            build_pe(
                names + ["hs_unexpected_fwd"],
                forward={"hs_unexpected_fwd": "OTHER.dll.x"},
            )
        )
        expect_fail(
            "forwarded unexpected hs_ export",
            fwd_unexp,
            header,
            "unexpected hs_",
        )

        x86 = t / "x86.dll"
        x86.write_bytes(build_pe(names, machine=0x14C))
        expect_fail("wrong machine", x86, header, "machine")

        trunc = t / "trunc.dll"
        trunc.write_bytes(build_pe(names, truncate=64))
        expect_fail("truncated image", trunc, header)

        # Coordinator false-greens: zero / DOS-header function RVA.
        zero = t / "zero-func.dll"
        zero.write_bytes(
            build_pe(names, func_rva_overrides={"hs_abi_version": 0})
        )
        expect_fail("zero function RVA", zero, header, "zero function RVA")

        hdr_rva = t / "header-func.dll"
        hdr_rva.write_bytes(
            build_pe(names, func_rva_overrides={"hs_abi_version": 1})
        )
        expect_fail("DOS-header function RVA", hdr_rva, header, "headers")

        # Non-executable section RVA (data section).
        nonexec = t / "nonexec-func.dll"
        nonexec.write_bytes(
            build_pe(names, func_rva_overrides={"hs_abi_version": 0x2000})
        )
        expect_fail("non-executable function RVA", nonexec, header, "executable")

        # Raw-section overrun: RVA in VirtualSize tail is not implemented.
        # Point at text_rva+0x200 which equals SizeOfRawData end (0x200).
        # .text va=0x1000 rsz=0x200 so 0x1200 is exactly past raw.
        past_raw = t / "past-raw.dll"
        past_raw.write_bytes(
            build_pe(names, func_rva_overrides={"hs_abi_version": 0x1200})
        )
        expect_fail("past SizeOfRawData function RVA", past_raw, header)

        # Non-executable fixture: flip .text to data characteristics.
        noexec = t / "text-not-exec.dll"
        noexec.write_bytes(build_pe(names, text_chars=DATA_CHARS))
        expect_fail("function section not executable", noexec, header, "executable")

        # Export directory size 0 must not silently become 40.
        esz = t / "exp-size0.dll"
        esz.write_bytes(build_pe(names, export_size_override=0))
        expect_fail("export directory size 0", esz, header, "export directory size")

        # Duplicate names: rewrite the second name string to equal the first.
        dup_src = bytearray(build_pe(names))
        n0 = names[0].encode() + b"\x00"
        n1 = names[1].encode() + b"\x00"
        i0 = dup_src.find(n0)
        i1 = dup_src.find(n1)
        if i0 < 0 or i1 < 0:
            raise SystemExit("FAIL duplicate-setup: name strings not found")
        dup_src[i1 : i1 + len(n1)] = n0[: len(n1)].ljust(len(n1), b"\x00")
        dup = t / "dup.dll"
        dup.write_bytes(bytes(dup_src))
        expect_fail("duplicate export name", dup, header, "duplicate")

        empty = t / "empty.dll"
        empty.write_bytes(b"")
        expect_fail("empty dll", empty, header)

        # Overlong / malformed header must fail cleanly (exit 1, no traceback).
        big_hdr = t / "big.h"
        big_hdr.write_bytes(b"HS_API uint32_t hs_abi_version(void);\n" * 1 + b"Z" * (2 * 1024 * 1024))
        code, out = run_checker(good, big_hdr)
        if code == 0 or "Traceback" in out:
            raise SystemExit(f"FAIL overlong header: exit={code}\n{out}")
        print(f"ok   overlong header cleanly rejected (exit {code})")

        bad_hdr = t / "bad.h"
        bad_hdr.write_bytes(b"HS_API uint32_t hs_x(\xff\xfe);\n")
        code, out = run_checker(good, bad_hdr)
        if code == 0 or "Traceback" in out:
            raise SystemExit(f"FAIL malformed header: exit={code}\n{out}")
        print(f"ok   malformed header cleanly rejected (exit {code})")

    print("all check-pe-exports regressions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
