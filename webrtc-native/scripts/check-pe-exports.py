#!/usr/bin/env python3
"""Verify hs_webrtc_shared.dll PE32+ x64 exports against a generated header.

Parses the real PE export directory (not raw file strings). Compares every
implemented (non-forwarded) export name to every HS_API declaration in the
supplied generated header. Integrity/metadata only: no signing, release, or
admission claim.

Usage:
  python3 check-pe-exports.py <dll> <header.h>

Exit 0 when the DLL export set equals the header HS_API set (implemented,
non-forwarded, executable raw-backed). Exit 1 on any structural, bound, or
set mismatch. Exit 2 on usage/IO errors.
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

# --- fail-closed bounds ----------------------------------------------------
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_HEADER_FILE_BYTES = 1 * 1024 * 1024
MAX_SECTIONS = 96
MAX_EXPORTS = 4096
MAX_NAME_LEN = 256
MAX_E_LFANEW = 4096
MAX_FORWARDER_LEN = 256
MAX_SIZE_OF_HEADERS = 4096
MIN_PE_HEADERS = 64
MIN_EXPORT_DIR = 40

# IMAGE_FILE_MACHINE_AMD64 / PE32+ optional magic
MACHINE_AMD64 = 0x8664
OPT_MAGIC_PE32_PLUS = 0x20B

# IMAGE_SCN_MEM_EXECUTE — function exports must live here (product contract:
# all HS_API entries are functions). PE generally allows data exports; this
# ABI does not.
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Harness-only test seam; must never appear in shared-library exports.
FORBIDDEN_NAME_PREFIXES = ("hs_test_",)

HS_API_DECL_RE = re.compile(
    r"^\s*HS_API\b[^;]*?\b(hs_[A-Za-z0-9_]+)\s*\(",
    re.MULTILINE,
)


class PeError(Exception):
    """Structural or contract failure. Message is the user-facing reason."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_header_exports(header_path: Path) -> list[str]:
    try:
        hsize = header_path.stat().st_size
        if hsize <= 0:
            raise PeError("header is empty")
        if hsize > MAX_HEADER_FILE_BYTES:
            raise PeError(f"header size {hsize} exceeds bound {MAX_HEADER_FILE_BYTES}")
        text = header_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PeError(f"header is not valid UTF-8: {exc}") from exc
    names: list[str] = []
    seen: set[str] = set()
    for match in HS_API_DECL_RE.finditer(text):
        name = match.group(1)
        if name in seen:
            raise PeError(f"duplicate HS_API declaration in header: {name}")
        if len(name) > MAX_NAME_LEN:
            raise PeError(f"HS_API name too long in header: {name[:32]}...")
        seen.add(name)
        names.append(name)
    if not names:
        raise PeError("no HS_API declarations found in header")
    return names


class PeImage:
    """Bounded PE32+ AMD64 image with export-directory access only."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)
        # (va, vsz, ptr, rsz, characteristics)
        self.sections: list[tuple[int, int, int, int, int]] = []
        self.size_of_headers = 0
        self.export_rva = 0
        self.export_size = 0
        self._parse_headers()

    def _u16(self, off: int) -> int:
        if off < 0 or off + 2 > self.size:
            raise PeError(f"truncated read u16 at {off}")
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int) -> int:
        if off < 0 or off + 4 > self.size:
            raise PeError(f"truncated read u32 at {off}")
        return struct.unpack_from("<I", self.data, off)[0]

    def _bytes(self, off: int, n: int) -> bytes:
        if off < 0 or n < 0 or off + n > self.size:
            raise PeError(f"truncated read bytes at {off}+{n}")
        return self.data[off : off + n]

    def _headers_span(self) -> tuple[int, int]:
        """File-offset span of the PE headers region (RVA == offset)."""
        return (0, self.size_of_headers)

    def _section_raw_span(self, rva: int, need: int) -> tuple[int, int, int]:
        """Return (file_off, raw_begin, raw_end) for a raw-backed section read.

        Only SizeOfRawData is file-backed. VirtualSize tail is zero-fill and
        must not borrow bytes from another file region.
        """
        for va, _vsz, ptr, rsz, _chars in self.sections:
            if rsz == 0:
                continue
            if va <= rva and rva + need <= va + rsz:
                off = rva - va + ptr
                if off < 0 or off + need > self.size:
                    raise PeError(
                        f"RVA {rva:#x} maps outside file (off={off} need={need})"
                    )
                if (rva - va + need) > rsz:
                    raise PeError(
                        f"RVA {rva:#x} extends past raw section data (need={need})"
                    )
                return off, ptr, ptr + rsz
        raise PeError(f"RVA {rva:#x} not in raw-backed section data")

    def rva_to_offset(self, rva: int, need: int = 1) -> int:
        if rva < 0:
            raise PeError(f"negative RVA {rva}")
        if need <= 0:
            raise PeError("non-positive read size")
        if rva + need > self.size:
            raise PeError(f"RVA {rva:#x}+{need} outside file")
        # Headers region: strictly SizeOfHeaders, not arbitrary gap below
        # the first section VA (PE spec: SizeOfHeaders bounds mapped headers).
        if rva + need <= self.size_of_headers:
            return rva
        off, _b, _e = self._section_raw_span(rva, need)
        return off

    def read_c_string(self, rva: int, max_len: int = MAX_NAME_LEN) -> str:
        """Read a C string that lies entirely in one mapped raw/header region."""
        if rva < 0:
            raise PeError(f"negative string RVA {rva}")
        if rva >= self.size:
            raise PeError(f"string RVA {rva:#x} outside file")
        # Determine the one valid region this RVA lives in.
        if rva < self.size_of_headers:
            region_lo = 0
            region_hi = self.size_of_headers
        else:
            found = False
            region_lo = region_hi = 0
            for va, _vsz, ptr, rsz, _chars in self.sections:
                if rsz == 0:
                    continue
                if va <= rva < va + rsz:
                    region_lo = ptr
                    region_hi = ptr + rsz
                    found = True
                    break
            if not found:
                raise PeError(f"string RVA {rva:#x} not in raw-backed section data")
        # File offset of this RVA within its region.
        if rva < self.size_of_headers:
            off = rva
        else:
            off = self.rva_to_offset(rva, 1)
        # NUL must sit inside the same region; never scan across unmapped gap
        # or into the next section.
        scan_hi = min(region_hi, off + max_len + 1, self.size)
        end = self.data.find(b"\x00", off, scan_hi)
        if end < 0:
            raise PeError(
                f"unterminated string at RVA {rva:#x} (max {max_len}, region ends {region_hi})"
            )
        raw = self.data[off:end]
        try:
            s = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise PeError(f"non-ASCII name at RVA {rva:#x}") from exc
        if not s:
            raise PeError(f"empty name at RVA {rva:#x}")
        return s

    def _parse_headers(self) -> None:
        if self.size < MIN_PE_HEADERS:
            raise PeError(f"file too small for PE headers ({self.size} bytes)")
        if self._bytes(0, 2) != b"MZ":
            raise PeError("missing MZ signature")
        e_lfanew = self._u32(0x3C)
        if e_lfanew < 0x40 or e_lfanew > MAX_E_LFANEW:
            raise PeError(f"e_lfanew out of bounds: {e_lfanew}")
        if self._bytes(e_lfanew, 4) != b"PE\x00\x00":
            raise PeError("missing PE signature")
        coff = e_lfanew + 4
        machine = self._u16(coff)
        if machine != MACHINE_AMD64:
            raise PeError(f"machine is {machine:#06x}; expected x64 (0x8664)")
        nsec = self._u16(coff + 2)
        if nsec == 0 or nsec > MAX_SECTIONS:
            raise PeError(f"section count {nsec} outside 1..{MAX_SECTIONS}")
        optsz = self._u16(coff + 16)
        opt = coff + 20
        if optsz < 0x70 + 8 or opt + optsz > self.size:
            raise PeError(f"optional header size {optsz} invalid")
        magic = self._u16(opt)
        if magic != OPT_MAGIC_PE32_PLUS:
            raise PeError(f"optional magic {magic:#06x}; expected PE32+ (0x20B)")

        # SizeOfHeaders bounds the mapped headers region (PE format spec).
        self.size_of_headers = self._u32(opt + 0x3C)
        if self.size_of_headers < MIN_PE_HEADERS or self.size_of_headers > MAX_SIZE_OF_HEADERS:
            raise PeError(
                f"SizeOfHeaders {self.size_of_headers} outside "
                f"{MIN_PE_HEADERS}..{MAX_SIZE_OF_HEADERS}"
            )
        if self.size_of_headers > self.size:
            raise PeError("SizeOfHeaders exceeds file size")

        nrva = self._u32(opt + 0x6C)
        if nrva < 1:
            raise PeError("NumberOfRvaAndSizes < 1 (no export directory slot)")
        self.export_rva = self._u32(opt + 0x70)
        self.export_size = self._u32(opt + 0x74)

        sec_off = opt + optsz
        for i in range(nsec):
            so = sec_off + i * 40
            if so + 40 > self.size:
                raise PeError(f"section table truncated at index {i}")
            vsz = self._u32(so + 8)
            va = self._u32(so + 12)
            rsz = self._u32(so + 16)
            ptr = self._u32(so + 20)
            chars = self._u32(so + 36)
            if rsz and (ptr < 0 or ptr + rsz > self.size):
                raise PeError(f"section {i} raw data outside file")
            if va and va < self.size_of_headers:
                raise PeError(f"section {i} VA {va:#x} overlaps headers")
            self.sections.append((va, vsz, ptr, rsz, chars))

    def _export_dir_span(self) -> tuple[int, int]:
        """Validate export data directory and return (rva_lo, rva_hi)."""
        if self.export_rva == 0:
            raise PeError("no export directory")
        if self.export_size < MIN_EXPORT_DIR:
            raise PeError(
                f"export directory size {self.export_size} < {MIN_EXPORT_DIR}"
            )
        # Entire export data-directory span must map in one raw/header region.
        if self.export_rva + self.export_size <= self.size_of_headers:
            if self.export_rva + self.export_size > self.size:
                raise PeError("export directory extends past file (headers)")
        else:
            self._section_raw_span(self.export_rva, self.export_size)
        return self.export_rva, self.export_rva + self.export_size

    def export_names(self) -> list[tuple[str, int, int, bool, str | None]]:
        """Return (name, ordinal_index, func_rva, is_forwarder, forwarder)."""
        exp_lo, exp_hi = self._export_dir_span()
        eoff = self.rva_to_offset(self.export_rva, MIN_EXPORT_DIR)
        (
            _chars,
            _ts,
            _maj,
            _min,
            _name_rva,
            base,
            nfunc,
            nnames,
            eat_rva,
            npt_rva,
            ot_rva,
        ) = struct.unpack_from("<IIHHIIIIIII", self.data, eoff)

        if nfunc == 0 or nnames == 0:
            raise PeError(f"empty export table (functions={nfunc} names={nnames})")
        if nfunc > MAX_EXPORTS or nnames > MAX_EXPORTS:
            raise PeError(
                f"export counts exceed bound (functions={nfunc} names={nnames} max={MAX_EXPORTS})"
            )
        if nnames > nfunc:
            raise PeError(f"more export names ({nnames}) than functions ({nfunc})")
        if base < 1:
            raise PeError(f"export ordinal base {base} < 1")

        eat_off = self.rva_to_offset(eat_rva, 4 * nfunc)
        npt_off = self.rva_to_offset(npt_rva, 4 * nnames)
        ot_off = self.rva_to_offset(ot_rva, 2 * nnames)

        out: list[tuple[str, int, int, bool, str | None]] = []
        seen: set[str] = set()
        prev_name: str | None = None
        for i in range(nnames):
            name_rva = self._u32(npt_off + 4 * i)
            name = self.read_c_string(name_rva)
            if len(name) > MAX_NAME_LEN:
                raise PeError(f"export name too long: {name[:32]}...")
            if name in seen:
                raise PeError(f"duplicate export name: {name}")
            # Product contract surfaces even if the name table is also malformed.
            for prefix in FORBIDDEN_NAME_PREFIXES:
                if name.startswith(prefix):
                    raise PeError(f"forbidden test hook exported: {name}")
            # PE loader binary-searches the name pointer table; require order.
            if prev_name is not None and name < prev_name:
                raise PeError(
                    f"export names not lexically ordered: {name!r} after {prev_name!r}"
                )
            prev_name = name
            seen.add(name)
            ord_index = self._u16(ot_off + 2 * i)
            if ord_index >= nfunc:
                raise PeError(
                    f"ordinal index {ord_index} out of range for {name} (nfunc={nfunc})"
                )
            func_rva = self._u32(eat_off + 4 * ord_index)
            is_fwd = exp_lo <= func_rva < exp_hi
            forwarder = None
            if is_fwd:
                # Forwarder string must lie entirely inside export data-directory
                # range (PE format spec).
                forwarder = self.read_c_string(func_rva, MAX_FORWARDER_LEN)
                end_rva = func_rva + len(forwarder) + 1
                if end_rva > exp_hi:
                    raise PeError(
                        f"forwarder string for {name} leaves export directory"
                    )
            else:
                self._require_function_rva(name, func_rva)
            out.append((name, ord_index, func_rva, is_fwd, forwarder))
        return out

    def _require_function_rva(self, name: str, func_rva: int) -> None:
        """Implemented function export: nonzero, raw-backed, executable section."""
        if func_rva == 0:
            raise PeError(f"export {name} has zero function RVA")
        if func_rva < self.size_of_headers:
            raise PeError(
                f"export {name} function RVA {func_rva:#x} is in PE/DOS headers"
            )
        for va, _vsz, ptr, rsz, chars in self.sections:
            if rsz == 0:
                continue
            if va <= func_rva < va + rsz:
                if not (chars & IMAGE_SCN_MEM_EXECUTE):
                    raise PeError(
                        f"export {name} function RVA {func_rva:#x} is not in an "
                        f"executable raw-backed section (chars={chars:#x})"
                    )
                off = func_rva - va + ptr
                if off + 1 > self.size or off < ptr or off + 1 > ptr + rsz:
                    raise PeError(
                        f"export {name} function RVA {func_rva:#x} outside raw section"
                    )
                return
        # Virtual-only tail or unmapped gap must not count as implemented.
        for va, vsz, ptr, rsz, chars in self.sections:
            if rsz and va <= func_rva < va + max(vsz, rsz):
                raise PeError(
                    f"export {name} function RVA {func_rva:#x} is zero-fill "
                    f"/ past SizeOfRawData (rsz={rsz})"
                )
        raise PeError(
            f"export {name} function RVA {func_rva:#x} not in any executable section"
        )


def check(dll_path: Path, header_path: Path) -> int:
    if not dll_path.is_file():
        raise PeError(f"DLL not found: {dll_path}")
    if not header_path.is_file():
        raise PeError(f"header not found: {header_path}")
    dll_size = dll_path.stat().st_size
    if dll_size <= 0:
        raise PeError("DLL is empty")
    if dll_size > MAX_FILE_BYTES:
        raise PeError(f"DLL size {dll_size} exceeds bound {MAX_FILE_BYTES}")

    header_names = parse_header_exports(header_path)
    header_set = set(header_names)

    data = dll_path.read_bytes()
    pe = PeImage(data)
    entries = pe.export_names()

    implemented: list[str] = []
    forwarded: list[tuple[str, str]] = []
    forbidden: list[str] = []
    for name, _oi, _frva, is_fwd, forwarder in entries:
        # Test-hook names fail regardless of forwarding.
        for prefix in FORBIDDEN_NAME_PREFIXES:
            if name.startswith(prefix):
                forbidden.append(name)
        if is_fwd:
            forwarded.append((name, forwarder or ""))
        else:
            implemented.append(name)

    implemented_set = set(implemented)
    forwarded_set = {name: target for name, target in forwarded}

    problems: list[str] = []
    if forbidden:
        problems.append("forbidden test hook exported: " + ", ".join(sorted(forbidden)))

    missing = sorted(header_set - implemented_set)
    if missing:
        only_forwarded = [n for n in missing if n in forwarded_set]
        truly_missing = [n for n in missing if n not in forwarded_set]
        if only_forwarded:
            problems.append(
                "header exports only forwarded, not implemented: "
                + ", ".join(f"{n}->{forwarded_set[n]}" for n in only_forwarded)
            )
        if truly_missing:
            problems.append(
                "header exports missing from DLL implemented export table: "
                + ", ".join(truly_missing)
            )

    # Unexpected hs_ surface fails whether implemented or forwarded.
    unexpected = sorted(
        n
        for n in set(implemented_set) | set(forwarded_set)
        if n.startswith("hs_") and n not in header_set
    )
    if unexpected:
        problems.append(
            "unexpected hs_ exports in DLL not declared by header: "
            + ", ".join(unexpected)
        )

    if problems:
        raise PeError("; ".join(problems))

    # Non-hs_ exports are tolerated (CRT/toolchain noise is not this contract).
    dll_sha = hashlib.sha256(data).hexdigest()
    hdr_sha = sha256_file(header_path)
    print("check-pe-exports: OK")
    print(f"  dll_path={dll_path}")
    print(f"  dll_sha256={dll_sha}")
    print(f"  dll_bytes={dll_size}")
    print(f"  header_path={header_path}")
    print(f"  header_sha256={hdr_sha}")
    print(f"  machine=0x{MACHINE_AMD64:04x} (x64) magic=0x{OPT_MAGIC_PE32_PLUS:04x} (PE32+)")
    print(f"  size_of_headers={pe.size_of_headers:#x}")
    print(f"  header_exports={len(header_names)}")
    print(f"  dll_implemented={len(implemented)} dll_forwarded={len(forwarded)}")
    print("  names:")
    for name in sorted(implemented_set):
        print(f"    {name}")
    if forwarded:
        print("  forwarded (not implemented):")
        for name, target in forwarded:
            print(f"    {name} -> {target}")
    print("  note: integrity/metadata only; not a signing, release, or admission claim")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: check-pe-exports.py <dll> <header.h>",
            file=sys.stderr,
        )
        return 2
    try:
        return check(Path(argv[1]), Path(argv[2]))
    except PeError as exc:
        print(f"check-pe-exports: FAIL: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, struct.error) as exc:
        print(f"check-pe-exports: ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — never leak a traceback
        print(f"check-pe-exports: ERROR: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
