#!/usr/bin/env python3
"""Reproduce the KernelSU kernel module this project ships.

Upstream source: sarabpal-dev/KernelSU-Next v3.4.0, asset `kernelsu-android12-5.10.ko`
(KMI android12-5.10). Its DEFEX and KDP steps are fail-open, so they tolerate this
firmware, which has no CONFIG_DEFEX.

The upstream bytes still do not load by plain insmod: the module carries a `__versions`
section whose entry for `module_layout` holds a CRC from a different kernel revision, so
`check_version()` rejects the image. On this kernel that rejection is silent for the ELF
checks that follow, which is why the earlier attempts looked inexplicable.

The fix this project applies, and the ONLY change it makes:

    keep the `__versions` section, zero its contents in place.

`check_version()` then finds no matching symbol name, warns once, and continues -- the
path this kernel tolerates. Removing the section entirely does NOT work (the full
vermagic string is then compared and fails).

Verified 2026-10-09 on Galaxy XR (SM-I610, I610UEU2AZF3, kernel 5.10.240): the patched
image inserts with plain `insmod` and KernelSU registers. See
builds/gxr-kernel/ksu-probe-20261009/RECEIPT.md.

Usage:
    patch_kernelsu_module.py --upstream kernelsu-android12-5.10.ko --out kernelsu-gxr.ko
    patch_kernelsu_module.py --verify kernelsu-gxr.ko --upstream kernelsu-android12-5.10.ko
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

VERSIONS_SECTION = "__versions"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(Path(path).read_bytes())
    return digest.hexdigest()


def sections(blob: bytes | bytearray) -> list[tuple[str, int, int]]:
    """Returns (name, offset, size) for every section; raises if the ELF is malformed."""
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise ValueError("not an ELF image")
    if blob[4] != 2:
        raise ValueError("not a 64-bit ELF image")
    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
    headers = [struct.unpack_from("<IIQQQQIIQQ", blob, e_shoff + k * e_shentsize)
               for k in range(e_shnum)]
    names_at = headers[e_shstrndx][4]
    out = []
    for header in headers:
        start = names_at + header[0]
        end = blob.index(b"\x00", start)
        out.append((blob[start:end].decode("utf-8", "replace"), header[4], header[5]))
    return out


def find_section(blob: bytes | bytearray, name: str) -> tuple[int, int]:
    for section, offset, size in sections(blob):
        if section == name:
            return offset, size
    raise ValueError(f"section {name} not found")


def vermagic(blob: bytes | bytearray) -> str:
    offset, size = find_section(blob, ".modinfo")
    for field in blob[offset:offset + size].split(b"\x00"):
        if field.startswith(b"vermagic="):
            return field.decode("utf-8", "replace")
    return "(none)"


def differing_range(before: bytes, after: bytes) -> tuple[int, int] | None:
    if len(before) != len(after):
        return None
    indexes = [i for i in range(len(before)) if before[i] != after[i]]
    return (indexes[0], indexes[-1]) if indexes else None


def patch(upstream: Path, out: Path) -> int:
    blob = bytearray(Path(upstream).read_bytes())
    offset, size = find_section(blob, VERSIONS_SECTION)
    if blob[offset:offset + size] == b"\x00" * size:
        print(f"{upstream} already has an empty {VERSIONS_SECTION}; nothing to do.")
    blob[offset:offset + size] = b"\x00" * size
    patched = bytes(blob)
    original = Path(upstream).read_bytes()
    changed = differing_range(original, patched)
    if changed is None:
        raise SystemExit("patch produced no change; refusing to publish")
    if not (offset <= changed[0] and changed[1] < offset + size):
        raise SystemExit("change escaped the __versions section; refusing to publish")
    out.write_bytes(patched)
    print(f"upstream vermagic: {vermagic(original)}")
    print(f"{VERSIONS_SECTION}: offset {offset}, size {size}, bytes cleared "
          f"{changed[1] - changed[0] + 1}")
    print(f"upstream sha256: {sha256(upstream)}")
    print(f"patched  sha256: {sha256(out)}  ({out.stat().st_size} bytes)")
    return 0


def verify(patched: Path, upstream: Path) -> int:
    before = Path(upstream).read_bytes()
    after = Path(patched).read_bytes()
    if len(before) != len(after):
        print("FAIL: size differs from upstream")
        return 1
    offset, size = find_section(before, VERSIONS_SECTION)
    changed = differing_range(before, after)
    if changed is None:
        print("FAIL: identical to upstream; the fix is missing")
        return 1
    if not (offset <= changed[0] and changed[1] < offset + size):
        print(f"FAIL: bytes changed outside {VERSIONS_SECTION} "
              f"({changed[0]}..{changed[1]} vs section {offset}..{offset + size - 1})")
        return 1
    if after[offset:offset + size] != b"\x00" * size:
        print(f"FAIL: {VERSIONS_SECTION} is not fully zeroed")
        return 1
    print(f"OK: {patched} differs from upstream only inside {VERSIONS_SECTION} "
          f"({changed[1] - changed[0] + 1} bytes cleared); vermagic {vermagic(after)}")
    print(f"patched sha256: {sha256(patched)}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--upstream", required=True, type=Path,
                        help="unmodified kernelsu-android12-5.10.ko from the release")
    parser.add_argument("--out", type=Path, help="where to write the patched module")
    parser.add_argument("--verify", type=Path,
                        help="check an existing patched module against --upstream")
    args = parser.parse_args(argv)
    if args.verify:
        return verify(args.verify, args.upstream)
    if not args.out:
        parser.error("--out is required unless --verify is used")
    return patch(args.upstream, args.out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
