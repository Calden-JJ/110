#!/usr/bin/env python3
"""Extract cipher constant tables the same way the server's static ctors do.

The AOT image initializes table arrays with
    lea rdx, [rip + <table blob>] ; mov r8d, size ; call memcpy
so scanning for memcpy call sites (target 0x180660) recovers every table
blob with its size.  Run:  python extract_tables.py
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import EXE, rva2off  # noqa

D = EXE.read_bytes()
MEMCPY = 0x180660
TEXT_LO, TEXT_HI = 0x1000, 0xa05bb6


def scan():
    out = []
    for rva in range(TEXT_LO, TEXT_HI - 5):
        o = rva2off(rva)
        if D[o] != 0xE8:
            continue
        tgt = rva + 5 + struct.unpack_from("<i", D, o + 1)[0]
        if tgt != MEMCPY:
            continue
        # look back for lea rdx,[rip+X] (48 8d 15) and mov r8d, imm32 (41 b8)
        src = size = None
        for k in range(rva - 1, max(rva - 24, 0), -1):
            o = rva2off(k)
            if size is None and D[o:o + 2] == b"\x41\xb8":
                size = struct.unpack_from("<I", D, o + 2)[0]
            elif src is None and D[o:o + 3] == b"\x48\x8d\x15":
                src = k + 7 + struct.unpack_from("<i", D, o + 3)[0]
            if src is not None and size is not None:
                break
        if src is not None:
            out.append((rva, src, size))
    return out


def main():
    sites = scan()
    print(f"{len(sites)} memcpy sites")
    for site, src, size in sites:
        if size is None or size < 64 or size > 0x20000:
            continue
        o = rva2off(src)
        if o is None:
            continue
        head = D[o:o + 24].hex(" ")
        print(f"  site {site:#08x}  src {src:#08x}  size {size:#06x} ({size})")
        print(f"      head: {head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
