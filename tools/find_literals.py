#!/usr/bin/env python3
"""List frozen string literals matching a regex (UTF-16), with object RVA.

Layout of a frozen literal: [u64 MethodTable*][u32 charcount][utf16 chars];
the object RVA is chars_start-12.  De-duplicates by object.

Usage: python find_literals.py <regex> [<regex> ...]
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\USLocalServer.Server.exe")

SECS = [
    (".text", 0x00001000, 0x00a05bb6, 0x00000400, 0x00a05c00),
    (".rdata", 0x00a07000, 0x058f39c6, 0x00a06000, 0x058f3a00),
    (".data", 0x062fb000, 0x001e6418, 0x062f9a00, 0x0018a400),
]
IMAGE_BASE = 0x140000000
IMAGE_END = IMAGE_BASE + 0x6500000

D = EXE.read_bytes()


def off2rva(off):
    for _n, va, _vs, ro, rs in SECS:
        if ro <= off < ro + rs:
            return va + (off - ro)
    return None


def lit_obj_at(off, back=8192):
    """Containing frozen literal for char offset `off`: (chars_off, text)."""
    best = None
    for q in range(off, max(12, off - back), -1):
        if D[q - 8:q - 4] != b"\x01\x00\x00\x00":
            continue
        mt = struct.unpack_from("<Q", D, q - 12)[0]
        if not (IMAGE_BASE <= mt < IMAGE_END):
            continue
        n = struct.unpack_from("<I", D, q - 4)[0]
        if n == 0 or n > 4096 or q + 2 * n < off:
            continue
        s = D[q:q + 2 * n]
        if any(x != 0 for x in s[1::2]):
            continue
        try:
            best = (q, s.decode("utf-16-le"))
        except UnicodeDecodeError:
            continue
    return best


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    seen = set()
    for pat in argv:
        print(f"\n===== {pat!r} =====")
        rx = re.compile(re.escape(pat).decode() if isinstance(pat, bytes) else re.escape(pat),
                        re.I)
        b = pat.encode("utf-16-le") if pat.isascii() else None
        if b is None:
            print("  (non-ascii patterns unsupported)")
            continue
        for m in re.finditer(re.escape(b), D, re.I):
            off = m.start()
            hit = lit_obj_at(off)
            if not hit:
                print(f"  hit @0x{off:x} (no literal header) rva 0x{off2rva(off) or 0:08x}")
                continue
            q, txt = hit
            rva = off2rva(q)
            key = (rva, txt)
            if key in seen:
                continue
            seen.add(key)
            print(f"  obj rva 0x{rva:08x} (chars 0x{off2rva(off):08x})  {txt!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
