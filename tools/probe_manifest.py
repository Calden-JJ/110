#!/usr/bin/env python3
"""Parse the NativeAOT manifest-resource listing in USLocalServer.Server.exe.

Entries look like:
    [u8 2*len][ASCII assembly-qualified name][u8 2*len][ASCII resource name]
followed by a small binary tail.  Walk the whole region, print every string
with the bytes that separate it from the previous one.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\USLocalServer.Server.exe")
D = EXE.read_bytes()

SECS = [
    (".text", 0x00001000, 0x00a05bb6, 0x00000400, 0x00a05c00),
    (".rdata", 0x00a07000, 0x058f39c6, 0x00a06000, 0x058f3a00),
    (".data", 0x062fb000, 0x001e6418, 0x062f9a00, 0x0018a400),
]


def rva2off(rva):
    for _n, va, vs, ro, _rs in SECS:
        if va <= rva < va + vs:
            o = ro + (rva - va)
            return o if 0 <= o < len(D) else None
    return None


def off2rva(off):
    for _n, va, _vs, ro, rs in SECS:
        if ro <= off < ro + rs:
            return va + (off - ro)
    return None


def scan(start_rva, end_rva):
    """Greedy [len][ascii] walk; returns list of (rva, name)."""
    o = rva2off(start_rva)
    e = rva2off(end_rva)
    out = []
    while o < e:
        L = D[o]
        if L == 0 or L % 2 or L > 0xF0:
            o += 1
            continue
        n = L // 2
        s = D[o + 1:o + 1 + n]
        if len(s) == n and all(32 <= c < 127 for c in s):
            out.append((off2rva(o), s.decode()))
            o += 1 + n
        else:
            o += 1
    return out


def main():
    hi = 0x00000000
    start = 0x58F1000
    end = 0x58F4D00
    items = scan(start, end)
    print(f"scanned rva 0x{start:x}..0x{end:x}: {len(items)} length-prefixed ASCII strings\n")
    prev_end = None
    for i, (rva, s) in enumerate(items):
        o = rva2off(rva) - 1
        gap = b""
        gp = None
        if prev_end is not None and o > prev_end:
            gap = D[prev_end:o]
            gp = off2rva(prev_end)
        gtxt = ""
        if gap:
            gtxt = " gap@" + (f"0x{gp:08x}" if gp is not None else "?") + " = " + gap.hex()
            if len(gap) >= 4:
                u = struct.unpack_from(f"<{len(gap)//4}I", gap.ljust(4 * (len(gap) // 4), b"\0"))
                gtxt += "  u32=" + ",".join(f"{v:x}" for v in u)
        print(f"[{i:3}] 0x{rva:08x} L={2*len(s):3d} {s!r}{gtxt}")
        prev_end = rva2off(rva) + len(s)

    print("\n-- file bytes at rva 0x14dd824 (tail field of algo06_misty1_s7) --")
    o = rva2off(0x14DD824)
    if o:
        print("   rva 0x14dd824:", D[o:o + 64].hex())
        print("   as ascii    :", D[o:o + 64])
    o2 = 0x14DD824
    print("-- file bytes at file offset 0x14dd824 --")
    print("   rva 0x%x:" % off2rva(o2), D[o2:o2 + 64].hex())


if __name__ == "__main__":
    raise SystemExit(main())
