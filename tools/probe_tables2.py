#!/usr/bin/env python3
"""Dump the payload boundaries of the embedded crypto tables (rva space)."""

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


def asc(off, n):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in D[off:off + n])


def dump(rva, n):
    o = rva2off(rva)
    for i in range(0, n, 16):
        c = D[o + i:o + i + 16]
        h = " ".join(f"{b:02x}" for b in c)
        print(f"  {rva + i:08x}  {h:<47}  {asc(o + i, 16)}")


def u32(rva, n):
    o = rva2off(rva)
    return struct.unpack_from(f"<{n}I", D, o)


def u64(rva, n):
    o = rva2off(rva)
    return struct.unpack_from(f"<{n}Q", D, o)


print("== blowfish S0 start 0x58eabf0 (canonical pi digits expected) ==")
dump(0x58EABF0, 64)
print("   S1 start 0x58ebbf0:")
dump(0x58EBBF0, 64)
print("   tail 0x58ebe90..0x58ebf00:")
dump(0x58EBE90, 0x70)

print("\n== rcon / sbox candidates 0x58ebc30..0x58ebed0 ==")
dump(0x58EBC30, 0x60)

print("\n== T-table start 0x58ebed0 ==")
v = u32(0x58EBED0, 16)
print("   u32:", " ".join(f"{x:08x}" for x in v))
v = u32(0x58EBED0, 256)
small = [(i, x) for i, x in enumerate(v) if x <= 0xFFFF]
print("   entries <= 64K:", small)

print("\n== 0x58eced0..0x58eda20 ==")
dump(0x58ECED0, 0x60)
dump(0x58ED000, 0x40)
print("   u32 @0x58eda00:", " ".join(f"{x:08x}" for x in u32(0x58EDA00, 16)))

print("\n== khazad block 1 @0x58eda08 as u64 ==")
v = u64(0x58EDA08, 8)
print("   u64:", " ".join(f"{x:016x}" for x in v))
dump(0x58EDA08, 0x40)
print("   khazad block 2 @0x58ee208:")
dump(0x58EE208, 0x20)

print("\n== khazad tail + keyblob + manifest start 0x58f1200..0x58f1720 ==")
dump(0x58F1200, 0x520)
