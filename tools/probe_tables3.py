#!/usr/bin/env python3
"""Identify each crypto table by content: pi digits, broadcast tables, T families."""

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


def u32(rva, n):
    return struct.unpack_from(f"<{n}I", D, rva2off(rva))


def pi_words(nwords):
    """First nwords 32-bit words of pi's fractional hex expansion (P-array then S-boxes)."""
    P = nwords * 32 + 128

    def atan_inv(x):
        total = term = (1 << P) // x
        x2 = x * x
        n = 1
        sign = -1
        while term:
            term //= x2
            total += sign * (term // (2 * n + 1))
            sign = -sign
            n += 1
        return total

    val = 16 * atan_inv(5) - 4 * atan_inv(239) - 3 * (1 << P)
    return [(val >> (P - 32 * (i + 1))) & 0xFFFFFFFF for i in range(nwords)]


print("== pi check ==")
PI = pi_words(1100)
print("   word0 = %08x (expect 243f6a88)" % PI[0])
print("   word18 = %08x (expect d1310ba6)" % PI[18])

print("\n== how far do canonical pi S-boxes run from 0x58eabf0? ==")
start = 0x58EABF0
data = D[rva2off(start):rva2off(start) + 4 * 1100]
match = 0
for i in range(1024):                     # S0..S3 = pi words 18..1041
    if struct.unpack_from("<I", data, 4 * i)[0] != PI[18 + i]:
        break
    match = i + 1
print(f"   matched {match} u32 ({match * 4} B) of the 1024 expected")
if match < 1024:
    bad = 18 + match
    print(f"   first mismatch at word {bad}: file=%08x pi=%08x"
          % (struct.unpack_from('<I', data, 4 * match)[0], PI[bad]))

print("\n== candidate tables ==")
for rva in (0x58EABF0, 0x58EBBF0, 0x58EBC30, 0x58EBED0, 0x58EC2D0, 0x58EC6D0,
            0x58ECAD0, 0x58ECED0, 0x58ED034, 0x58ED800, 0x58EDA00):
    v = u32(rva, 16)
    bcast = all((x >> 8) == (x & 0xFF) and (x >> 16) == (x & 0xFF) and (x >> 24) == (x & 0xFF) for x in v)
    print(f"   0x{rva:08x}: " + " ".join(f"{x:08x}" for x in v[:8]) + ("  <broadcast u32>" if bcast else ""))

print("\n== broadcast-table byte sequences (every u32 = b*0x01010101) ==")
for rva in (0x58EBC30, 0x58EBED0, 0x58EC2D0, 0x58EC6D0, 0x58ECAD0):
    v = u32(rva, 256)
    ok = all((x >> 8) == (x & 0xFF) and (x >> 16) == (x & 0xFF) and (x >> 24) == (x & 0xFF) for x in v)
    seq = [x & 0xFF for x in v]
    uniq = len(set(seq)) == 256
    print(f"   0x{rva:08x}: broadcast={ok} permutation={uniq} first8={[hex(s) for s in seq[:8]]}")

print("\n== which bytes are duplicated across the payload? ==")

seq_a = [u32(0x58EBC30, 256)[i] & 0xFF for i in range(256)]
seq_b = [u32(0x58EBED0, 256)[i] & 0xFF for i in range(256)]
t_tbl = [u32(0x58ECED0, 256)[i] & 0xFF for i in range(256)]
print("   seq@0x58ebc30 == seq@0x58ebed0 :", seq_a == seq_b)
print("   seq@0x58ebc30 == T-first-bytes  :", seq_a == t_tbl)
print("   seq@0x58ebed0 == T-first-bytes  :", seq_b == t_tbl)
inv = [0] * 256
for i, s in enumerate(seq_b):
    inv[s] = i
print("   seq@0x58ebed0 inverse == seq@0x58ebc30:", inv == seq_a)

print("\n== T-table structure at 0x58eced0 (s,2s,4s,6s?) ==")
t = u32(0x58ECED0, 256)
s0 = t[0] & 0xFF
for i in (0, 1, 2, 3, 100, 255):
    x = t[i]
    b = x & 0xFF
    print(f"   T[{i:3}] = {x:08x}  bytes={x.to_bytes(4,'little').hex()}  (s={b:02x})")

print("\n== 4 tables 0x58ebed0..0x58eced0: rotation family? ==")
tabs = [u32(0x58EBED0 + 0x400 * k, 256) for k in range(4)]
for k in range(1, 4):
    # T_k[i] should be byte-rotate of T_0[i]
    same = sum(1 for i in range(256)
               if tabs[k][i] == ((tabs[0][i] >> 8) | ((tabs[0][i] & 0xFF) << 24)))
    same4 = sum(1 for i in range(256)
                if tabs[k][i] == ((tabs[0][i] >> 24) | ((tabs[0][i] & 0xFFFFFF) << 8)))
    print(f"   T{k} vs T0: rotr8 matches={same}/256  rotl8 matches={same4}/256")

print("\n== khazad blocks 0x58eda00 + 0x800*k (u64[256]) ==")
blk0 = struct.unpack_from("<256Q", D, rva2off(0x58EDA00))
for k in range(1, 8):
    o = rva2off(0x58EDA00 + 0x800 * k)
    blk = struct.unpack_from("<256Q", D, o)
    for rot in range(1, 8):
        m = sum(1 for i in range(256) if blk[i] == (((blk0[i] >> (8 * rot)) | ((blk0[i] & ((1 << (8 * rot)) - 1)) << (64 - 8 * rot))) & 0xFFFFFFFFFFFFFFFF))
        if m == 256:
            print(f"   T{k} = rol64(T0, {rot})")
            break
    else:
        print(f"   T{k}: no simple 64-bit rotation of T0, T0[0]={blk0[0]:016x} T{k}[0]={blk[0]:016x}")

print("\n== ASCII runs >= 6 near the end of the payload (0x58f1000..0x58f1800) ==")
import re
so, eo = rva2off(0x58F1000), rva2off(0x58F1800)
for m in re.finditer(rb"[\x20-\x7e]{6,}", D[so:eo]):
    p = so + m.start()
    print(f"   rva 0x{p + 0x1000:08x} {m.group()[:60]!r}")

print("\n== what precedes the first manifest entry (0x58f1680..0x58f16e0) ==")
o = rva2off(0x58F1680)
for i in range(0, 0x60, 16):
    c = D[o + i:o + i + 16]
    print("  %08x  %s  %s" % (0x58F1680 + i, " ".join(f"{b:02x}" for b in c),
                              "".join(chr(b) if 32 <= b < 127 else "." for b in c)))
