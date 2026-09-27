#!/usr/bin/env python3
"""Solve the S->C header word [7:11] as a *seeded* xxh32 / murmur3 / CRC.

Frame 6515 has a zero-length body and [7:11] = 0x18000000 -- three zero bytes,
which no unseeded hash of "" produces (xxh32 -> 02cc5d05, murmur3 -> 00000000,
crc32 -> 00000000, fnv1a -> 811c9dc5, md5 -> d41d8cd9, sha1 -> da39a3ee).  The
finalisers of xxh32 and murmur3 are both invertible, so the seed that turns ""
into 0x18000000 is computable in closed form; likewise the CRC init, since the
CRC of a fixed input is an affine function of the init.  A seed recovered from
one sample always "fits" it; it only means something if it then reproduces the
other 56 frames.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_s2c_hdr import murmur3, s2c_frames, xxh32, u32be  # noqa: E402

M = 0xFFFFFFFF
TARGET = 0x18000000


def inv_shift_xor(y: int, s: int) -> int:
    """Invert `y = x ^ (x >> s)` for a 32-bit x."""
    x = 0
    acc = y
    while acc:
        x ^= acc
        acc >>= s
    return x & M


def inv_xxh32_avalanche(y: int) -> int:
    x = inv_shift_xor(y, 16)
    x = (x * pow(0xC2B2AE3D, -1, 1 << 32)) & M
    x = inv_shift_xor(x, 13)
    x = (x * pow(0x85EBCA77, -1, 1 << 32)) & M
    return inv_shift_xor(x, 15)


def inv_murmur3_fmix(y: int) -> int:
    x = inv_shift_xor(y, 16)
    x = (x * pow(0xC2B2AE35, -1, 1 << 32)) & M
    x = inv_shift_xor(x, 13)
    x = (x * pow(0x85EBCA6B, -1, 1 << 32)) & M
    return inv_shift_xor(x, 16)


def crc32_of(d: bytes, init: int, poly: int = 0xEDB88320, xorout: int = M) -> int:
    crc = init
    for b in d:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (poly if crc & 1 else 0)
    return (crc ^ xorout) & M


def main() -> int:
    rows = [r for r in s2c_frames() if not r[7]]
    empty = [r for r in rows if not r[5]]
    print(f"{len(rows)} clean frames, {len(empty)} with an empty body")
    assert empty, "the empty-body frame is what makes the seeds solvable"
    for r in empty:
        print(f"  line {r[0]}  opcode {r[3]}  header {r[4].hex()}")

    # xxh32("") = avalanche(seed + P5)
    seed_xxh = (inv_xxh32_avalanche(TARGET) - 0x165667B1) & M
    seed_mur = inv_murmur3_fmix(TARGET)
    print(f"\nxxh32   seed that maps \"\" -> {TARGET:08x}: {seed_xxh:08x}")
    print(f"murmur3 seed that maps \"\" -> {TARGET:08x}: {seed_mur:08x}")
    print(f"  sanity: xxh32(\"\", {seed_xxh:08x}) = {xxh32(b'', seed_xxh):08x}"
          f"  murmur3(\"\", {seed_mur:08x}) = {murmur3(b'', seed_mur):08x}")

    # CRC is affine in the init: crc(d, init) = crc(d, 0) ^ crc(0, init).
    # So the init solving crc("") == TARGET is TARGET ^ xorout (since crc("",i)=i).
    print(f"crc32 (init=xorout=c): empty body forces c ^ c = 0 != 0x18000000"
          f" -> no init/xorout pair can produce it")

    print("\n-- verified forward on all frames (ct / pt) --")
    for name, fn, seed in (("xxh32", xxh32, seed_xxh), ("murmur3", murmur3, seed_mur)):
        for what in ("ct", "pt"):
            hit = tot = 0
            for line, ts, conn, op, hd, body, pl, trunc in rows:
                d = body if what == "ct" else pl
                if d is None:
                    continue
                tot += 1
                hit += fn(d, seed) == u32be(hd[7:11])
            print(f"  {name}({what}, seed={seed:08x}): {hit}/{tot}")

    # also: two halves may be two different seeded hashes of the same input
    print("\n-- is [11:15] the same seeded function? --")
    for name, fn, seed in (("xxh32", xxh32, seed_xxh), ("murmur3", murmur3, seed_mur)):
        for what in ("ct", "pt"):
            hit = tot = 0
            for line, ts, conn, op, hd, body, pl, trunc in rows:
                d = body if what == "ct" else pl
                if d is None:
                    continue
                tot += 1
                hit += fn(d, seed) == u32be(hd[11:15])
            print(f"  {name}({what}): {hit}/{tot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
