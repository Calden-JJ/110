#!/usr/bin/env python3
"""Verify the S->C header recipe recovered from the exe's frame builder.

0x5814b0 builds a 16-byte-header frame as:
    buf[0]=main, *(u16*)(buf+1)=sub, *(u32*)(buf+3)=len
    v = tag(crc32(body))          # 0x580c50(0x580ee0(seed=0, body))
    *(u32*)(buf+7) = v            # little-endian store
    *(u32*)(buf+11) = v
    if (flag) *(u32*)(buf+12) = nonce24 & 0xffffff   # 0x581030 output
    buf[15] = bool

  tag(w) = (w & 0xffffff00) | ((b0^b1^b2^b3) ^ 0x18)      (0x580c50)

So a header read big-endian shows A = bswap(tag(crc32(body))) and B = the same
value with its top byte kept and the rest overwritten by the nonce.  Two CRC
tables exist (0xedb88320 and 0x4db89129), so both are scored, over ct and pt.
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

from probe_c2s_hdr import c2s_frames, plaintext  # noqa: E402
from probe_s2c_hdr import s2c_frames, u32be  # noqa: E402

M32 = 0xFFFFFFFF


def crc_table(poly: int) -> list[int]:
    t = []
    for i in range(0x100):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (poly if c & 1 else 0)
        t.append(c & M32)
    return t


def crc(d: bytes, table: list[int], seed: int = 0, xorout: int = M32) -> int:
    c = (~seed) & M32
    for b in d:
        c = (c >> 8) ^ table[(c ^ b) & 0xFF]
    return (c ^ xorout) & M32


def tag(w: int) -> int:
    f = (w ^ (w >> 8) ^ (w >> 16) ^ (w >> 24)) & 0xFF
    return (w & 0xFFFFFF00) | (f ^ 0x18)


TABLES = {"E(edb88320)": crc_table(0xEDB88320), "X(4db89129)": crc_table(0x4DB89129)}


def main() -> int:
    s2 = [r for r in s2c_frames() if not r[7]]
    c2 = [r for r in c2s_frames() if not r[7]]
    print(f"{len(s2)} S->C frames, {len(c2)} C->S frames")
    print("bswap check: struct.pack('>I', t)[::-1] == struct.pack('<I', t)\n")

    print("-- S->C: A = [7:11] read big-endian --")
    for tname, tab in TABLES.items():
        for src in ("ct", "pt"):
            for variant, vfn in (
                ("bswap(tag(crc))", lambda t: struct.unpack("<I", struct.pack(">I", t))[0]),
                ("bswap(crc)", lambda t: struct.unpack("<I", struct.pack(">I", t))[0]),
                ("tag(crc)", lambda t: t),
                ("crc", lambda t: t),
            ):
                hit = tot = 0
                for r in s2:
                    d = r[5] if src == "ct" else r[6]
                    if d is None:
                        continue
                    tot += 1
                    v = crc(d, tab) if "crc" in variant and "tag" not in variant else None
                    if variant == "bswap(tag(crc))":
                        v = vfn(tag(crc(d, tab)))
                    elif variant == "bswap(crc)":
                        v = vfn(crc(d, tab))
                    elif variant == "tag(crc)":
                        v = tag(crc(d, tab))
                    else:
                        v = crc(d, tab)
                    hit += v == u32be(r[4][7:11])
                if hit:
                    print(f"  {tname:<12} {src} {variant:<18} {hit}/{tot}")
    print("  (only non-zero printed)")

    print("\n-- S->C: byte 11 vs byte 7, and B[12:15] vs A --")
    b11 = sum(r[4][11] == r[4][7] for r in s2)
    same = sum(r[4][7:11] == r[4][11:15] for r in s2)
    print(f"  hd[11]==hd[7]: {b11}/{len(s2)}   full [7:11]==[11:15]: {same}/{len(s2)}")

    # if the nonce variant fired, B = tagbyte<<24 | bswap24(nonce)
    print("\n-- S->C: reconstruct A from the recipe, per frame --")
    tab = TABLES["E(edb88320)"]
    shown = 0
    for r in s2:
        for src, d in (("ct", r[5]), ("pt", r[6])):
            if d is None:
                continue
            v = struct.unpack("<I", struct.pack(">I", tag(crc(d, tab))))[0]
            ok = v == u32be(r[4][7:11])
            if not ok and shown < 6:
                print(f"  MISS line {r[0]} op={r[3]} {src}: got {v:#010x} "
                      f"want {u32be(r[4][7:11]):#010x}  (len {len(d)})")
                shown += 1
            elif ok and src == "ct":
                break
    if not shown:
        print("  every frame matches on ct")

    print("\n-- C->S: same recipe? --")
    for tname, t in TABLES.items():
        for src in ("ct", "pt"):
            hit = tot = 0
            for r in c2:
                d = r[5] if src == "ct" else plaintext(r[3], r[5])
                if d is None:
                    continue
                tot += 1
                v = struct.unpack("<I", struct.pack(">I", tag(crc(d, t))))[0]
                hit += v == u32be(r[4][7:11])
            print(f"  {tname:<12} {src} bswap(tag(crc)) == [7:11]: {hit}/{tot}")

    print("\n-- C->S: does the low byte of the word relate to the rest? --")
    print("   word = u32be(hd[7:11]); looking for any fixed fold/xor --")
    for name, fn in (
        ("xor4^0x18 == low", lambda w: ((w ^ (w >> 8) ^ (w >> 16) ^ (w >> 24)) ^ 0x18) & 0xFF == (w & 0xFF)),
        ("xor4^0x18 == top", lambda w: ((w ^ (w >> 8) ^ (w >> 16) ^ (w >> 24)) ^ 0x18) & 0xFF == (w >> 24)),
    ):
        n = sum(fn(u32be(r[4][7:11])) for r in c2)
        print(f"  {name:<20} {n}/{len(c2)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
