#!/usr/bin/env python3
"""Brute-test candidate cipher constructions against observed wire blocks.

Ground truths (from server-20260926.log, conn=2):
  ai=8  XTEA-LE  packets end in constant block  a7c02233e5721520
  ai=10 XOR-32   packets end in constant block  06831f52 / 03821e52
  ai=13 Custom-8B packets repeat               046ca0b1a4dddbda
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

BLOB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto\channelinfo_key_blob.bin")
KEYS = {  # algo id -> (file offset, length)
    0: (0, 16), 1: (16, 16), 2: (32, 60), 3: (92, 32), 4: (124, 16),
    5: (140, 10), 6: (150, 16), 7: (166, 56), 8: (222, 16), 9: (238, 16),
    10: (254, 8), 11: (262, 16), 12: (278, 16), 13: (294, 40),
}
D = BLOB.read_bytes()


def key_of(ai: int) -> bytes:
    off, ln = KEYS[ai]
    return D[off:off + ln]


def xtea_encrypt(block8: bytes, key16: bytes, cycles=32, endian="<", delta=0x9E3779B9,
                 key_endian=None):
    ke = endian if key_endian is None else key_endian
    v0, v1 = struct.unpack(endian + "2I", block8)
    k = struct.unpack(ke + "4I", key16)
    s = 0
    for _ in range(cycles):
        v0 = (v0 + ((((v1 << 4) & 0xFFFFFFFF) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3])) & 0xFFFFFFFF
        s = (s + delta) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) & 0xFFFFFFFF) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3])) & 0xFFFFFFFF
    return struct.pack(endian + "2I", v0, v1)


def xtea_old(block8, key16, cycles=32, endian="<", delta=0x9E3779B9, key_endian=None):
    """Original XTEA (Tea2) variant used by some libs."""
    ke = endian if key_endian is None else key_endian
    v0, v1 = struct.unpack(endian + "2I", block8)
    k = struct.unpack(ke + "4I", key16)
    s = 0
    for _ in range(cycles):
        v0 = (v0 + (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3])) & 0xFFFFFFFF
        s = (s + delta) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3])) & 0xFFFFFFFF
    return struct.pack(endian + "2I", v0, v1)


def xor_variants(block: bytes, key: bytes, pos: int, bs: int):
    """Many plausible 'XOR-32' shapes."""
    out = {}
    kb = len(key)
    ks = key
    st = (pos * bs) % kb
    kk = (ks + ks)[st:st + bs]
    out["xor_key_cycle"] = bytes(a ^ b for a, b in zip(block, kk))
    ks2 = key[0:bs]
    out["xor_first_bs"] = bytes(a ^ b for a, b in zip(block, ks2))
    # 32-bit add of key word
    w = struct.unpack("<I", block)[0]
    for i in range(0, kb - 3, 4):
        kw = struct.unpack("<I", key[i:i + 4])[0]
        out[f"add_kw{i}"] = struct.pack("<I", (w + kw) & 0xFFFFFFFF)
        out[f"sub_kw{i}"] = struct.pack("<I", (w - kw) & 0xFFFFFFFF)
        out[f"xor_kw{i}"] = struct.pack("<I", w ^ kw)
        # xorshift-ish
        out[f"rotr_kw{i}"] = struct.pack("<I", ((kw ^ w) >> 1) | (((kw ^ w) << 31) & 0xFFFFFFFF))
    return out


def main():
    gt = {
        8: bytes.fromhex("a7c02233e5721520"),
        0: bytes.fromhex("42d6b8d8e9e84eda"),
        10: bytes.fromhex("06831f52"),
    }
    print("== XTEA candidates: E(0) vs observed constant block ==")
    tgt = gt[8]
    k8 = key_of(8)
    k0 = key_of(0)
    print(f"key ai=8  {k8.hex()}\nkey ai=0  {k0.hex()}")
    hits = []
    for ai, k in ((8, k8), (0, k0)):
        for name, fn in (("xtea", xtea_encrypt), ("xtea_old", xtea_old)):
            for cyc in (32, 64):
                for endian in ("<", ">"):
                    for ke in ("<", ">"):
                        for d in (0x9E3779B9, 0x61C88647):
                            for pt in (b"\0" * 8, b"\xd6" * 8):
                                c = fn(pt, k, cyc, endian, d, ke)
                                mark = "  <== MATCH" if c == tgt else ""
                                if mark or (pt == b"\0" * 8 and c.hex() == gt[ai].hex()):
                                    print(f"  ai={ai} {name} cyc={cyc} e={endian} ke={ke} d={d:#x} "
                                          f"E({pt.hex()[:4]}..)={c.hex()}{mark}")
                                if mark:
                                    hits.append((ai, name, cyc, endian, ke, d, pt))
    if not hits:
        print("  (no direct match for a7c02233e5721520)")

    print("\n== XOR-32 candidates: E(0) ==")
    kx = key_of(10)
    print(f"key ai=10 {kx.hex()}  ({len(kx)}B)")
    for pt_name, pt in (("00", b"\0" * 4), ("d6", b"\xd6" * 4)):
        for pos in range(0, 3):
            for n, c in xor_variants(pt, kx, pos, 4).items():
                tag = ""
                if c.hex() in ("06831f52", "03821e52", "07821e52", "07831f52"):
                    tag = "  <== MATCH-ISH"
                print(f"  {pt_name} pos={pos} {n:<14} {c.hex()}{tag}")


if __name__ == "__main__":
    main()
