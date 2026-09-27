#!/usr/bin/env python3
"""Python model of algo13 (DFO custom 8B, 40B key), checked against the
native transforms 0x5858c0 (enc) / 0x585aa0 (dec) via a patched-validator
probe and the log's gold pair.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run_native import BASE, SPAN  # noqa
from probe_util import call3, patch_validator_calls  # noqa

ENC = 0x5858C0
DEC = 0x585AA0
VALIDATORS = (0x585907, 0x585AE7)
M = 0xFFFFFFFF


def rotl(x, n):
    x &= M
    return ((x << n) | (x >> (32 - n))) & M


def F(x, k1, k2):
    c = (k1 + x) & M
    c = (c + rotl(c, 2) + 1) & M
    v = rotl(c, 8) ^ c
    z = (v + k2) & M
    w = (rotl(z, 1) - z) & M
    return ((w | x) ^ rotl(w, 16)) & M


def key_sched(key40: bytes):
    K = [int.from_bytes(key40[4 * i:4 * i + 4], "big") for i in range(8)]
    w8 = int.from_bytes(key40[32:36], "big")
    w9 = int.from_bytes(key40[36:40], "big")
    x = w8 ^ w9
    s = [0] * 8
    c = (x + K[0]) & M
    t = (c + rotl(c, 1) - 1) & M
    s[0] = w8 ^ t ^ rotl(t, 4)
    s[1] = F(s[0], K[1], K[2]) ^ x
    c = (s[1] + K[3]) & M
    s[2] = s[0] ^ ((c + rotl(c, 2) + 1) & M)
    s[3] = s[1] ^ s[2]
    c = (s[3] + K[4]) & M
    t = (c + rotl(c, 1) - 1) & M
    s[4] = s[2] ^ t ^ rotl(t, 4)
    s[5] = s[3] ^ F(s[4], K[5], K[6])
    c = (s[5] + K[7]) & M
    s[6] = s[4] ^ ((c + rotl(c, 2) + 1) & M)
    s[7] = s[5] ^ s[6]
    return s


def enc_block(block8: bytes, s: list) -> bytes:
    a = int.from_bytes(block8[0:4], "big")
    b = int.from_bytes(block8[4:8], "big") ^ a
    i = 0
    n = 1
    while n < 128:
        t = (b + s[i]) & M
        u = (t + rotl(t, 1) - 1) & M
        a ^= u
        a ^= rotl(u, 4)
        n += 1
        if n == 128:
            break
        b ^= F(a, s[i + 1], s[i + 2])
        n += 1
        if n == 128:
            break
        t = (b + s[i + 3]) & M
        a ^= (t + rotl(t, 2) + 1) & M
        n += 1
        if n == 128:
            break
        i ^= 4
        b ^= a
        n += 1
    return a.to_bytes(4, "big") + b.to_bytes(4, "big")


def dec_block(block8: bytes, s: list) -> bytes:
    a = int.from_bytes(block8[0:4], "big")
    b = int.from_bytes(block8[4:8], "big")
    # undo the final pass (i = 4, C/B/A only)
    t = (b + s[7]) & M
    a ^= (t + rotl(t, 2) + 1) & M
    b ^= F(a, s[5], s[6])
    t = (b + s[4]) & M
    u = (t + rotl(t, 1) - 1) & M
    a ^= u
    a ^= rotl(u, 4)
    for p in range(30, -1, -1):
        i = 0 if p % 2 == 0 else 4
        b ^= a
        t = (b + s[i + 3]) & M
        a ^= (t + rotl(t, 2) + 1) & M
        b ^= F(a, s[i + 1], s[i + 2])
        t = (b + s[i]) & M
        u = (t + rotl(t, 1) - 1) & M
        a ^= u
        a ^= rotl(u, 4)
    return a.to_bytes(4, "big") + (a ^ b).to_bytes(4, "big")


def make_this(s: list):
    ks = (ctypes.c_uint8 * (0x10 + 4 * len(s)))()
    struct.pack_into("<I", ks, 8, len(s))
    for i, v in enumerate(s):
        struct.pack_into("<I", ks, 0x10 + 4 * i, v)
    this = (ctypes.c_uint8 * 0x20)()
    struct.pack_into("<Q", this, 8, ctypes.addressof(ks))
    return this, ks


def main():
    patch_validator_calls(VALIDATORS)
    blob = (Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto"
                 r"\channelinfo_key_blob.bin")).read_bytes()
    key = blob[294:334]
    s = key_sched(key)
    print("sched:", " ".join(f"{v:08x}" for v in s))
    this, ks = make_this(s)
    enc = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(SPAN),
                           ctypes.POINTER(SPAN))(BASE + ENC)
    dec = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(SPAN),
                           ctypes.POINTER(SPAN))(BASE + DEC)
    import random
    random.seed(11)
    ok = True
    for t in range(6):
        blk = bytes(random.randrange(256) for _ in range(8))
        ne = call3(enc, this, blk)
        nd = call3(dec, this, blk)
        pe = enc_block(blk, s)
        pd = dec_block(blk, s)
        same = (ne == pe) and (nd == pd)
        ok &= same
        print(f"  {blk.hex()} native E={ne.hex()} mine={pe.hex()} "
              f"{'OK' if ne == pe else 'DIFF'} | D {'OK' if nd == pd else 'DIFF'}")
    print("random vs native:", "ALL OK" if ok else "FAIL")
    print("roundtrip:", dec_block(enc_block(bytes(range(8)), s), s) ==
          bytes(range(8)))
    ct = bytes.fromhex("7c5d436d3a01ca341f64fc77bfcd8e6d6a01c3c0f4eafd6d")
    pt = bytes.fromhex("020002357247204ec347070006b96773475df0c247070000")
    got_d = b"".join(dec_block(ct[i:i + 8], s) for i in range(0, 24, 8))
    got_e = b"".join(enc_block(pt[i:i + 8], s) for i in range(0, 24, 8))
    print("gold dec(ct) == pt:", got_d == pt)
    print("gold enc(pt) == ct:", got_e == ct)
    print("  dec:", got_d.hex())
    print("  enc:", got_e.hex())


if __name__ == "__main__":
    main()
