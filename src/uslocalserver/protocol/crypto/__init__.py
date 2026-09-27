#!/usr/bin/env python3
"""DFO cipher suite: CAST-128, Skipjack, Blowfish, RC6, Twofish, MISTY1,
XTEA (both endiannesses) and Xor32 -- the 14 tiles `AlgoId = sub % 14` selects.

Ports of the BouncyCastle engines (`tools/ref/*.cs`) and RFC 2994, using the
static tables the server ships in `data/crypto/*.bin`.  Every cipher is used
in ECB over whole blocks; a trailing partial block passes through unchanged
(the server's shared validator 0x5843b0 only accepts whole blocks).

Where a "*-DFO" variant deviates from the stock algorithm, the deviation is
marked and (once pinned by disassembly of the transform) implemented here.

This was `tools/dfo_ciphers.py`.  `paths.py` owns both directories it reads,
because a `__file__`-relative root breaks the moment the file moves; the
shim of the same name keeps the old probes importing it unchanged.
"""
from __future__ import annotations

import re
import struct

from ... import paths

M32 = 0xFFFFFFFF
TAB = paths.CRYPTO_TABLES
#: 334 bytes of 14 concatenated key entries in AlgoId order -- see `tiles.py`.
KEY_BLOB = TAB / "channelinfo_key_blob.bin"
REF = paths.TOOLS_DIR / "ref"


def _u32s(name: str) -> tuple:
    b = (TAB / name).read_bytes()
    return struct.unpack(f"<{len(b) // 4}I", b)


def _u16s(name: str) -> tuple:
    b = (TAB / name).read_bytes()
    return struct.unpack(f"<{len(b) // 2}H", b)


def _u64s(name: str) -> tuple:
    b = (TAB / name).read_bytes()
    return struct.unpack(f"<{len(b) // 8}Q", b)


def _rotl(x: int, n: int) -> int:
    n &= 31
    x &= M32
    return ((x << n) | (x >> (32 - n))) & M32 if n else x


def _rotr(x: int, n: int) -> int:
    n &= 31
    x &= M32
    return ((x >> n) | (x << (32 - n))) & M32 if n else x


def _rol16(x: int, n: int) -> int:
    n &= 15
    x &= 0xFFFF
    return ((x << n) | (x >> (16 - n))) & 0xFFFF if n else x


def ecb_encrypt(fn, data: bytes, key: bytes, bs: int) -> bytes:
    n = len(data) - len(data) % bs
    return b"".join(fn(data[i:i + bs], key) for i in range(0, n, bs)) + data[n:]


def ecb_decrypt(fn, data: bytes, key: bytes, bs: int) -> bytes:
    return ecb_encrypt(fn, data, key, bs)


# ---------------------------------------------------------------------------
# CAST-128 (RFC 2144) -- BC Cast5Engine, tables from cast_s.bin (S1..S8)
# ---------------------------------------------------------------------------
_CS = _u32s("cast_s.bin")
S1, S2, S3, S4 = _CS[0:256], _CS[256:512], _CS[512:768], _CS[768:1024]
S5, S6, S7, S8 = _CS[1024:1280], _CS[1280:1536], _CS[1536:1792], _CS[1792:2048]


def _cast_set_key(key: bytes):
    x = [0] * 16
    z = [0] * 16
    for i in range(min(len(key), 16)):
        x[i] = key[i]
    km = [0] * 17
    kr = [0] * 17

    def i32(b, i):
        return ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) & M32

    def put32(v, b, i):
        b[i + 3] = v & 0xFF
        b[i + 2] = (v >> 8) & 0xFF
        b[i + 1] = (v >> 16) & 0xFF
        b[i] = (v >> 24) & 0xFF

    x03, x47, x8B, xCF = i32(x, 0), i32(x, 4), i32(x, 8), i32(x, 12)
    z03 = x03 ^ S5[x[0xD]] ^ S6[x[0xF]] ^ S7[x[0xC]] ^ S8[x[0xE]] ^ S7[x[0x8]]
    put32(z03, z, 0)
    z47 = x8B ^ S5[z[0x0]] ^ S6[z[0x2]] ^ S7[z[0x1]] ^ S8[z[0x3]] ^ S8[x[0xA]]
    put32(z47, z, 4)
    z8B = xCF ^ S5[z[0x7]] ^ S6[z[0x6]] ^ S7[z[0x5]] ^ S8[z[0x4]] ^ S5[x[0x9]]
    put32(z8B, z, 8)
    zCF = x47 ^ S5[z[0xA]] ^ S6[z[0x9]] ^ S7[z[0xB]] ^ S8[z[0x8]] ^ S6[x[0xB]]
    put32(zCF, z, 12)
    km[1] = S5[z[0x8]] ^ S6[z[0x9]] ^ S7[z[0x7]] ^ S8[z[0x6]] ^ S5[z[0x2]]
    km[2] = S5[z[0xA]] ^ S6[z[0xB]] ^ S7[z[0x5]] ^ S8[z[0x4]] ^ S6[z[0x6]]
    km[3] = S5[z[0xC]] ^ S6[z[0xD]] ^ S7[z[0x3]] ^ S8[z[0x2]] ^ S7[z[0x9]]
    km[4] = S5[z[0xE]] ^ S6[z[0xF]] ^ S7[z[0x1]] ^ S8[z[0x0]] ^ S8[z[0xC]]

    z03, z47, z8B, zCF = i32(z, 0), i32(z, 4), i32(z, 8), i32(z, 12)
    x03 = z8B ^ S5[z[0x5]] ^ S6[z[0x7]] ^ S7[z[0x4]] ^ S8[z[0x6]] ^ S7[z[0x0]]
    put32(x03, x, 0)
    x47 = z03 ^ S5[x[0x0]] ^ S6[x[0x2]] ^ S7[x[0x1]] ^ S8[x[0x3]] ^ S8[z[0x2]]
    put32(x47, x, 4)
    x8B = z47 ^ S5[x[0x7]] ^ S6[x[0x6]] ^ S7[x[0x5]] ^ S8[x[0x4]] ^ S5[z[0x1]]
    put32(x8B, x, 8)
    xCF = zCF ^ S5[x[0xA]] ^ S6[x[0x9]] ^ S7[x[0xB]] ^ S8[x[0x8]] ^ S6[z[0x3]]
    put32(xCF, x, 12)
    km[5] = S5[x[0x3]] ^ S6[x[0x2]] ^ S7[x[0xC]] ^ S8[x[0xD]] ^ S5[x[0x8]]
    km[6] = S5[x[0x1]] ^ S6[x[0x0]] ^ S7[x[0xE]] ^ S8[x[0xF]] ^ S6[x[0xD]]
    km[7] = S5[x[0x7]] ^ S6[x[0x6]] ^ S7[x[0x8]] ^ S8[x[0x9]] ^ S7[x[0x3]]
    km[8] = S5[x[0x5]] ^ S6[x[0x4]] ^ S7[x[0xA]] ^ S8[x[0xB]] ^ S8[x[0x7]]

    x03, x47, x8B, xCF = i32(x, 0), i32(x, 4), i32(x, 8), i32(x, 12)
    z03 = x03 ^ S5[x[0xD]] ^ S6[x[0xF]] ^ S7[x[0xC]] ^ S8[x[0xE]] ^ S7[x[0x8]]
    put32(z03, z, 0)
    z47 = x8B ^ S5[z[0x0]] ^ S6[z[0x2]] ^ S7[z[0x1]] ^ S8[z[0x3]] ^ S8[x[0xA]]
    put32(z47, z, 4)
    z8B = xCF ^ S5[z[0x7]] ^ S6[z[0x6]] ^ S7[z[0x5]] ^ S8[z[0x4]] ^ S5[x[0x9]]
    put32(z8B, z, 8)
    zCF = x47 ^ S5[z[0xA]] ^ S6[z[0x9]] ^ S7[z[0xB]] ^ S8[z[0x8]] ^ S6[x[0xB]]
    put32(zCF, z, 12)
    km[9] = S5[z[0x3]] ^ S6[z[0x2]] ^ S7[z[0xC]] ^ S8[z[0xD]] ^ S5[z[0x9]]
    km[10] = S5[z[0x1]] ^ S6[z[0x0]] ^ S7[z[0xE]] ^ S8[z[0xF]] ^ S6[z[0xC]]
    km[11] = S5[z[0x7]] ^ S6[z[0x6]] ^ S7[z[0x8]] ^ S8[z[0x9]] ^ S7[z[0x2]]
    km[12] = S5[z[0x5]] ^ S6[z[0x4]] ^ S7[z[0xA]] ^ S8[z[0xB]] ^ S8[z[0x6]]

    z03, z47, z8B, zCF = i32(z, 0), i32(z, 4), i32(z, 8), i32(z, 12)
    x03 = z8B ^ S5[z[0x5]] ^ S6[z[0x7]] ^ S7[z[0x4]] ^ S8[z[0x6]] ^ S7[z[0x0]]
    put32(x03, x, 0)
    x47 = z03 ^ S5[x[0x0]] ^ S6[x[0x2]] ^ S7[x[0x1]] ^ S8[x[0x3]] ^ S8[z[0x2]]
    put32(x47, x, 4)
    x8B = z47 ^ S5[x[0x7]] ^ S6[x[0x6]] ^ S7[x[0x5]] ^ S8[x[0x4]] ^ S5[z[0x1]]
    put32(x8B, x, 8)
    xCF = zCF ^ S5[x[0xA]] ^ S6[x[0x9]] ^ S7[x[0xB]] ^ S8[x[0x8]] ^ S6[z[0x3]]
    put32(xCF, x, 12)
    km[13] = S5[x[0x8]] ^ S6[x[0x9]] ^ S7[x[0x7]] ^ S8[x[0x6]] ^ S5[x[0x3]]
    km[14] = S5[x[0xA]] ^ S6[x[0xB]] ^ S7[x[0x5]] ^ S8[x[0x4]] ^ S6[x[0x7]]
    km[15] = S5[x[0xC]] ^ S6[x[0xD]] ^ S7[x[0x3]] ^ S8[x[0x2]] ^ S7[x[0x8]]
    km[16] = S5[x[0xE]] ^ S6[x[0xF]] ^ S7[x[0x1]] ^ S8[x[0x0]] ^ S8[x[0xD]]

    x03, x47, x8B, xCF = i32(x, 0), i32(x, 4), i32(x, 8), i32(x, 12)
    z03 = x03 ^ S5[x[0xD]] ^ S6[x[0xF]] ^ S7[x[0xC]] ^ S8[x[0xE]] ^ S7[x[0x8]]
    put32(z03, z, 0)
    z47 = x8B ^ S5[z[0x0]] ^ S6[z[0x2]] ^ S7[z[0x1]] ^ S8[z[0x3]] ^ S8[x[0xA]]
    put32(z47, z, 4)
    z8B = xCF ^ S5[z[0x7]] ^ S6[z[0x6]] ^ S7[z[0x5]] ^ S8[z[0x4]] ^ S5[x[0x9]]
    put32(z8B, z, 8)
    zCF = x47 ^ S5[z[0xA]] ^ S6[z[0x9]] ^ S7[z[0xB]] ^ S8[z[0x8]] ^ S6[x[0xB]]
    put32(zCF, z, 12)
    kr[1] = (S5[z[0x8]] ^ S6[z[0x9]] ^ S7[z[0x7]] ^ S8[z[0x6]] ^ S5[z[0x2]]) & 0x1F
    kr[2] = (S5[z[0xA]] ^ S6[z[0xB]] ^ S7[z[0x5]] ^ S8[z[0x4]] ^ S6[z[0x6]]) & 0x1F
    kr[3] = (S5[z[0xC]] ^ S6[z[0xD]] ^ S7[z[0x3]] ^ S8[z[0x2]] ^ S7[z[0x9]]) & 0x1F
    kr[4] = (S5[z[0xE]] ^ S6[z[0xF]] ^ S7[z[0x1]] ^ S8[z[0x0]] ^ S8[z[0xC]]) & 0x1F

    z03, z47, z8B, zCF = i32(z, 0), i32(z, 4), i32(z, 8), i32(z, 12)
    x03 = z8B ^ S5[z[0x5]] ^ S6[z[0x7]] ^ S7[z[0x4]] ^ S8[z[0x6]] ^ S7[z[0x0]]
    put32(x03, x, 0)
    x47 = z03 ^ S5[x[0x0]] ^ S6[x[0x2]] ^ S7[x[0x1]] ^ S8[x[0x3]] ^ S8[z[0x2]]
    put32(x47, x, 4)
    x8B = z47 ^ S5[x[0x7]] ^ S6[x[0x6]] ^ S7[x[0x5]] ^ S8[x[0x4]] ^ S5[z[0x1]]
    put32(x8B, x, 8)
    xCF = zCF ^ S5[x[0xA]] ^ S6[x[0x9]] ^ S7[x[0xB]] ^ S8[x[0x8]] ^ S6[z[0x3]]
    put32(xCF, x, 12)
    kr[5] = (S5[x[0x3]] ^ S6[x[0x2]] ^ S7[x[0xC]] ^ S8[x[0xD]] ^ S5[x[0x8]]) & 0x1F
    kr[6] = (S5[x[0x1]] ^ S6[x[0x0]] ^ S7[x[0xE]] ^ S8[x[0xF]] ^ S6[x[0xD]]) & 0x1F
    kr[7] = (S5[x[0x7]] ^ S6[x[0x6]] ^ S7[x[0x8]] ^ S8[x[0x9]] ^ S7[x[0x3]]) & 0x1F
    kr[8] = (S5[x[0x5]] ^ S6[x[0x4]] ^ S7[x[0xA]] ^ S8[x[0xB]] ^ S8[x[0x7]]) & 0x1F

    x03, x47, x8B, xCF = i32(x, 0), i32(x, 4), i32(x, 8), i32(x, 12)
    z03 = x03 ^ S5[x[0xD]] ^ S6[x[0xF]] ^ S7[x[0xC]] ^ S8[x[0xE]] ^ S7[x[0x8]]
    put32(z03, z, 0)
    z47 = x8B ^ S5[z[0x0]] ^ S6[z[0x2]] ^ S7[z[0x1]] ^ S8[z[0x3]] ^ S8[x[0xA]]
    put32(z47, z, 4)
    z8B = xCF ^ S5[z[0x7]] ^ S6[z[0x6]] ^ S7[z[0x5]] ^ S8[z[0x4]] ^ S5[x[0x9]]
    put32(z8B, z, 8)
    zCF = x47 ^ S5[z[0xA]] ^ S6[z[0x9]] ^ S7[z[0xB]] ^ S8[z[0x8]] ^ S6[x[0xB]]
    put32(zCF, z, 12)
    kr[9] = (S5[z[0x3]] ^ S6[z[0x2]] ^ S7[z[0xC]] ^ S8[z[0xD]] ^ S5[z[0x9]]) & 0x1F
    kr[10] = (S5[z[0x1]] ^ S6[z[0x0]] ^ S7[z[0xE]] ^ S8[z[0xF]] ^ S6[z[0xC]]) & 0x1F
    kr[11] = (S5[z[0x7]] ^ S6[z[0x6]] ^ S7[z[0x8]] ^ S8[z[0x9]] ^ S7[z[0x2]]) & 0x1F
    kr[12] = (S5[z[0x5]] ^ S6[z[0x4]] ^ S7[z[0xA]] ^ S8[z[0xB]] ^ S8[z[0x6]]) & 0x1F

    z03, z47, z8B, zCF = i32(z, 0), i32(z, 4), i32(z, 8), i32(z, 12)
    x03 = z8B ^ S5[z[0x5]] ^ S6[z[0x7]] ^ S7[z[0x4]] ^ S8[z[0x6]] ^ S7[z[0x0]]
    put32(x03, x, 0)
    x47 = z03 ^ S5[x[0x0]] ^ S6[x[0x2]] ^ S7[x[0x1]] ^ S8[x[0x3]] ^ S8[z[0x2]]
    put32(x47, x, 4)
    x8B = z47 ^ S5[x[0x7]] ^ S6[x[0x6]] ^ S7[x[0x5]] ^ S8[x[0x4]] ^ S5[z[0x1]]
    put32(x8B, x, 8)
    xCF = zCF ^ S5[x[0xA]] ^ S6[x[0x9]] ^ S7[x[0xB]] ^ S8[x[0x8]] ^ S6[z[0x3]]
    put32(xCF, x, 12)
    kr[13] = (S5[x[0x8]] ^ S6[x[0x9]] ^ S7[x[0x7]] ^ S8[x[0x6]] ^ S5[x[0x3]]) & 0x1F
    kr[14] = (S5[x[0xA]] ^ S6[x[0xB]] ^ S7[x[0x5]] ^ S8[x[0x4]] ^ S6[x[0x7]]) & 0x1F
    kr[15] = (S5[x[0xC]] ^ S6[x[0xD]] ^ S7[x[0x3]] ^ S8[x[0x2]] ^ S7[x[0x8]]) & 0x1F
    kr[16] = (S5[x[0xE]] ^ S6[x[0xF]] ^ S7[x[0x1]] ^ S8[x[0x0]] ^ S8[x[0xD]]) & 0x1F
    return km, kr


def _cast_f1(d, km, kr):
    i = _rotl((km + d) & M32, kr)
    return (((S1[(i >> 24) & 0xFF] ^ S2[(i >> 16) & 0xFF]) - S3[(i >> 8) & 0xFF]) + S4[i & 0xFF]) & M32


def _cast_f2(d, km, kr):
    i = _rotl(km ^ d, kr)
    return (((S1[(i >> 24) & 0xFF] - S2[(i >> 16) & 0xFF]) + S3[(i >> 8) & 0xFF]) ^ S4[i & 0xFF]) & M32


def _cast_f3(d, km, kr):
    i = _rotl((km - d) & M32, kr)
    return (((S1[(i >> 24) & 0xFF] + S2[(i >> 16) & 0xFF]) ^ S3[(i >> 8) & 0xFF]) - S4[i & 0xFF]) & M32


_FTYPE = {1: _cast_f1, 2: _cast_f2, 3: _cast_f3,
          4: _cast_f1, 5: _cast_f2, 6: _cast_f3,
          7: _cast_f1, 8: _cast_f2, 9: _cast_f3,
          10: _cast_f1, 11: _cast_f2, 12: _cast_f3,
          13: _cast_f1, 14: _cast_f2, 15: _cast_f3, 16: _cast_f1}


def _cast_crypt(block8: bytes, key: bytes, decrypt: bool) -> bytes:
    km, kr = _cast_set_key(key)
    li, ri = struct.unpack(">II", block8)
    rng = range(16, 0, -1) if decrypt else range(1, 17)
    for i in rng:
        li, ri = ri, li ^ _FTYPE[i](ri, km[i], kr[i])
    return struct.pack(">II", ri, li)


def cast128_encrypt(block8, key):
    return _cast_crypt(block8, key, False)


def cast128_decrypt(block8, key):
    return _cast_crypt(block8, key, True)


# ---------------------------------------------------------------------------
# Skipjack -- BC SkipjackEngine, F table from skipjack_f.bin
# ---------------------------------------------------------------------------
_SJF = _u16s("skipjack_f.bin")


def _sj_g(k, w, key0, key1, key2, key3):
    g1 = (w >> 8) & 0xFF
    g2 = w & 0xFF
    g3 = _SJF[g2 ^ key0[k]] ^ g1
    g4 = _SJF[g3 ^ key1[k]] ^ g2
    g5 = _SJF[g4 ^ key2[k]] ^ g3
    g6 = _SJF[g5 ^ key3[k]] ^ g4
    return (g5 << 8) + g6


def _sj_h(k, w, key0, key1, key2, key3):
    h1 = w & 0xFF
    h2 = (w >> 8) & 0xFF
    h3 = _SJF[h2 ^ key3[k]] ^ h1
    h4 = _SJF[h3 ^ key2[k]] ^ h2
    h5 = _SJF[h4 ^ key1[k]] ^ h3
    h6 = _SJF[h5 ^ key0[k]] ^ h4
    return (h6 << 8) + h5


def _sj_keys(key: bytes):
    k0 = [key[(i * 4 + 0) % 10] for i in range(32)]
    k1 = [key[(i * 4 + 1) % 10] for i in range(32)]
    k2 = [key[(i * 4 + 2) % 10] for i in range(32)]
    k3 = [key[(i * 4 + 3) % 10] for i in range(32)]
    return k0, k1, k2, k3


def skipjack_encrypt(block8: bytes, key: bytes) -> bytes:
    k0, k1, k2, k3 = _sj_keys(key)
    w1 = (block8[0] << 8) + block8[1]
    w2 = (block8[2] << 8) + block8[3]
    w3 = (block8[4] << 8) + block8[5]
    w4 = (block8[6] << 8) + block8[7]
    k = 0
    for _ in range(2):
        for _ in range(8):
            tmp = w4
            w4 = w3
            w3 = w2
            w2 = _sj_g(k, w1, k0, k1, k2, k3)
            w1 = w2 ^ tmp ^ (k + 1)
            k += 1
        for _ in range(8):
            tmp = w4
            w4 = w3
            w3 = w1 ^ w2 ^ (k + 1)
            w2 = _sj_g(k, w1, k0, k1, k2, k3)
            w1 = tmp
            k += 1
    return bytes(((w1 >> 8) & 0xFF, w1 & 0xFF, (w2 >> 8) & 0xFF, w2 & 0xFF,
                  (w3 >> 8) & 0xFF, w3 & 0xFF, (w4 >> 8) & 0xFF, w4 & 0xFF))


def skipjack_decrypt(block8: bytes, key: bytes) -> bytes:
    k0, k1, k2, k3 = _sj_keys(key)
    w2 = (block8[0] << 8) + block8[1]
    w1 = (block8[2] << 8) + block8[3]
    w4 = (block8[4] << 8) + block8[5]
    w3 = (block8[6] << 8) + block8[7]
    k = 31
    for _ in range(2):
        for _ in range(8):
            tmp = w4
            w4 = w3
            w3 = w2
            w2 = _sj_h(k, w1, k0, k1, k2, k3)
            w1 = w2 ^ tmp ^ (k + 1)
            k -= 1
        for _ in range(8):
            tmp = w4
            w4 = w3
            w3 = w1 ^ w2 ^ (k + 1)
            w2 = _sj_h(k, w1, k0, k1, k2, k3)
            w1 = tmp
            k -= 1
    return bytes(((w2 >> 8) & 0xFF, w2 & 0xFF, (w1 >> 8) & 0xFF, w1 & 0xFF,
                  (w4 >> 8) & 0xFF, w4 & 0xFF, (w3 >> 8) & 0xFF, w3 & 0xFF))


# ---------------------------------------------------------------------------
# Blowfish (standard) -- P from blowfish_p.bin, S0..S3 from algo07_*sboxes.bin
# ---------------------------------------------------------------------------
_BFP = list(_u32s("blowfish_p.bin"))
_BFS = _u32s("algo07_blowfish_sboxes.bin")
_BF_ROUNDS = 16


def _bf_f(x, s0, s1, s2, s3):
    return (((s0[(x >> 24) & 0xFF] + s1[(x >> 16) & 0xFF]) & M32
             ^ s2[(x >> 8) & 0xFF]) + s3[x & 0xFF]) & M32


def _bf_process_table(xl, xr, table, p, s0, s1, s2, s3):
    for i in range(0, len(table), 2):
        xl ^= p[0]
        for r in range(1, _BF_ROUNDS, 2):
            xr ^= _bf_f(xl, s0, s1, s2, s3) ^ p[r]
            xl ^= _bf_f(xr, s0, s1, s2, s3) ^ p[r + 1]
        xr ^= p[_BF_ROUNDS + 1]
        table[i] = xr
        table[i + 1] = xl
        xr, xl = xl, table[i]


def _bf_set_key(key: bytes):
    p = list(_BFP)
    s = list(_BFS)
    s0, s1, s2, s3 = s[0:256], s[256:512], s[512:768], s[768:1024]
    ki = 0
    for i in range(len(p)):
        data = 0
        for _ in range(4):
            data = ((data << 8) | key[ki]) & M32
            ki += 1
            if ki >= len(key):
                ki = 0
        p[i] ^= data
    _bf_process_table(0, 0, p, p, s0, s1, s2, s3)
    _bf_process_table(p[-2], p[-1], s0, p, s0, s1, s2, s3)
    _bf_process_table(s0[-2], s0[-1], s1, p, s0, s1, s2, s3)
    _bf_process_table(s1[-2], s1[-1], s2, p, s0, s1, s2, s3)
    _bf_process_table(s2[-2], s2[-1], s3, p, s0, s1, s2, s3)
    return p, s0, s1, s2, s3


def _bf_crypt(block8: bytes, key: bytes, dec: bool) -> bytes:
    p, s0, s1, s2, s3 = _bf_set_key(key)
    xl, xr = struct.unpack(">II", block8)
    if dec:
        xl ^= p[_BF_ROUNDS + 1]
        for i in range(_BF_ROUNDS, 0, -2):
            xr ^= _bf_f(xl, s0, s1, s2, s3) ^ p[i]
            xl ^= _bf_f(xr, s0, s1, s2, s3) ^ p[i - 1]
        xr ^= p[0]
    else:
        xl ^= p[0]
        for i in range(1, _BF_ROUNDS, 2):
            xr ^= _bf_f(xl, s0, s1, s2, s3) ^ p[i]
            xl ^= _bf_f(xr, s0, s1, s2, s3) ^ p[i + 1]
        xr ^= p[_BF_ROUNDS + 1]
    return struct.pack(">II", xr, xl)


def blowfish_encrypt(block8, key):
    return _bf_crypt(block8, key, False)


def blowfish_decrypt(block8, key):
    return _bf_crypt(block8, key, True)


# ---------------------------------------------------------------------------
# Blowfish-DFO -- the server's variant (ctor 0x584730, key expand 0x584b40,
# block encrypt 0x584d60, F 0x584cd0).  F and the 16-round loop are stock; the
# deviations are all in the tables:
#   * the P refill loop stops after 10 of 18 words (P[10..17] keep pi ^ key)
#   * each S-box is refilled only at entries 0..127 (128..255 keep pi)
#   * final whitening runs xR ^= P[16]; xL ^= P[17] (stock: the other way)
# Accepts a 4..56 byte key, like stock.
# ---------------------------------------------------------------------------
def _bf_dfo_f(x, s):
    return (((s[x >> 24] + s[0x100 + ((x >> 16) & 0xFF)]) & M32
             ^ s[0x200 + ((x >> 8) & 0xFF)]) + s[0x300 + (x & 0xFF)]) & M32


def _bf_dfo_schedule(key: bytes):
    p = list(_BFP)
    s = list(_BFS)
    n = len(key)
    j = 0
    for i in range(18):
        w = 0
        for _ in range(4):
            w = ((w << 8) | key[j % n]) & M32
            j += 1
        p[i] ^= w

    def enc(xl, xr):
        for i in range(16):
            xl ^= p[i]
            xr ^= _bf_dfo_f(xl, s)
            xl, xr = xr, xl
        xl, xr = xr, xl
        xr ^= p[16]
        xl ^= p[17]
        return xl, xr

    xl = xr = 0
    for i in range(0, 10, 2):
        xl, xr = enc(xl, xr)
        p[i], p[i + 1] = xl, xr
    for b in range(4):
        base = b * 0x100
        for k in range(0, 0x80, 2):
            xl, xr = enc(xl, xr)
            s[base + k], s[base + k + 1] = xl, xr
    return p, s


def _bf_dfo_crypt(block8: bytes, key: bytes, dec: bool) -> bytes:
    p, s = _bf_dfo_schedule(key)
    xl, xr = struct.unpack(">II", block8)
    if not dec:
        for i in range(16):
            xl ^= p[i]
            xr ^= _bf_dfo_f(xl, s)
            xl, xr = xr, xl
        xl, xr = xr, xl
        xr ^= p[16]
        xl ^= p[17]
    else:
        xl ^= p[17]
        xr ^= p[16]
        xl, xr = xr, xl
        for i in range(15, -1, -1):
            xl, xr = xr, xl
            xr ^= _bf_dfo_f(xl, s)
            xl ^= p[i]
    return struct.pack(">II", xl, xr)


def blowfish_dfo_encrypt(block8, key):
    return _bf_dfo_crypt(block8, key, False)


def blowfish_dfo_decrypt(block8, key):
    return _bf_dfo_crypt(block8, key, True)


# ---------------------------------------------------------------------------
# RC6-32/20/16 -- BC RC6Engine (little-endian words, 20 rounds)
# ---------------------------------------------------------------------------
_RC6_P = 0xB7E15163
_RC6_Q = 0x9E3779B9
_RC6_ROUNDS = 20


def _rc6_set_key(key: bytes):
    L = [0] * ((len(key) + 3) // 4)
    for i in range(len(key) - 1, -1, -1):
        L[i // 4] = ((L[i // 4] << 8) + key[i]) & M32
    n = 2 + 2 * _RC6_ROUNDS + 2
    s = [_RC6_P]
    for i in range(1, n):
        s.append((s[i - 1] + _RC6_Q) & M32)
    a = b = 0
    ii = jj = 0
    for _ in range(3 * max(len(L), len(s))):
        a = s[ii] = _rotl((s[ii] + a + b) & M32, 3)
        b = L[jj] = _rotl((L[jj] + a + b) & M32, (a + b) & 31)
        ii = (ii + 1) % len(s)
        jj = (jj + 1) % len(L)
    return s


def _rc6_crypt(block16: bytes, key: bytes, dec: bool) -> bytes:
    s = _rc6_set_key(key)
    a, b, c, d = struct.unpack("<4I", block16)
    if dec:
        c = (c - s[2 * _RC6_ROUNDS + 3]) & M32
        a = (a - s[2 * _RC6_ROUNDS + 2]) & M32
        for i in range(_RC6_ROUNDS, 0, -1):
            d, c, b, a = c, b, a, d
            t = _rotl((b * (2 * b + 1)) & M32, 5)
            u = _rotl((d * (2 * d + 1)) & M32, 5)
            c = _rotr((c - s[2 * i + 1]) & M32, t)
            c ^= u
            a = _rotr((a - s[2 * i]) & M32, u)
            a ^= t
        d = (d - s[1]) & M32
        b = (b - s[0]) & M32
    else:
        b = (b + s[0]) & M32
        d = (d + s[1]) & M32
        for i in range(1, _RC6_ROUNDS + 1):
            t = _rotl((b * (2 * b + 1)) & M32, 5)
            u = _rotl((d * (2 * d + 1)) & M32, 5)
            a = _rotl(a ^ t, u)
            a = (a + s[2 * i]) & M32
            c = _rotl(c ^ u, t)
            c = (c + s[2 * i + 1]) & M32
            a, b, c, d = b, c, d, a
        a = (a + s[2 * _RC6_ROUNDS + 2]) & M32
        c = (c + s[2 * _RC6_ROUNDS + 3]) & M32
    return struct.pack("<4I", a, b, c, d)


def rc6_encrypt(block16, key):
    return _rc6_crypt(block16, key, False)


def rc6_decrypt(block16, key):
    return _rc6_crypt(block16, key, True)


# ---------------------------------------------------------------------------
# RC6-480-DFO -- the server's variant (ctor 0x586ec0, key schedule 0x5871e0,
# block encrypt 0x587340, decrypt 0x587520).
#
# Same round structure as stock RC6-32/20/16, but the 44-entry subkey table S
# holds *bytes* (added as 0..255), and the schedule mixes it with the key:
#   L[0] = 0, L[1..8] = key[0:32] as big-endian dwords (key[28:32] then unused)
#   S[0] = 0x63, S[i] = (S[i-1] - 0x47) & 0xFF
#   133 passes, B = (byte)rol32(S[j] + A + B, 3); A = rol32(A + B + L[i], A + B)
#   with i cycling 0..7 and j cycling 0..43 (so L[8] is never mixed in).
# Only the first 32 of the 60 key bytes reach the schedule.
# ---------------------------------------------------------------------------
_RC6D_ROUNDS = 20


def _rc6_dfo_schedule(key60: bytes) -> bytes:
    L = [0] * 9
    for i in range(31, -1, -1):
        L[i // 4 + 1] = ((L[i // 4 + 1] << 8) + key60[i]) & M32
    s = bytearray(44)
    s[0] = 0x63
    for i in range(1, 44):
        s[i] = (s[i - 1] - 0x47) & 0xFF
    a = b = 0
    i = j = 0
    for _ in range(132):
        b = (b + a) & M32
        b = _rotl((s[j] + b) & M32, 3) & 0xFF
        s[j] = b
        i = i % 8 + 1          # the counter masks to 0..7 *after* the ++, so L[1..8]
        a = _rotl((a + b + L[i]) & M32, (a + b) & 31)
        L[i] = a
        j = (j + 1) % 44
    return bytes(s)


def _rc6_dfo_crypt(block16: bytes, key: bytes, decrypt: bool) -> bytes:
    s = _rc6_dfo_schedule(key)
    a, b, c, d = struct.unpack("<4I", block16)
    if not decrypt:
        b = (b + s[0]) & M32
        d = (d + s[1]) & M32
        for r in range(_RC6D_ROUNDS):
            k = 2 + 2 * r
            t = _rotl((b * (2 * b + 1)) & M32, 5)
            u = _rotl((d * (2 * d + 1)) & M32, 5)
            a_mod = (_rotl((a ^ t) & M32, u & 31) + s[k]) & M32
            u_new = (_rotl((u ^ c) & M32, t & 31) + s[k + 1]) & M32
            a, b, c, d = b, u_new, d, a_mod
        a = (a + s[42]) & M32
        c = (c + s[43]) & M32
        return struct.pack("<4I", a, b, c, d)
    c = (c - s[43]) & M32
    a = (a - s[42]) & M32
    for r in range(_RC6D_ROUNDS - 1, -1, -1):
        k = 2 + 2 * r
        a_mod, u_new, b_old, d_old = d, b, a, c
        t = _rotl((b_old * (2 * b_old + 1)) & M32, 5)
        u = _rotl((d_old * (2 * d_old + 1)) & M32, 5)
        c_old = _rotr((u_new - s[k + 1]) & M32, t & 31) ^ u
        a = _rotr((a_mod - s[k]) & M32, u & 31) ^ t
        a, b, c, d = a, b_old, c_old, d_old
    b = (b - s[0]) & M32
    d = (d - s[1]) & M32
    return struct.pack("<4I", a, b, c, d)


def rc6_dfo_encrypt(block16, key):
    return _rc6_dfo_crypt(block16, key, False)


def rc6_dfo_decrypt(block16, key):
    return _rc6_dfo_crypt(block16, key, True)


# ---------------------------------------------------------------------------
# Twofish-256 -- BC TwofishEngine, q0/q1 from twofish_q.bin
# ---------------------------------------------------------------------------
_TFQ = (TAB / "twofish_q.bin").read_bytes()
_TFP = (_TFQ[0:256], _TFQ[256:512])
_TF_GF_FDBK = 0x169
_TF_RS_GF_FDBK = 0x14D
_TF_ROUNDS = 16
_TF_MAX_KEY_BITS = 256
_TF_INPUT_WHITEN = 0
_TF_OUTPUT_WHITEN = 4
_TF_ROUND_SUBKEYS = 8
_TF_TOTAL_SUBKEYS = 8 + 2 * _TF_ROUNDS
_TF_SK_STEP = 0x02020202
_TF_SK_BUMP = 0x01010101
_TF_SK_ROTL = 9
_P00, _P01, _P02, _P04 = 1, 0, 0, 1
_P10, _P11, _P12, _P14 = 0, 0, 1, 0
_P20, _P21, _P22, _P24 = 1, 1, 0, 0
_P30, _P31, _P32, _P34 = 0, 1, 1, 1
_P03 = _P01 ^ 1
_P13 = _P11 ^ 1
_P23 = _P21 ^ 1
_P33 = _P31 ^ 1


def _lfsr1(x):
    return (x >> 1) ^ ((_TF_GF_FDBK // 2) if (x & 1) else 0)


def _lfsr2(x):
    return (x >> 2) ^ ((_TF_GF_FDBK // 2) if (x & 2) else 0) ^ \
        ((_TF_GF_FDBK // 4) if (x & 1) else 0)


def _mx_x(x):
    return (x ^ _lfsr2(x)) & 0xFF


def _mx_y(x):
    return (x ^ _lfsr1(x) ^ _lfsr2(x)) & 0xFF


def _tf_build_mds():
    mds = [[0] * 256 for _ in range(4)]
    for i in range(_TF_MAX_KEY_BITS):
        j = _TFP[0][i]
        m1 = [j, _TFP[1][i]]
        mX = [_mx_x(j), _mx_x(_TFP[1][i])]
        mY = [_mx_y(j), _mx_y(_TFP[1][i])]
        mds[0][i] = (m1[_P00] | mX[_P00] << 8 | mY[_P00] << 16 | mY[_P00] << 24) & M32
        mds[1][i] = (mY[_P10] | mY[_P10] << 8 | mX[_P10] << 16 | m1[_P10] << 24) & M32
        mds[2][i] = (mX[_P20] | mY[_P20] << 8 | m1[_P20] << 16 | mY[_P20] << 24) & M32
        mds[3][i] = (mX[_P30] | m1[_P30] << 8 | mY[_P30] << 16 | mX[_P30] << 24) & M32
    return mds


_TFMDS = _tf_build_mds()


def _rs_rem(x):
    b = (x >> 24) & 0xFF
    g2 = ((b << 1) ^ (_TF_RS_GF_FDBK if (b & 0x80) else 0)) & 0xFF
    g3 = ((b >> 1) ^ ((_TF_RS_GF_FDBK >> 1) if (b & 1) else 0)) ^ g2
    return ((x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b) & M32


def _rs_mds_encode(k0, k1):
    r = k1
    for _ in range(4):
        r = _rs_rem(r)
    r ^= k0
    for _ in range(4):
        r = _rs_rem(r)
    return r


class Twofish:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key length not 128/192/256 bits.")
        self.k64 = len(key) // 8
        k32e = [0] * 4
        k32o = [0] * 4
        sboxkeys = [0] * 4
        for i in range(self.k64):
            p = i * 8
            k32e[i] = struct.unpack_from("<I", key, p)[0]
            k32o[i] = struct.unpack_from("<I", key, p + 4)[0]
            sboxkeys[self.k64 - 1 - i] = _rs_mds_encode(k32e[i], k32o[i])
        self.k32e, self.k32o, self.sboxkeys = k32e, k32o, sboxkeys
        sub = [0] * _TF_TOTAL_SUBKEYS
        for i in range(_TF_TOTAL_SUBKEYS // 2):
            q = i * _TF_SK_STEP
            a = self._f32(q, k32e)
            b = self._f32(q + _TF_SK_BUMP, k32o)
            b = _rotl(b, 8)
            a = (a + b) & M32
            sub[i * 2] = a
            a = (a + b) & M32
            sub[i * 2 + 1] = _rotl(a, _TF_SK_ROTL)
        self.sub = sub
        k0, k1, k2, k3 = sboxkeys
        sbox = [0] * (4 * _TF_MAX_KEY_BITS)
        for i in range(_TF_MAX_KEY_BITS):
            b0 = b1 = b2 = b3 = i
            mode = self.k64 & 3
            if mode == 0:
                b0 = (_TFP[_P04][b0] & 0xFF) ^ ((k3) & 0xFF)
                b1 = (_TFP[_P14][b1] & 0xFF) ^ ((k3 >> 8) & 0xFF)
                b2 = (_TFP[_P24][b2] & 0xFF) ^ ((k3 >> 16) & 0xFF)
                b3 = (_TFP[_P34][b3] & 0xFF) ^ ((k3 >> 24) & 0xFF)
            if mode in (0, 3):
                b0 = (_TFP[_P03][b0] & 0xFF) ^ ((k2) & 0xFF)
                b1 = (_TFP[_P13][b1] & 0xFF) ^ ((k2 >> 8) & 0xFF)
                b2 = (_TFP[_P23][b2] & 0xFF) ^ ((k2 >> 16) & 0xFF)
                b3 = (_TFP[_P33][b3] & 0xFF) ^ ((k2 >> 24) & 0xFF)
            if mode == 1:
                sbox[i * 2] = _TFMDS[0][(_TFP[_P01][b0] & 0xFF) ^ (k0 & 0xFF)]
                sbox[i * 2 + 1] = _TFMDS[1][(_TFP[_P11][b1] & 0xFF) ^ ((k0 >> 8) & 0xFF)]
                sbox[i * 2 + 0x200] = _TFMDS[2][(_TFP[_P21][b2] & 0xFF) ^ ((k0 >> 16) & 0xFF)]
                sbox[i * 2 + 0x201] = _TFMDS[3][(_TFP[_P31][b3] & 0xFF) ^ ((k0 >> 24) & 0xFF)]
            else:
                sbox[i * 2] = _TFMDS[0][(_TFP[_P01][(_TFP[_P02][b0] & 0xFF) ^ (k1 & 0xFF)] & 0xFF) ^ (k0 & 0xFF)]
                sbox[i * 2 + 1] = _TFMDS[1][(_TFP[_P11][(_TFP[_P12][b1] & 0xFF) ^ ((k1 >> 8) & 0xFF)] & 0xFF) ^ ((k0 >> 8) & 0xFF)]
                sbox[i * 2 + 0x200] = _TFMDS[2][(_TFP[_P21][(_TFP[_P22][b2] & 0xFF) ^ ((k1 >> 16) & 0xFF)] & 0xFF) ^ ((k0 >> 16) & 0xFF)]
                sbox[i * 2 + 0x201] = _TFMDS[3][(_TFP[_P31][(_TFP[_P32][b3] & 0xFF) ^ ((k1 >> 24) & 0xFF)] & 0xFF) ^ ((k0 >> 24) & 0xFF)]
        self.sbox = sbox

    def _f32(self, x, k32):
        b0, b1, b2, b3 = x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF
        k0, k1, k2, k3 = k32
        mode = self.k64 & 3
        if mode == 0:
            b0 = (_TFP[_P04][b0] & 0xFF) ^ (k3 & 0xFF)
            b1 = (_TFP[_P14][b1] & 0xFF) ^ ((k3 >> 8) & 0xFF)
            b2 = (_TFP[_P24][b2] & 0xFF) ^ ((k3 >> 16) & 0xFF)
            b3 = (_TFP[_P34][b3] & 0xFF) ^ ((k3 >> 24) & 0xFF)
        if mode in (0, 3):
            b0 = (_TFP[_P03][b0] & 0xFF) ^ (k2 & 0xFF)
            b1 = (_TFP[_P13][b1] & 0xFF) ^ ((k2 >> 8) & 0xFF)
            b2 = (_TFP[_P23][b2] & 0xFF) ^ ((k2 >> 16) & 0xFF)
            b3 = (_TFP[_P33][b3] & 0xFF) ^ ((k2 >> 24) & 0xFF)
        if mode == 1:
            return (_TFMDS[0][(_TFP[_P01][b0] & 0xFF) ^ (k0 & 0xFF)]
                    ^ _TFMDS[1][(_TFP[_P11][b1] & 0xFF) ^ ((k0 >> 8) & 0xFF)]
                    ^ _TFMDS[2][(_TFP[_P21][b2] & 0xFF) ^ ((k0 >> 16) & 0xFF)]
                    ^ _TFMDS[3][(_TFP[_P31][b3] & 0xFF) ^ ((k0 >> 24) & 0xFF)]) & M32
        return (_TFMDS[0][(_TFP[_P01][(_TFP[_P02][b0] & 0xFF) ^ (k1 & 0xFF)] & 0xFF) ^ (k0 & 0xFF)]
                ^ _TFMDS[1][(_TFP[_P11][(_TFP[_P12][b1] & 0xFF) ^ ((k1 >> 8) & 0xFF)] & 0xFF) ^ ((k0 >> 8) & 0xFF)]
                ^ _TFMDS[2][(_TFP[_P21][(_TFP[_P22][b2] & 0xFF) ^ ((k1 >> 16) & 0xFF)] & 0xFF) ^ ((k0 >> 16) & 0xFF)]
                ^ _TFMDS[3][(_TFP[_P31][(_TFP[_P32][b3] & 0xFF) ^ ((k1 >> 24) & 0xFF)] & 0xFF) ^ ((k0 >> 24) & 0xFF)]) & M32

    def _fe32_0(self, x):
        s = self.sbox
        return (s[0x000 + 2 * (x & 0xFF)] ^ s[0x001 + 2 * ((x >> 8) & 0xFF)]
                ^ s[0x200 + 2 * ((x >> 16) & 0xFF)] ^ s[0x201 + 2 * ((x >> 24) & 0xFF)]) & M32

    def _fe32_3(self, x):
        s = self.sbox
        return (s[0x000 + 2 * ((x >> 24) & 0xFF)] ^ s[0x001 + 2 * (x & 0xFF)]
                ^ s[0x200 + 2 * ((x >> 8) & 0xFF)] ^ s[0x201 + 2 * ((x >> 16) & 0xFF)]) & M32

    def encrypt_block(self, block16: bytes) -> bytes:
        sub = self.sub
        x0, x1, x2, x3 = struct.unpack("<4I", block16)
        x0 ^= sub[_TF_INPUT_WHITEN]
        x1 ^= sub[_TF_INPUT_WHITEN + 1]
        x2 ^= sub[_TF_INPUT_WHITEN + 2]
        x3 ^= sub[_TF_INPUT_WHITEN + 3]
        k = _TF_ROUND_SUBKEYS
        for _ in range(0, _TF_ROUNDS, 2):
            t0 = self._fe32_0(x0)
            t1 = self._fe32_3(x1)
            x2 ^= (t0 + t1 + sub[k]) & M32
            k += 1
            x2 = _rotr(x2, 1)
            x3 = _rotl(x3, 1) ^ ((t0 + 2 * t1 + sub[k]) & M32)
            k += 1
            t0 = self._fe32_0(x2)
            t1 = self._fe32_3(x3)
            x0 ^= (t0 + t1 + sub[k]) & M32
            k += 1
            x0 = _rotr(x0, 1)
            x1 = _rotl(x1, 1) ^ ((t0 + 2 * t1 + sub[k]) & M32)
            k += 1
        return struct.pack("<4I", x2 ^ sub[_TF_OUTPUT_WHITEN],
                           x3 ^ sub[_TF_OUTPUT_WHITEN + 1],
                           x0 ^ sub[_TF_OUTPUT_WHITEN + 2],
                           x1 ^ sub[_TF_OUTPUT_WHITEN + 3])

    def decrypt_block(self, block16: bytes) -> bytes:
        sub = self.sub
        x2, x3, x0, x1 = struct.unpack("<4I", block16)
        x2 ^= sub[_TF_OUTPUT_WHITEN]
        x3 ^= sub[_TF_OUTPUT_WHITEN + 1]
        x0 ^= sub[_TF_OUTPUT_WHITEN + 2]
        x1 ^= sub[_TF_OUTPUT_WHITEN + 3]
        k = _TF_ROUND_SUBKEYS + 2 * _TF_ROUNDS - 1
        for _ in range(0, _TF_ROUNDS, 2):
            t0 = self._fe32_0(x2)
            t1 = self._fe32_3(x3)
            x1 ^= (t0 + 2 * t1 + sub[k]) & M32
            k -= 1
            x0 = _rotl(x0, 1) ^ ((t0 + t1 + sub[k]) & M32)
            k -= 1
            x1 = _rotr(x1, 1)
            t0 = self._fe32_0(x0)
            t1 = self._fe32_3(x1)
            x3 ^= (t0 + 2 * t1 + sub[k]) & M32
            k -= 1
            x2 = _rotl(x2, 1) ^ ((t0 + t1 + sub[k]) & M32)
            k -= 1
            x3 = _rotr(x3, 1)
        return struct.pack("<4I", x0 ^ sub[_TF_INPUT_WHITEN],
                           x1 ^ sub[_TF_INPUT_WHITEN + 1],
                           x2 ^ sub[_TF_INPUT_WHITEN + 2],
                           x3 ^ sub[_TF_INPUT_WHITEN + 3])


def twofish_encrypt(block16: bytes, key: bytes) -> bytes:
    return Twofish(key).encrypt_block(block16)


def twofish_decrypt(block16: bytes, key: bytes) -> bytes:
    return Twofish(key).decrypt_block(block16)


# ---------------------------------------------------------------------------
# MISTY1 (RFC 2994)
# The server ships a *customized* MISTY1-DFO: custom S-boxes (algo06_*.bin,
# permutations of 0..127 / 0..511 but not the RFC values), an extra S7 mixing
# step at the end of FI (0x586e20), a rotated-by-1 FLmix (0x586d00), a
# re-ordered 3-round FO (0x586d40) over a 64-entry EK, and a round body that
# folds FL into the FO inputs (0x5866e0/0x5868e0).  Both variants are
# implemented; the DFO one is the live candidate, the RFC one (tables straight
# out of rfc2994.txt) is the comparison baseline.
# ---------------------------------------------------------------------------
def _misty_rfc_tables():
    txt = (REF / "rfc2994.txt").read_text(errors="replace")
    s7 = [None] * 128
    s9 = [None] * 512
    for line in txt.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]{2,3}):\s+"
                     r"([0-9a-fA-F]{2,3}(?:\s+[0-9a-fA-F]{2,3})*)\s*$", line)
        if not m:
            continue
        base = int(m.group(1), 16)
        toks = m.group(2).split()
        dst = s7 if len(toks[0]) == 2 else s9
        for i, t in enumerate(toks):
            dst[base + i] = int(t, 16)
    assert all(v is not None for v in s7) and all(v is not None for v in s9)
    return s7, s9


_M7_RFC, _M9_RFC = _misty_rfc_tables()
_M7_DFO = list(_u32s("algo06_misty1_s7.bin"))
_M9_DFO = list(_u32s("algo06_misty1_s9.bin"))
_MISTY_KP = [0x0123, 0x4567, 0x89AB, 0xCDEF,
             0xFEDC, 0xBA98, 0x7654, 0x3210]


def _misty_fi_rfc(x, key):
    d9 = (x >> 7) & 0x1FF
    d7 = x & 0x7F
    d9 = _M9_RFC[d9] ^ d7
    d7 = (_M7_RFC[d7] ^ d9) & 0x7F
    d7 ^= (key >> 9) & 0x7F
    d9 ^= key & 0x1FF
    d9 = _M9_RFC[d9] ^ d7
    return ((d7 << 9) | d9) & 0xFFFF


def _rotl16(v, n):
    v &= 0xFFFF
    return ((v << n) | (v >> (16 - n))) & 0xFFFF


def _misty_dfo_ek(key16: bytes) -> list:
    """Key schedule at 0x586ac0: byte-swapped 16-bit key words, Kp = K ^ C,
    then eight rotl16 mixes filling a 64-entry u32 table."""
    K = list(struct.unpack(">8H", key16))
    Kp = [k ^ c for k, c in zip(K, _MISTY_KP)]
    ek = [0] * 64
    for i in range(8):
        ek[i] = _rotl16(K[i], 1)
        ek[i + 8] = Kp[(i + 2) % 8]
        ek[i + 16] = _rotl16(K[(i + 1) % 8], 5)
        ek[i + 24] = _rotl16(K[(i + 5) % 8], 8)
        ek[i + 32] = _rotl16(K[(i + 6) % 8], 13)
        ek[i + 40] = Kp[(i + 4) % 8]
        ek[i + 48] = Kp[(i + 3) % 8]
        ek[i + 56] = Kp[(i + 7) % 8]
    return ek


def _misty_dfo_fi(x, key):
    """FI at 0x586e20: RFC FI with a final S7 mix, result = e + (f << 9)."""
    d7 = x & 0x7F
    a = _M9_DFO[(x >> 7) & 0x1FF] ^ d7
    e7 = (_M7_DFO[d7] ^ (a & 0x7F)) & 0x7F
    c = ((key >> 9) & 0x7F) ^ e7
    e = c ^ _M9_DFO[((key & 0x1FF) ^ a) & 0x1FF]
    f = (e & 0x7F) ^ _M7_DFO[c]
    return e + (f << 9)


def _misty_dfo_fl(x, k1, k2):
    """FL at 0x586d00: 16-bit halves with rotl16-by-1 mixing."""
    a = x & 0xFFFF
    b = (x >> 16) & 0xFFFF
    a ^= _rotl16(k1 & b, 1)
    b ^= _rotl16((k2 | a) & 0xFFFF, 1)
    return (b << 16) | a


def _misty_dfo_fo(x, k, ek):
    """FO at 0x586d40: three FI calls keyed from ek[k+16..k+56]."""
    xl = x & 0xFFFF
    a = xl ^ _misty_dfo_fi((x >> 16) ^ ek[k + 16], ek[k + 40])
    b = _misty_dfo_fi(xl ^ ek[k + 24], ek[k + 48])
    c = _misty_dfo_fi(a ^ ek[k + 32], ek[k + 56])
    return ((b ^ a) << 16) | (c ^ b ^ a)


def _misty_dfo_block(block8, ek, decrypt) -> bytes:
    """Block body of 0x5866e0 / 0x5868e0: per round k the FL is folded into
    the FO input (encrypt) and applied to the FO output (decrypt)."""
    d0, d1 = struct.unpack(">2I", block8)
    ks = range(6, -1, -2) if decrypt else range(0, 8, 2)
    for k in ks:
        if not decrypt:
            d1 ^= _misty_dfo_fo(_misty_dfo_fl(d0, ek[k], ek[k + 8]), k, ek)
            d0 ^= _misty_dfo_fl(_misty_dfo_fo(d1, k + 1, ek),
                                ek[k + 1], ek[k + 9])
        else:
            d0 ^= _misty_dfo_fl(_misty_dfo_fo(d1, k + 1, ek),
                                ek[k + 1], ek[k + 9])
            d1 ^= _misty_dfo_fo(_misty_dfo_fl(d0, ek[k], ek[k + 8]), k, ek)
    return struct.pack(">2I", d0, d1)


def _misty_key(key: bytes, fi) -> list:
    ek = list(struct.unpack(">8H", key))
    ek += [0] * 24
    for i in range(8):
        ek[i + 8] = fi(ek[i], ek[(i + 1) % 8])
        ek[i + 16] = ek[i + 8] & 0x1FF
        ek[i + 24] = ek[i + 8] >> 9
    return ek


def _misty_crypt(block8: bytes, key: bytes, fi, decrypt: bool) -> bytes:
    """RFC 2994: C = (D1<<32)|D0 on encrypt, P = (D0<<32)|D1 on decrypt."""
    ek = _misty_key(key, fi)

    def fo(x, k):
        t0 = (x >> 16) ^ ek[k]
        t0 = fi(t0, ek[(k + 5) % 8 + 8])
        t0 ^= x & 0xFFFF
        t1 = (x & 0xFFFF) ^ ek[(k + 2) % 8]
        t1 = fi(t1, ek[(k + 1) % 8 + 8])
        t1 ^= t0
        t0 ^= ek[(k + 7) % 8]
        t0 = fi(t0, ek[(k + 3) % 8 + 8])
        t0 ^= t1
        t1 ^= ek[(k + 4) % 8]
        return ((t1 << 16) | t0) & M32

    def fl(x, k):
        d0, d1 = (x >> 16) & 0xFFFF, x & 0xFFFF
        if k % 2 == 0:
            d1 ^= d0 & ek[k // 2]
            d0 ^= d1 | ek[(k // 2 + 6) % 8 + 8]
        else:
            d1 ^= d0 & ek[((k - 1) // 2 + 2) % 8 + 8]
            d0 ^= d1 | ek[((k - 1) // 2 + 4) % 8]
        return ((d0 << 16) | d1) & M32

    def flinv(x, k):
        d0, d1 = (x >> 16) & 0xFFFF, x & 0xFFFF
        if k % 2 == 0:
            d0 ^= d1 | ek[(k // 2 + 6) % 8 + 8]
            d1 ^= d0 & ek[k // 2]
        else:
            d0 ^= d1 | ek[((k - 1) // 2 + 4) % 8]
            d1 ^= d0 & ek[((k - 1) // 2 + 2) % 8 + 8]
        return ((d0 << 16) | d1) & M32

    if not decrypt:
        d0, d1 = struct.unpack(">II", block8)
        for r in range(0, 8, 2):
            d0 = fl(d0, r)
            d1 = fl(d1, r + 1)
            d1 ^= fo(d0, r)
            d0 ^= fo(d1, r + 1)
        d0 = fl(d0, 8)
        d1 = fl(d1, 9)
        return struct.pack(">II", d1, d0)
    d1, d0 = struct.unpack(">II", block8)
    d0 = flinv(d0, 8)
    d1 = flinv(d1, 9)
    for r in range(6, -1, -2):
        d0 ^= fo(d1, r + 1)
        d1 ^= fo(d0, r)
        d0 = flinv(d0, r)
        d1 = flinv(d1, r + 1)
    return struct.pack(">II", d0, d1)


def misty1_encrypt(block8, key):
    return _misty_crypt(block8, key, _misty_fi_rfc, False)


def misty1_decrypt(block8, key):
    return _misty_crypt(block8, key, _misty_fi_rfc, True)


def _misty_dfo_crypt(data, key, decrypt):
    ek = _misty_dfo_ek(key)
    n = len(data) - len(data) % 8
    return b"".join(_misty_dfo_block(data[i:i + 8], ek, decrypt)
                    for i in range(0, n, 8)) + data[n:]


def misty1_dfo_encrypt(data, key):
    return _misty_dfo_crypt(data, key, False)


def misty1_dfo_decrypt(data, key):
    return _misty_dfo_crypt(data, key, True)


# ---------------------------------------------------------------------------
# DFO-Custom-16B (algo 12): a Rijndael-flavoured 16B cipher from the server
# ("DFO custom 16B cipher needs a 16B key").  16 rounds; round function
# 0x585500 (inverse 0x5855e0) over four 32-bit words with a 4-word key
# schedule (0x585370) and a shared 17-entry round-constant table (0x64187b0);
# final round 0x5856c0.  Wrappers 0x585000/0x5851c0, big-endian words.
# ---------------------------------------------------------------------------
_RIJ12_K = [0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E,
            0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4]
_RIJ12_ROUNDS = 16


def _rij12_f(x):
    """0x5854f0: (ror8(x) ^ x) ^ rol8(x)."""
    x &= M32
    return (_rotr(x, 8) ^ x) ^ _rotl(x, 8)


def _rij12_key(key16: bytes):
    """0x585370: two 4-word schedules, one per direction."""
    w0, w1, w2, w3 = struct.unpack(">4I", key16)
    ks_e = [w0, w1, w2, w3]
    t = _rij12_f(w0 ^ w2)
    w1 ^= t
    w3 ^= t
    u = _rij12_f(w1 ^ w3)
    ks_d = [w0 ^ u, w1, w2 ^ u, w3]
    return ks_e, ks_d


def _rij12_round(a, b, c, d, rc, k):
    t0 = rc ^ a
    e0 = _rij12_f(t0 ^ c)
    r13 = e0 ^ k[1] ^ b
    t1 = e0 ^ k[3] ^ d
    r12 = _rotl(t1, 2)
    e1 = _rij12_f(t1 ^ r13)
    q = _rotl(e1 ^ c ^ k[2], 5)
    dd = (~(q | r12)) ^ r13
    p = _rotl(e1 ^ t0 ^ k[0], 1) ^ (dd & q)
    q ^= p ^ dd ^ r12
    dd ^= ~(p | q)
    b_new = dd & M32
    return (_rotr(((q & b_new) ^ r12) & M32, 1), b_new,
            _rotr(q & M32, 5), _rotr(p & M32, 2))


def _rij12_round_inv(a, b, c, d, rc, k):
    e0 = _rij12_f(a ^ c)
    r13 = e0 ^ k[1] ^ b
    t1 = e0 ^ k[3] ^ d
    r12 = _rotl(t1, 2)
    e1 = _rij12_f(t1 ^ r13)
    q = _rotl(e1 ^ c ^ k[2], 5)
    dd = (~(q | r12)) ^ r13
    p = _rotl(e1 ^ a ^ rc ^ k[0], 1) ^ (dd & q)
    q ^= p ^ dd ^ r12
    dd ^= ~(p | q)
    b_new = dd & M32
    return (_rotr(((q & b_new) ^ r12) & M32, 1), b_new,
            _rotr(q & M32, 5), _rotr(p & M32, 2))


def _rij12_final(a, b, c, d, e, key, k):
    """0x5856c0: `e` is the pre-mixed word supplied by the wrapper."""
    r13 = e ^ k[1] ^ b
    r12 = e ^ k[3] ^ d
    e2 = _rij12_f(r13 ^ r12)
    return ((e2 ^ k[0] ^ a ^ key) & M32, r13, (c ^ e2 ^ k[2]) & M32, r12)


def _rij12_block(block16: bytes, ks_e, ks_d, decrypt: bool) -> bytes:
    a, b, c, d = struct.unpack(">4I", block16)
    if not decrypt:
        for i in range(_RIJ12_ROUNDS):
            a, b, c, d = _rij12_round(a, b, c, d, _RIJ12_K[i], ks_e)
        e = _rij12_f(a ^ c ^ _RIJ12_K[16])
        a, b, c, d = _rij12_final(a, b, c, d, e, _RIJ12_K[16], ks_e)
    else:
        for j in range(_RIJ12_ROUNDS):
            a, b, c, d = _rij12_round_inv(a, b, c, d,
                                          _RIJ12_K[16 - j], ks_d)
        e = _rij12_f(a ^ c)
        a, b, c, d = _rij12_final(a, b, c, d, e, _RIJ12_K[0], ks_d)
    return struct.pack(">4I", a, b, c, d)


def _rij12_crypt(data, key, decrypt):
    ks_e, ks_d = _rij12_key(key)
    n = len(data) - len(data) % 16
    return b"".join(_rij12_block(data[i:i + 16], ks_e, ks_d, decrypt)
                    for i in range(0, n, 16)) + data[n:]


def dfo16_encrypt(data, key):
    return _rij12_crypt(data, key, False)


def dfo16_decrypt(data, key):
    return _rij12_crypt(data, key, True)


# ---------------------------------------------------------------------------
# DFO-Rijndael12 (algo 9): 12-round 16B cipher ("DFO Rijndael-12 needs a 16B
# key").  SetKey 0x5876f0, schedule builder 0x587d40, one-step K4 0x587fa0
# (table picker G 0x588160), state expansion 0x588240, word transform
# 0x5883c0, block worker 0x587880 (enc thunk 0x587860 -> this+8,
# dec thunk 0x587870 -> this+0x10).  Tables live in the class holder built by
# cctor 0x5884a0: t0..t3, tbl5, sbox (u32 broadcast), byte sbox, rcon.
# ---------------------------------------------------------------------------
_RIJ9_T = tuple(_u32s(f"algo09_t{i}.bin") for i in range(4))
_RIJ9_IDX = _u32s("algo09_sbox.bin")           # u32 broadcast of S[x]
_RIJ9_TB5 = _u32s("algo09_tbl5.bin")           # (8x, 6x, 2x, x) per lane
_RIJ9_RCON = _u32s("algo09_rcon.bin")
_RIJ9_S = bytes(v & 0xFF for v in _RIJ9_IDX)


def _rij9_expand(st: bytes, rcon: int) -> bytes:
    """0x588240: diagonal byte routing through t0..t3, rcon only on word 0."""
    t0, t1, t2, t3 = _RIJ9_T
    out = []
    for i in range(4):
        v = (t0[st[4 * i + 3]] ^ t1[st[4 * ((i + 3) % 4) + 2]]
             ^ t2[st[4 * ((i + 2) % 4) + 1]] ^ t3[st[4 * ((i + 1) % 4)]])
        if i == 0:
            v ^= rcon
        out.append(v & M32)
    return struct.pack("<4I", *out)


def _rij9_G(w, x):
    """0x588160: lane l picks byte l of tbl5[byte l of w], then xor the
    broadcast sbox of x."""
    v = 0
    for lane in range(4):
        v |= _RIJ9_TB5[(w >> (8 * lane)) & 0xFF] & (0xFF << (8 * lane))
    return (v ^ _RIJ9_IDX[x & 0xFF]) & M32


def _rij9_K4(st: bytes):
    """0x587fa0: sched words for one state; word j reads lane 3-j of every
    state word (last word first)."""
    res = []
    for j in range(4):
        acc = _RIJ9_IDX[st[15 - j]]
        for w in (2, 1, 0):
            acc = _rij9_G(acc, st[4 * w + (3 - j)])
        res.append(acc)
    return res


def _rij9_f(w):
    """0x5883c0: t0..t3 through the byte sbox, big-endian lanes."""
    t0, t1, t2, t3 = _RIJ9_T
    s = _RIJ9_S
    return (t0[s[(w >> 24) & 0xFF]] ^ t1[s[(w >> 16) & 0xFF]]
            ^ t2[s[(w >> 8) & 0xFF]] ^ t3[s[w & 0xFF]]) & M32


def _rij9_key(key16: bytes):
    """0x587d40 + 0x587fa0: 13 round keys; each state word byte-reversed."""
    st = b"".join(key16[4 * i:4 * i + 4][::-1] for i in range(4))
    enc = []
    for i in range(13):
        enc += _rij9_K4(st)
        if i < 12:
            st = _rij9_expand(st, _RIJ9_RCON[i])
    dec = [0] * 52
    dec[0:4] = enc[48:52]
    dec[48:52] = enc[0:4]
    for i in range(1, 12):
        for j in range(4):
            dec[4 * i + j] = _rij9_f(enc[48 - 4 * i + j])
    return enc, dec


def _rij9_rnd(v, k):
    """0x587880 round: word j gets t_i[byte j of v i] for each i."""
    t0, t1, t2, t3 = _RIJ9_T
    return [(k[0] ^ t0[(v[0] >> 24) & 0xFF] ^ t1[(v[1] >> 24) & 0xFF]
             ^ t2[(v[2] >> 24) & 0xFF] ^ t3[(v[3] >> 24) & 0xFF]) & M32,
            (k[1] ^ t0[(v[0] >> 16) & 0xFF] ^ t1[(v[1] >> 16) & 0xFF]
             ^ t2[(v[2] >> 16) & 0xFF] ^ t3[(v[3] >> 16) & 0xFF]) & M32,
            (k[2] ^ t0[(v[0] >> 8) & 0xFF] ^ t1[(v[1] >> 8) & 0xFF]
             ^ t2[(v[2] >> 8) & 0xFF] ^ t3[(v[3] >> 8) & 0xFF]) & M32,
            (k[3] ^ t0[v[0] & 0xFF] ^ t1[v[1] & 0xFF] ^ t2[v[2] & 0xFF]
             ^ t3[v[3] & 0xFF]) & M32]


def _rij9_fin(v, k):
    """0x587880 last round: lane j keeps only table t_j's byte j."""
    t0, t1, t2, t3 = _RIJ9_T
    return [(k[0] ^ (t0[(v[0] >> 24) & 0xFF] & 0xFF000000)
             ^ (t1[(v[1] >> 24) & 0xFF] & 0x00FF0000)
             ^ (t2[(v[2] >> 24) & 0xFF] & 0x0000FF00)
             ^ (t3[(v[3] >> 24) & 0xFF] & 0x000000FF)) & M32,
            (k[1] ^ (t0[(v[0] >> 16) & 0xFF] & 0xFF000000)
             ^ (t1[(v[1] >> 16) & 0xFF] & 0x00FF0000)
             ^ (t2[(v[2] >> 16) & 0xFF] & 0x0000FF00)
             ^ (t3[(v[3] >> 16) & 0xFF] & 0x000000FF)) & M32,
            (k[2] ^ (t0[(v[0] >> 8) & 0xFF] & 0xFF000000)
             ^ (t1[(v[1] >> 8) & 0xFF] & 0x00FF0000)
             ^ (t2[(v[2] >> 8) & 0xFF] & 0x0000FF00)
             ^ (t3[(v[3] >> 8) & 0xFF] & 0x000000FF)) & M32,
            (k[3] ^ (t0[v[0] & 0xFF] & 0xFF000000)
             ^ (t1[v[1] & 0xFF] & 0x00FF0000)
             ^ (t2[v[2] & 0xFF] & 0x0000FF00)
             ^ (t3[v[3] & 0xFF] & 0x000000FF)) & M32]


def _rij9_block(block16: bytes, sched) -> bytes:
    v = [w ^ k for w, k in zip(struct.unpack(">4I", block16), sched[0:4])]
    for r in range(1, 12):
        v = _rij9_rnd(v, sched[4 * r:4 * r + 4])
    return struct.pack(">4I", *_rij9_fin(v, sched[48:52]))


def _rij9_crypt(data, key, decrypt):
    enc, dec = _rij9_key(key)
    sched = dec if decrypt else enc
    n = len(data) - len(data) % 16
    return b"".join(_rij9_block(data[i:i + 16], sched)
                    for i in range(0, n, 16)) + data[n:]


def dfo9_encrypt(data, key):
    return _rij9_crypt(data, key, False)


def dfo9_decrypt(data, key):
    return _rij9_crypt(data, key, True)


# ---------------------------------------------------------------------------
# Custom 8B (algo 13): 8B cipher, 40B key.  SetKey 0x585750 (span len == 40 ->
# schedule builder 0x585ce0 -> this+8), enc 0x5858c0 / dec 0x585aa0 (shared
# block-multiple validator 0x5843b0, call sites 0x585907/0x585ae7).  F helper
# 0x585cb0.  127 steps: 31 full passes over s[0..7] with i alternating 0/4
# plus a final pass that stops after the C step.
# ---------------------------------------------------------------------------


def _rij13_F(x, k1, k2):
    """0x585cb0."""
    c = (k1 + x) & M32
    c = (c + _rotl(c, 2) + 1) & M32
    v = _rotl(c, 8) ^ c
    z = (v + k2) & M32
    w = (_rotl(z, 1) - z) & M32
    return ((w | x) ^ _rotl(w, 16)) & M32


def _rij13_key(key40: bytes):
    """0x585ce0: 8 sched words from the 40B key."""
    K = [int.from_bytes(key40[4 * i:4 * i + 4], "big") for i in range(8)]
    w8 = int.from_bytes(key40[32:36], "big")
    w9 = int.from_bytes(key40[36:40], "big")
    x = w8 ^ w9
    s = [0] * 8
    c = (x + K[0]) & M32
    t = (c + _rotl(c, 1) - 1) & M32
    s[0] = w8 ^ t ^ _rotl(t, 4)
    s[1] = _rij13_F(s[0], K[1], K[2]) ^ x
    c = (s[1] + K[3]) & M32
    s[2] = s[0] ^ ((c + _rotl(c, 2) + 1) & M32)
    s[3] = s[1] ^ s[2]
    c = (s[3] + K[4]) & M32
    t = (c + _rotl(c, 1) - 1) & M32
    s[4] = s[2] ^ t ^ _rotl(t, 4)
    s[5] = s[3] ^ _rij13_F(s[4], K[5], K[6])
    c = (s[5] + K[7]) & M32
    s[6] = s[4] ^ ((c + _rotl(c, 2) + 1) & M32)
    s[7] = s[5] ^ s[6]
    return s


def _rij13_enc_block(block8: bytes, s) -> bytes:
    a = int.from_bytes(block8[0:4], "big")
    b = int.from_bytes(block8[4:8], "big") ^ a
    i = 0
    n = 1
    while n < 128:
        t = (b + s[i]) & M32
        u = (t + _rotl(t, 1) - 1) & M32
        a ^= u
        a ^= _rotl(u, 4)
        n += 1
        if n == 128:
            break
        b ^= _rij13_F(a, s[i + 1], s[i + 2])
        n += 1
        if n == 128:
            break
        t = (b + s[i + 3]) & M32
        a ^= (t + _rotl(t, 2) + 1) & M32
        n += 1
        if n == 128:
            break
        i ^= 4
        b ^= a
        n += 1
    return a.to_bytes(4, "big") + b.to_bytes(4, "big")


def _rij13_dec_block(block8: bytes, s) -> bytes:
    a = int.from_bytes(block8[0:4], "big")
    b = int.from_bytes(block8[4:8], "big")
    t = (b + s[7]) & M32                      # undo final pass (i = 4, C/B/A)
    a ^= (t + _rotl(t, 2) + 1) & M32
    b ^= _rij13_F(a, s[5], s[6])
    t = (b + s[4]) & M32
    u = (t + _rotl(t, 1) - 1) & M32
    a ^= u
    a ^= _rotl(u, 4)
    for p in range(30, -1, -1):
        i = 0 if p % 2 == 0 else 4
        b ^= a
        t = (b + s[i + 3]) & M32
        a ^= (t + _rotl(t, 2) + 1) & M32
        b ^= _rij13_F(a, s[i + 1], s[i + 2])
        t = (b + s[i]) & M32
        u = (t + _rotl(t, 1) - 1) & M32
        a ^= u
        a ^= _rotl(u, 4)
    return a.to_bytes(4, "big") + (a ^ b).to_bytes(4, "big")


def _rij13_crypt(data, key, decrypt):
    s = _rij13_key(key)
    fn = _rij13_dec_block if decrypt else _rij13_enc_block
    n = len(data) - len(data) % 8
    return b"".join(fn(data[i:i + 8], s)
                    for i in range(0, n, 8)) + data[n:]


def dfo13_encrypt(data, key):
    return _rij13_crypt(data, key, False)


def dfo13_decrypt(data, key):
    return _rij13_crypt(data, key, True)


# ---------------------------------------------------------------------------
# Khazad-like (algo 11): 8B block, 16B key.  SetKey 0x585eb0 -> schedule
# builder 0x586240 (K[i] = K[i-2] ^ G(K[i-1]) ^ C[i], K[-2]=key BE hw0,
# K[-1]=key BE hw1); enc thunk 0x586030 ([this+8]) and dec thunk 0x586040
# ([this+0x10]) share worker 0x586060.  G 0x586360, inverse 0x5863e0.
# Table loader 0x583860 turns the 16384B blob into 8 u64[256] tables t0..t7
# and reorders them R = [t0, t7, t6, t5, t4, t3, t2, t1]; S_INV = low bytes
# of R[0]; C[9] lives at .rdata 0x5af1500 (holder cctor 0x586470).
# ---------------------------------------------------------------------------
_A11_RAW = _u64s("algo11_khazad_t.bin")
_A11_T = [_A11_RAW[256 * i:256 * i + 256] for i in range(8)]
_A11_R = [_A11_T[0]] + _A11_T[:0:-1]
_A11_SINV = bytes(v & 0xFF for v in _A11_R[0])
_A11_C = _u64s("algo11_c.bin")
M64 = 0xFFFFFFFFFFFFFFFF


def _a11_G(x):
    y = 0
    for r in range(8):
        y ^= _A11_R[r][(x >> (8 * r)) & 0xFF]
    return y & M64


def _a11_inv(x):
    y = 0
    for r in range(8):
        y ^= _A11_R[r][_A11_SINV[(x >> (8 * r)) & 0xFF]]
    return y & M64


def _a11_key(key16: bytes):
    enc = []
    rsi = int.from_bytes(key16[8:16], "big")
    rdi = int.from_bytes(key16[0:8], "big")
    for i in range(9):
        if i:
            rsi, rdi = rdi, rsi
        rdi ^= _a11_G(rsi) ^ _A11_C[i]
        enc.append(rdi)
    dec = [0] * 9
    dec[0] = enc[8]
    dec[8] = enc[0]
    for i in range(1, 8):
        dec[i] = _a11_inv(enc[8 - i])
    return enc, dec


def _a11_block(blk8: bytes, sched) -> bytes:
    x = int.from_bytes(blk8, "big") ^ sched[0]
    for r in range(1, 8):
        x = _a11_G(x) ^ sched[r]
    y = sched[8]
    for r in range(8):
        y ^= _A11_R[r][(x >> (8 * r)) & 0xFF] & (0xFF << (8 * r))
    return (y & M64).to_bytes(8, "big")


def _a11_crypt(data, key, decrypt):
    enc, dec = _a11_key(key)
    sched = dec if decrypt else enc
    n = len(data) - len(data) % 8
    return b"".join(_a11_block(data[i:i + 8], sched)
                    for i in range(0, n, 8)) + data[n:]


def dfo11_encrypt(data, key):
    return _a11_crypt(data, key, False)


def dfo11_decrypt(data, key):
    return _a11_crypt(data, key, True)


# ---------------------------------------------------------------------------
# AES-128 (algo 4): stock .NET Aes, ECB mode, PaddingMode.None.  SetKey
# 0x588af0 builds a SymmetricAlgorithm, calls set_Mode(2)/set_PaddingMode(1),
# SetKey(16B), then stashes CreateEncryptor()/CreateDecryptor() in this+0x10
# /this+0x18 (thunks 0x588d10/0x588d30 -> shared span worker 0x588da0).
# On Windows the BCL Aes is bcrypt-backed (exe imports bcrypt.dll /
# BCryptEncrypt), so parity with BCrypt AES-ECB pins this implementation.
# ---------------------------------------------------------------------------


def _aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        rot = q
        for k in (1, 2, 3, 4):
            rot ^= ((q << k) | (q >> (8 - k))) & 0xFF
        sbox[p] = rot ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return bytes(sbox), bytes(inv)


_AES_S, _AES_SI = _aes_tables()
_AES_RCON = (0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _aes_xtime(b):
    b <<= 1
    return (b ^ 0x1B) & 0xFF if b & 0x100 else b


def _aes_key(key16: bytes):
    w = [list(key16[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_AES_S[b] for b in t[1:] + t[:1]]
            t[0] ^= _AES_RCON[i // 4]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return w


def _aes_add_key(st, w, r):
    for c in range(4):
        for i in range(4):
            st[4 * c + i] ^= w[4 * r + c][i]


def _aes_mix(st, inv):
    xt = _aes_xtime
    ns = []
    for c in range(4):
        a0, a1, a2, a3 = st[4 * c:4 * c + 4]
        if not inv:
            ns += [xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3,
                   a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3,
                   a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3,
                   xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3)]
        else:
            m = _aes_mul
            ns += [m(a0, 14) ^ m(a1, 11) ^ m(a2, 13) ^ m(a3, 9),
                   m(a0, 9) ^ m(a1, 14) ^ m(a2, 11) ^ m(a3, 13),
                   m(a0, 13) ^ m(a1, 9) ^ m(a2, 14) ^ m(a3, 11),
                   m(a0, 11) ^ m(a1, 13) ^ m(a2, 9) ^ m(a3, 14)]
    return ns


def _aes_crypt(data, key, decrypt):
    key = key[:16]
    w = _aes_key(key)
    n = len(data) - len(data) % 16
    out = bytearray()
    for o in range(0, n, 16):
        st = list(data[o:o + 16])
        if not decrypt:
            _aes_add_key(st, w, 0)
            for r in range(1, 11):
                st = [_AES_S[b] for b in st]
                st = [st[4 * ((c + i) % 4) + i]
                      for c in range(4) for i in range(4)]
                if r < 10:
                    st = _aes_mix(st, False)
                _aes_add_key(st, w, r)
        else:
            _aes_add_key(st, w, 10)
            for r in range(9, -1, -1):
                st = [st[4 * ((c - i) % 4) + i]
                      for c in range(4) for i in range(4)]
                st = [_AES_SI[b] for b in st]
                _aes_add_key(st, w, r)
                if r:
                    st = _aes_mix(st, True)
        out += bytes(st)
    return bytes(out) + data[n:]


def _aes_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _aes_xtime(a)
        b >>= 1
    return r


def aes128_encrypt(data, key):
    return _aes_crypt(data, key, False)


def aes128_decrypt(data, key):
    return _aes_crypt(data, key, True)


# ---------------------------------------------------------------------------
# XTEA (32 rounds, delta 0x9E3779B9) -- the exe's XTEA class, MT 0x5b78850,
# transform 0x589080 / 0x589200.  It carries two independent endian flags:
# `io_be` (block words packed big-endian) and `key_be` (key words bswapped).
# The two wire variants set them *together* -- AlgoId 0 is io_be=key_be=1,
# AlgoId 8 is 0/0 -- so one flag each way is enough here.
# ---------------------------------------------------------------------------
DELTA = 0x9E3779B9


def _xtea_mix(a: int, s: int, k: int) -> int:
    """The XTEA round function `(((a<<4) ^ (a>>5)) + a) ^ (s + k)`.

    Written out because in Python `+` binds tighter than `^`: the two XORs
    have to be explicit or the term silently folds into the accumulator.
    """
    return ((((a << 4) & M32) ^ (a >> 5)) + a) ^ ((s + k) & M32)


def xtea_encrypt(block8: bytes, key16: bytes, io_be: bool = False) -> bytes:
    fmt = ">II" if io_be else "<II"
    v0, v1 = struct.unpack(fmt, block8)
    k = struct.unpack(">4I" if io_be else "<4I", key16[:16])
    s = 0
    for _ in range(32):
        v0 = (v0 + _xtea_mix(v1, s, k[s & 3])) & M32
        s = (s + DELTA) & M32
        v1 = (v1 + _xtea_mix(v0, s, k[(s >> 11) & 3])) & M32
    return struct.pack(fmt, v0, v1)


def xtea_decrypt(block8: bytes, key16: bytes, io_be: bool = False) -> bytes:
    fmt = ">II" if io_be else "<II"
    v0, v1 = struct.unpack(fmt, block8)
    k = struct.unpack(">4I" if io_be else "<4I", key16[:16])
    s = (DELTA * 32) & M32
    for _ in range(32):
        v1 = (v1 - _xtea_mix(v0, s, k[(s >> 11) & 3])) & M32
        s = (s - DELTA) & M32
        v0 = (v0 - _xtea_mix(v1, s, k[s & 3])) & M32
    return struct.pack(fmt, v0, v1)


def xtea_be_encrypt(data, key):
    return xtea_encrypt(data, key, io_be=True)


def xtea_be_decrypt(data, key):
    return xtea_decrypt(data, key, io_be=True)


def xtea_le_encrypt(data, key):
    return xtea_encrypt(data, key, io_be=False)


def xtea_le_decrypt(data, key):
    return xtea_decrypt(data, key, io_be=False)


# ---------------------------------------------------------------------------
# XOR-32 -- the exe's Xor32Cipher, MT 0x5b788b8, transform 0x589580: xor every
# 4-byte block with one u32le taken from the *end* of the key material.  It
# has no partial-block rule of its own: a trailing 1..3 bytes pass through.
# ---------------------------------------------------------------------------
def xor32_encrypt(data: bytes, key: bytes) -> bytes:
    k = int.from_bytes(key[-4:], "little")
    n = len(data) - len(data) % 4
    return b"".join(
        (int.from_bytes(data[i:i + 4], "little") ^ k).to_bytes(4, "little")
        for i in range(0, n, 4)) + data[n:]


xor32_decrypt = xor32_encrypt


#: Every algorithm with the key slice and block size the server pairs it
#: with, as `verify_gold.py` found them.  `selftest` is the round-trip check
#: the file used to do only when run as `__main__`; the key offsets are the
#: reason it is worth keeping.
SELFTEST = (
    ("CAST-128  ", cast128_encrypt, cast128_decrypt, 16, 16, 8),
    ("Skipjack  ", skipjack_encrypt, skipjack_decrypt, 140, 10, 8),
    ("Blowfish  ", blowfish_encrypt, blowfish_decrypt, 166, 56, 8),
    ("RC6-480   ", rc6_encrypt, rc6_decrypt, 32, 60, 16),
    ("Twofish256", twofish_encrypt, twofish_decrypt, 92, 32, 16),
    ("MISTY1    ", misty1_encrypt, misty1_decrypt, 150, 16, 8),
    ("MISTY1-DFO", misty1_dfo_encrypt, misty1_dfo_decrypt, 150, 16, 8),
    ("DFO-16B   ", dfo16_encrypt, dfo16_decrypt, 278, 16, 16),
    ("DFO-Rij12 ", dfo9_encrypt, dfo9_decrypt, 238, 16, 16),
    ("Custom 8B ", dfo13_encrypt, dfo13_decrypt, 294, 40, 8),
    ("Khazad    ", dfo11_encrypt, dfo11_decrypt, 262, 16, 8),
    ("AES-128   ", aes128_encrypt, aes128_decrypt, 124, 16, 16),
    ("XTEA-BE   ", xtea_be_encrypt, xtea_be_decrypt, 0, 16, 8),
    ("XTEA-LE   ", xtea_le_encrypt, xtea_le_decrypt, 222, 16, 8),
    ("XOR-32    ", xor32_encrypt, xor32_decrypt, 254, 8, 4),
)


def selftest() -> int:
    """Round-trip all 15 primitives on `bytes(range(block))`; 0 if all pass."""
    blob = KEY_BLOB.read_bytes()
    bad = 0
    for name, enc, dec, off, ln, bs in SELFTEST:
        key = blob[off:off + ln]
        pt = bytes(range(bs))
        ct = enc(pt, key)
        rt = dec(ct, key)
        bad += rt != pt
        print(f"  {'OK ' if rt == pt else 'BAD'} {name} block={bs} "
              f"E(0123..)={ct.hex()} roundtrip={'yes' if rt == pt else 'no'}")
    return bad


if __name__ == "__main__":
    raise SystemExit(selftest())
