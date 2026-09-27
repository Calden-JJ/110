#!/usr/bin/env python3
"""Extract the 12 embedded Crypto.Tables.* resource payloads from USLocalServer.Server.exe.

Layout was pinned by content, not by guesswork:
  * the payload blob starts right after the JSON resource blob at RVA 0x58ea1f0
  * manifest order == blob order, and the per-entry offset deltas equal size/16
  * algo07...sboxes is 4096 B of the canonical pi-digit Blowfish S-boxes
  * algo09_sbox/t0..t3 are 5 x 1024 B (broadcast sbox + four byte-rotated
    (s,2s,4s,6s) tables); tbl5 is 1024 B of (x,2x,6x,8x)
  * algo11_khazad_t is 8 x 2048 B = 16384 B
  * channelinfo_key_blob is exactly 334 B (the loader's own message says so)

Writes to <out>/<resource name>.  Read-only w.r.t. the exe.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\USLocalServer.Server.exe")
OUT = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto")

SECS = [
    (".text", 0x00001000, 0x00a05bb6, 0x00000400, 0x00a05c00),
    (".rdata", 0x00a07000, 0x058f39c6, 0x00a06000, 0x058f3a00),
    (".data", 0x062fb000, 0x001e6418, 0x062f9a00, 0x0018a400),
]

BLOB_BASE = 0x58EA1F0            # RVA where the crypto payload blob starts
C_RVA = 0x5AF1500                # algo11 Khazad-like round constants (9 u64,
                                 # memcpy'd by the holder cctor 0x586470)

TABLES = [
    ("algo06_misty1_s7.bin", 0x0000, 512),
    ("algo06_misty1_s9.bin", 0x0200, 2048),
    ("algo07_blowfish_sboxes.bin", 0x0A00, 4096),
    ("algo09_rcon.bin", 0x1A00, 64),
    ("algo09_sbox.bin", 0x1A40, 1024),
    ("algo09_t0.bin", 0x1E40, 1024),
    ("algo09_t1.bin", 0x2240, 1024),
    ("algo09_t2.bin", 0x2640, 1024),
    ("algo09_t3.bin", 0x2A40, 1024),
    ("algo09_tbl5.bin", 0x2E40, 1024),
    ("algo11_khazad_t.bin", 0x3240, 16384),
    ("channelinfo_key_blob.bin", 0x7240, 334),
]


def rva2off(rva):
    for _n, va, vs, ro, _rs in SECS:
        if va <= rva < va + vs:
            return ro + (rva - va)
    return None


def pi_words(nwords):
    P = nwords * 32 + 128

    def atan_inv(x):
        total = term = (1 << P) // x
        x2 = x * x
        n, sign = 1, -1
        while term:
            term //= x2
            total += sign * (term // (2 * n + 1))
            sign = -sign
            n += 1
        return total

    val = 16 * atan_inv(5) - 4 * atan_inv(239) - 3 * (1 << P)
    return [(val >> (P - 32 * (i + 1))) & 0xFFFFFFFF for i in range(nwords)]


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return r


def check(name, b):
    """Structural self-check -- returns a short verdict string."""
    if name.startswith("algo06_misty1_s7"):
        v = struct.unpack("<128I", b)
        return f"perm(0..127)={sorted(v) == list(range(128))}"
    if name.startswith("algo06_misty1_s9"):
        v = struct.unpack("<512I", b)
        return f"perm(0..511)={sorted(v) == list(range(512))}"
    if name.startswith("algo07"):
        v = struct.unpack("<1024I", b)
        pi = pi_words(1100)[18:1042]
        return f"canonical pi S-boxes={list(v) == pi}"
    if name.startswith("algo09_sbox"):
        v = struct.unpack("<256I", b)
        flat = all(x == (x & 0xFF) * 0x01010101 for x in v)
        seq = [x & 0xFF for x in v]
        return f"broadcast={flat} perm={sorted(seq) == list(range(256))}"
    if name.startswith("algo09_t") and name[8] in "0123":
        v = struct.unpack("<256I", b)
        sbox = struct.unpack("<256I", (OUT / "algo09_sbox.bin").read_bytes())
        s = [x & 0xFF for x in sbox]
        rot = int(name[8])
        hits = [tag for tag, f in
                (("int%256", lambda x: (x, 2 * x % 256, 4 * x % 256, 6 * x % 256)),
                 ("gf", lambda x: (x, gmul(x, 2), gmul(x, 4), gmul(x, 6))))
                if all(v[i].to_bytes(4, "little")
                       == bytes(f(s[i])[j ^ rot] for j in range(4))
                       for i in range(256))]
        return f"sbox-indexed (s,2s,4s,6s) perm i^={rot}: {hits or 'FAIL'}"
    if name.startswith("algo09_tbl5"):
        v = struct.unpack("<256I", b)
        hits = [tag for tag, f in
                (("int%256", lambda x: (x, 2 * x % 256, 6 * x % 256, 8 * x % 256)),
                 ("gf", lambda x: (x, gmul(x, 2), gmul(x, 6), gmul(x, 8))))
                if all(v[x].to_bytes(4, "little") == bytes(f(x)) for x in range(256))]
        return f"x-indexed (x,2x,6x,8x): {hits or 'FAIL'}"
    if name.startswith("algo09_rcon"):
        v = struct.unpack("<16I", b)
        return "u32[16]: " + " ".join(f"{x:08x}" for x in v)
    if name.startswith("algo11"):
        v = struct.unpack("<2048Q", b)
        zero_idx = [i for i in range(2048) if v[i] == 0]
        return f"u64[2048], zeros at {zero_idx[:4]}"
    return "raw"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = EXE.read_bytes()
    for name, off, size in TABLES:
        o = rva2off(BLOB_BASE + off)
        blob = data[o:o + size]
        p = OUT / name
        p.write_bytes(blob)
        print(f"{name:34} {size:6d} B -> {p}")
        print(f"{'':34} {check(name, blob)}")
    o = rva2off(C_RVA)
    c = data[o:o + 72]
    (OUT / "algo11_c.bin").write_bytes(c)
    print(f"{'algo11_c.bin':34} {72:6d} B  (rva {C_RVA:#x})")
    print(f"{'':34} " + " ".join(f"{x:016x}" for x in struct.unpack("<9Q", c)))
    kb = (OUT / "channelinfo_key_blob.bin").read_bytes()
    print("\nchannelinfo_key_blob.bin:")
    for i in range(0, len(kb), 16):
        c = kb[i:i + 16]
        print("  %3d  %s  %s" % (i, " ".join(f"{b:02x}" for b in c),
                                 "".join(chr(b) if 32 <= b < 127 else "." for b in c)))
    prints = bytes(x for x in kb if 32 <= x < 127)
    print(f"printable bytes: {len(prints)} -> {prints[:80]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
