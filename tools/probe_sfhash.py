#!/usr/bin/env python3
"""Test Paul Hsieh's SuperFastHash and CRC32 variants on the header words.

`scan_hash_consts` found the server's packet class in the exe's metadata string
heap: `MakeHashForSending`, `MakeHash`, `SuperFastHash`, `MakeChecksumToOneByte`,
`Crc32` + `BuildTable` (plus `BuildChannelInfoPacket` and
`FromChannelInfoPlaintext` from the CHANNELINFO work).  So the S->C header word
is produced by one of those, not by a stdlib hash -- which is why the 11
standard functions all missed.

SuperFastHash is the one worth writing out by hand (Hsieh's reference C, with
the `len <= 0 -> 0` guard and the signed-char tail cases).  `Crc32`+`BuildTable`
suggests a hand-rolled table CRC, so its init/xorout/reflection are swept too.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from probe_s2c_hdr import HASHES, s2c_frames  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402

M32 = 0xFFFFFFFF


def sfh(d: bytes, seed: int | None = None) -> int:
    """Paul Hsieh's SuperFastHash; `seed=None` uses the reference `hash = len`."""
    n = len(d)
    if n <= 0:
        return 0
    h = n if seed is None else seed
    rem = n & 3
    blocks = n >> 2
    p = 0
    for _ in range(blocks):
        h = (h + (d[p] | d[p + 1] << 8)) & M32
        tmp = ((d[p + 2] | d[p + 3] << 8) << 11) ^ h
        h = ((h << 16) ^ tmp) & M32
        p += 4
        h = (h + (h >> 11)) & M32
    if rem == 3:
        h = (h + (d[p] | d[p + 1] << 8)) & M32
        h ^= (h << 16) & M32
        h ^= (struct.unpack("b", d[p + 2:p + 3])[0] << 18) & M32
        h = (h + (h >> 11)) & M32
    elif rem == 2:
        h = (h + (d[p] | d[p + 1] << 8)) & M32
        h ^= (h << 11) & M32
        h = (h + (h >> 17)) & M32
    elif rem == 1:
        h = (h + struct.unpack("b", d[p:p + 1])[0]) & M32
        h ^= (h << 10) & M32
        h = (h + (h >> 1)) & M32
    h ^= (h << 3) & M32
    h = (h + (h >> 5)) & M32
    h ^= (h << 4) & M32
    h = (h + (h >> 17)) & M32
    h ^= (h << 25) & M32
    h = (h + (h >> 6)) & M32
    return h


def crc32_gen(d: bytes, poly: int, init: int, refin: bool, refout: bool,
              xorout: int) -> int:
    def rev8(v):
        v = ((v & 0x0F) << 4) | (v >> 4)
        v = ((v & 0x33) << 2) | ((v >> 2) & 0x33)
        return ((v & 0x55) << 1) | ((v >> 1) & 0x55)

    def rev32(v):
        return int(f"{v:032b}"[::-1], 2)

    crc = init
    if refin:
        for b in d:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ (poly & M32 if crc & 1 else 0)
            crc &= M32
    else:
        for b in d:
            crc ^= b << 24
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & M32 if crc & 0x80000000 else (crc << 1) & M32
    if refin != refout:
        crc = rev32(crc)
    return (crc ^ xorout) & M32


def main() -> int:
    rows = [r for r in s2c_frames() if not r[7]]

    # hypotheses: name -> fn(body)->int  for [7:11] and for [11:15]
    HYPS: list[tuple[str, object]] = [
        ("sfh(len-seed)", sfh),
        ("sfh(seed=0)", lambda d: sfh(d, 0)),
        ("sfh(seed=1)", lambda d: sfh(d, 1)),
    ]
    for poly_name, poly in (("E", 0xEDB88320), ("C", 0x82F63B78), ("K", 0xEB31D82E)):
        for init in (0, M32):
            for io in ((True, True), (False, False)):
                for xo in (0, M32):
                    nm = f"crc32{poly_name} i{init:02x} r{int(io[0])} x{xo:02x}"
                    HYPS.append((nm, (lambda d, p=poly, i=init, r=io[0], x=xo:
                                      crc32_gen(d, p, i, r, r, x))))

    print(f"{len(rows)} clean frames; testing {len(HYPS)} hypotheses "
          f"against both header words, body and plaintext\n")
    for name, fn in HYPS:
        for what in ("ct", "pt"):
            h7 = h11 = tot = 0
            for line, ts, conn, op, hd, body, pl, trunc in rows:
                d = body if what == "ct" else pl
                if not d:
                    continue
                tot += 1
                v = fn(d)
                h7 += v == struct.unpack(">I", hd[7:11])[0]
                h11 += v == struct.unpack(">I", hd[11:15])[0]
            if h7 or h11:
                print(f"  {name:<22} {what}: [7:11] {h7}/{tot}  [11:15] {h11}/{tot}")
    print("\n(only non-zero scorers are printed)")

    # the one-byte checksum angle: maybe [7] and [11] are the same byte
    print("\n-- one-byte f(old) of the body vs byte[7] --")
    for name, fn in (("sfh", sfh), ("crc32", lambda d: zlib.crc32(d) & M32),
                     ("adler32", lambda d: zlib.adler32(d) & M32)):
        for fold_name, fold in (("&ff", lambda v: v & 0xFF),
                                (">>24", lambda v: v >> 24),
                                ("xor4", lambda v: (v ^ v >> 8 ^ v >> 16 ^ v >> 24) & 0xFF),
                                ("sum4", lambda v: (v + (v >> 8) + (v >> 16) + (v >> 24)) & 0xFF)):
            hit = tot = 0
            for line, ts, conn, op, hd, body, pl, trunc in rows:
                for d in (body, pl):
                    if not d:
                        continue
                    tot += 1
                    hit += fold(fn(d)) == hd[7]
            if hit:
                print(f"  {name}/{fold_name}: {hit}/{tot}")
    print("  (no lines = [7] is not a folded whole-body hash either)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
