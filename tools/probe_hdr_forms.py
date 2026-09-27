#!/usr/bin/env python3
"""Brute-force (input form x hash) for the S->C header words.

`probe_s2c_hdr` proved [7:11] is a deterministic function of the frame body
(57 distinct bodies -> 57 distinct values; four independent groups of
byte-identical bodies all give byte-identical values, and it ignores the
opcode).  The single empty-body frame (line 6515, opcode (0,124)) pins the
function at "" -> 0x18000000, which no unseeded standard hash of "" produces.

That leaves two axes: the *input* may not be the bare body, and the *function*
may be one of the server's own (`MakeHash`, `SuperFastHash`, `Crc32` are the
names in the packet class's metadata).  A frame's header is mostly determined
by the opcode and length, so the plausible inputs are the body with some
mixture of the length field and the zeroed hash field around it.  Since the
empty-body frame's form is short and fully known, it sieves the matrix cheaply.
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

from probe_s2c_hdr import (  # noqa: E402
    djb2, fnv1a, murmur3, s2c_frames, sdbm, sum4be, sum4le, u32be, xxh32,
)
from probe_sfhash import sfh  # noqa: E402


def jenkins_oat(d: bytes) -> int:
    h = 0
    for c in d:
        h = (h + c) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= h >> 6
    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= h >> 11
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h


def elf(d: bytes) -> int:
    h = 0
    for c in d:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h


def xor4(d: bytes) -> int:
    v = 0
    for i in range(0, len(d) // 4 * 4, 4):
        v ^= struct.unpack_from("<I", d, i)[0]
    for b in d[len(d) // 4 * 4:]:
        v ^= b
    return v & 0xFFFFFFFF


HASHES = [
    ("crc32", lambda d: zlib.crc32(d) & 0xFFFFFFFF),
    ("crc32-init0", lambda d: _crc_init0(d)),
    ("adler32", lambda d: zlib.adler32(d) & 0xFFFFFFFF),
    ("sfh", sfh),
    ("sfh0", lambda d: sfh(d, 0)),
    ("fnv1a", fnv1a),
    ("djb2", djb2),
    ("sdbm", sdbm),
    ("jenkins", jenkins_oat),
    ("elf", elf),
    ("sum4le", sum4le),
    ("sum4be", sum4be),
    ("xor4", xor4),
    ("xxh32", xxh32),
    ("murmur3", murmur3),
]


def _crc_init0(d: bytes) -> int:
    crc = 0
    for b in d:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return crc & 0xFFFFFFFF


def forms(hd: bytes, body: bytes):
    """Candidate byte strings a body-hash might actually be fed.

    `hdr[0:3] + body` is excluded up front: frames 6521 and 6538 have the same
    body and the same [7:11] but different `main`/`sub`.  `len` is not excluded
    that way (both frames are 24 bytes on the wire), so forms that fold it in
    stay in the matrix, including with the hash field zeroed -- a self-hashing
    checksum has to zero its own slot.
    """
    le, be = hd[3:7], hd[3:7][::-1]
    z9 = b"\x00" * 9
    bl_le = struct.pack("<I", len(body))
    bl_be = struct.pack(">I", len(body))
    return [
        ("body", body),
        ("le+body", le + body),
        ("be+body", be + body),
        ("bodylen_le+body", bl_le + body),
        ("bodylen_be+body", bl_be + body),
        ("z9+body", z9 + body),
        ("le+z9+body", le + z9 + body),
        ("body+le", body + le),
        ("body+z9", body + z9),
        ("hdr[0:7]+body", hd[0:7] + body),
        ("hdr[0:7]+z9+body", hd[0:7] + z9 + body),
        ("hdr[3:16]+body", hd[3:16] + body),
        ("z7+body", b"\x00" * 7 + body),
        ("z4+body", b"\x00" * 4 + body),
        ("le+body+le", le + body + le),
        ("hdr[3:8]+body", hd[3:8] + body),
        ("sub2le+body", hd[1:3] + body),
        ("sub2be+body", hd[1:3][::-1] + body),
        ("main+sub+body", hd[0:3] + body),
        # padding: the body may be hashed on a block-aligned buffer before
        # the wire copy truncates it (the empty frame then hashes zeros, not "").
        ("pad4", body + b"\x00" * (-len(body) % 4)),
        ("pad8", body + b"\x00" * (-len(body) % 8)),
        ("pad16", body + b"\x00" * (-len(body) % 16)),
        ("pad32", body + b"\x00" * (-len(body) % 32)),
        ("iso7816pad", body + b"\x80" + b"\x00" * ((-len(body) - 1) % 16)),
        ("pkcs7pad16", body + bytes([16 - len(body) % 16]) * (16 - len(body) % 16)),
        ("revbody", body[::-1]),
        # wire length (header included / excluded) rather than body length
        ("wirele+body", struct.pack("<I", 16 + len(body)) + body),
        ("wirebe+body", struct.pack(">I", 16 + len(body)) + body),
        # self-hashing checksum: only *its own* word zeroed, not both
        ("hdrA0+body", hd[0:7] + b"\x00" * 4 + hd[11:16] + body),
        ("hdrB0+body", hd[0:11] + b"\x00" * 4 + hd[15:16] + body),
    ]


def main() -> int:
    rows = [r for r in s2c_frames() if not r[7]]
    print(f"{len(rows)} clean frames\n")

    hits: dict[tuple[str, str, str, str], list[int]] = {}
    nform = len(forms(b"\x00" * 16, b"x"))
    for line, ts, conn, op, hd, body, pl, trunc in rows:
        for src, raw in (("ct", body), ("pt", pl)):
            if raw is None:
                continue
            for fname, data in forms(hd, raw):
                for hname, fn in HASHES:
                    v = fn(data)
                    if v == u32be(hd[7:11]):
                        hits.setdefault((fname, hname, "[7:11]", src),
                                        []).append(line)
                    if v == u32be(hd[11:15]):
                        hits.setdefault((fname, hname, "[11:15]", src),
                                        []).append(line)

    print(f"{nform} forms x {len(HASHES)} hashes x ct/pt = "
          f"{nform * len(HASHES) * 2} configs")
    if not hits:
        print("no (form, hash) pair matched any frame")
        return 0
    print("-- matches --")
    for key, lines in sorted(hits.items(), key=lambda kv: -len(kv[1])):
        fname, hname, word, src = key
        print(f"  {fname:<14} {hname:<12} {word:<8} {src} {len(lines)} frame(s): "
              f"{lines[:8]}")

    # Which forms are *excluded outright*: the empty-body frame is the filter.
    empty = [r for r in rows if not r[5]]
    if empty:
        line, ts, conn, op, hd, body, pl, trunc = empty[0]
        print(f"\n-- the empty-body frame (line {line}) rules out every pair "
              f"not listed above: [7:11]={u32be(hd[7:11]):08x} "
              f"[11:15]={u32be(hd[11:15]):08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
