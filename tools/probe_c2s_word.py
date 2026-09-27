#!/usr/bin/env python3
"""C->S [7:11] = hash of the body with the sequence counter folded in?

`probe_c2s_hdr` showed the C->S word is *not* a function of the body alone:
18 bodies were sent more than once and each send has a different word, with a
u16le counter at [11:13] incrementing by one every packet.  So the input is
likely (body, counter) in some arrangement -- counter appended or prefixed, as
u16le/u16be/u32, or as the hash seed.  The 221 frames make this a much stronger
test than the 57 S->C samples, and whatever function fits here is the same one
`MakeHashForSending` uses on the S->C side.
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
from probe_hdr_forms import HASHES  # noqa: E402
from probe_s2c_hdr import u32be  # noqa: E402


def forms(hd: bytes, body: bytes, ctr: int, wire: int):
    c16le = struct.pack("<H", ctr)
    c16be = struct.pack(">H", ctr)
    c32le = struct.pack("<I", ctr)
    c32be = struct.pack(">I", ctr)
    le, be = hd[3:7], hd[3:7][::-1]
    w_le, w_be = struct.pack("<I", wire), struct.pack(">I", wire)
    z4 = b"\x00" * 4
    return [
        ("body", body),
        ("body+c16le", body + c16le),
        ("body+c16be", body + c16be),
        ("body+c32le", body + c32le),
        ("body+c32be", body + c32be),
        ("c16le+body", c16le + body),
        ("c16be+body", c16be + body),
        ("c32le+body", c32le + body),
        ("c32be+body", c32be + body),
        ("le+body", le + body),
        ("body+le", body + le),
        ("z4+body", z4 + body),
        ("hdrA0+body", hd[0:7] + z4 + hd[11:13] + body),
        ("hdr[0:7]+z6+body", hd[0:7] + b"\x00" * 6 + body),
        ("hdr[0:11]+body", hd[0:11] + body),
        ("w_le+body", w_le + body),
        ("w_be+body", w_be + body),
        ("wirele+body", struct.pack("<I", wire + len(body)) + body),
    ]


SEEDED = [
    ("xxh32(seed=ctr)", lambda d, c: __import__("probe_s2c_hdr").xxh32(d, c)),
    ("murmur3(seed=ctr)", lambda d, c: __import__("probe_s2c_hdr").murmur3(d, c)),
]


def main() -> int:
    rows = [r for r in c2s_frames() if not r[7]]
    print(f"{len(rows)} C->S frames\n")

    hits: dict[tuple[str, str, str], int] = {}
    for line, ts, conn, op, hd, body, ctr, tr in rows:
        wire = u32be(hd[3:7][::-1]) & 0xFFFFFFFF  # [3:7] is u32le
        wire = struct.unpack("<I", hd[3:7])[0]
        for src, raw in (("ct", body), ("pt", plaintext(op, body))):
            if raw is None:
                continue
            fs = forms(hd, raw, ctr, wire)
            for fname, data in fs:
                for hname, fn in HASHES:
                    if fn(data) == u32be(hd[7:11]):
                        hits[(fname, hname, src)] = hits.get((fname, hname, src), 0) + 1
            for hname, fn in SEEDED:
                if fn(raw, ctr) == u32be(hd[7:11]):
                    hits[(fname, hname, src)] = hits.get((fname, hname, src), 0) + 1

    # also the seeded variants over every form
    for line, ts, conn, op, hd, body, ctr, tr in rows:
        for src, raw in (("ct", body), ("pt", plaintext(op, body))):
            if raw is None:
                continue
            for fname, data in forms(hd, raw, ctr, 0):
                for hname, fn in SEEDED:
                    if fn(data, ctr) == u32be(hd[7:11]):
                        k = (fname, hname + "(seed=ctr)", src)
                        hits[k] = hits.get(k, 0) + 1

    if not hits:
        print("no match on any (form, hash) -- counter is not folded in as an "
              "appendix/prefix/seed of these families")
        return 0
    print("-- partial scorers --")
    for (fname, hname, src), n in sorted(hits.items(), key=lambda kv: -kv[1]):
        print(f"  {fname:<18} {hname:<12} {src} {n}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
