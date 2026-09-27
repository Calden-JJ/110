#!/usr/bin/env python3
"""Characterise the C->S game header word [7:11] (the client's counterpart).

The C->S game header is 13 bytes: [0]=1, [1:3]=sub u16le, [3:7]=wire length
u32le, [7:11]=4-byte word, [11:13]=u16le sequence counter that increments by
one per packet for the life of the connection (verified on the 221 logged
dumps).  The S->C header carries two such 4-byte words in 16 bytes, so the
C->S word is the same field the server writes -- characterising the 221
client-side samples is a much bigger corpus than the 57 server-side ones.

First question is structural: is [7:11] a function of the body (as S->C
[7:11] is), or does the counter feed into it?
"""
from __future__ import annotations

import re
import struct
import sys
import zlib
from collections import defaultdict
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_s2c_hdr import (  # noqa: E402
    LINE_RE, LOG, PKT_RE, HEX_RE, fnv1a, djb2, sdbm, sum4le, sum4be,
    xxh32, murmur3, u32be,
)
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles as T  # noqa: E402


def c2s_frames():
    """(line, hh:mm:ss.mmm, conn, opcode, hdr13, body, plain, counter, counter_le)"""
    with open(LOG, encoding="utf-8", errors="replace") as f:
        for i, ln in enumerate(f, 1):
            m = LINE_RE.match(ln)
            if not m:
                continue
            ts, lvl, tag, msg = m.groups()
            if lvl != "DEBUG" or tag != "PACKET":
                continue
            m2 = PKT_RE.search(msg)
            if not m2 or m2.group(2) != "C->S" or m2.group(3) != "game":
                continue
            hm = HEX_RE.search(msg)
            if not hm:
                continue
            raw = bytes.fromhex(hm.group(1))
            try:
                fr = frame.parse(frame.Link.GAME_C2S, raw, strict=False)
            except frame.ProtocolError:
                continue
            counter = struct.unpack("<H", raw[11:13])[0]
            yield (i, ts[11:], int(m2.group(1)), fr.opcode, raw[:13],
                   fr.body, counter, "(+" in msg)


def plaintext(op, body: bytes) -> bytes | None:
    tile = op.sub % T.ALGO_COUNT
    bs = T.TILES[tile][2]
    if not body or (bs != 4 and len(body) % bs):
        return None
    return T.decrypt_body(tile, body)


HASHES = [
    ("crc32", lambda d: zlib.crc32(d) & 0xFFFFFFFF),
    ("adler32", lambda d: zlib.adler32(d) & 0xFFFFFFFF),
    ("fnv1a", fnv1a), ("djb2", djb2), ("sdbm", sdbm),
    ("sum4le", sum4le), ("sum4be", sum4be),
    ("xxh32", xxh32), ("murmur3", murmur3),
]


def main() -> int:
    rows = [r for r in c2s_frames() if not r[7]]
    print(f"{len(rows)} C->S game dumps, all untruncated\n")

    # counter sanity
    conns: dict[int, list[int]] = defaultdict(list)
    for line, ts, conn, op, hd, body, ctr, tr in rows:
        conns[conn].append(ctr)
    for conn, ctrs in conns.items():
        ok = sum(1 for a, b in zip(ctrs, ctrs[1:]) if b > a)
        print(f"conn {conn}: {len(ctrs)} frames, counters {min(ctrs)}..{max(ctrs)}, "
              f"ascending {ok}/{len(ctrs) - 1}, unique {len(set(ctrs))}")

    # body purity: same body -> same [7:11]?
    bybody: dict[bytes, set] = defaultdict(set)
    byword: dict[int, set] = defaultdict(set)
    for line, ts, conn, op, hd, body, ctr, tr in rows:
        w = u32be(hd[7:11])
        bybody[body].add(w)
        byword[w].add(body)
    print(f"\ndistinct bodies {len(bybody)}  distinct [7:11] {len(byword)}  "
          f"frames {len(rows)}")
    multi = {b: w for b, w in bybody.items() if len(w) > 1}
    print(f"bodies with >1 distinct [7:11]: {len(multi)}")
    for b, w in list(multi.items())[:5]:
        print(f"   body {b[:16].hex()}... -> " + ", ".join(f"{x:08x}" for x in w))
    print(f"[7:11] seen on >1 body: {sum(1 for w, b in byword.items() if len(b) > 1)}")

    # is [7:11] the counter in disguise?  or a function of the plaintext?
    print("\n-- [7:11] vs counter / hash of body (ct) / hash of plaintext --")
    for name, fn in HASHES:
        for what in ("ct", "pt"):
            hit = tot = 0
            for line, ts, conn, op, hd, body, ctr, tr in rows:
                d = body if what == "ct" else plaintext(op, body)
                if d is None or not d:
                    continue
                tot += 1
                hit += fn(d) == u32be(hd[7:11])
            if hit:
                print(f"  MATCH {name}({what}) {hit}/{tot}")
    hit = sum(1 for r in rows if r[5] == r[6])
    print(f"  == counter: {hit}/{len(rows)}")

    hdr = (f"\n{'line':>5} {'conn':>4} {'ctr':>5} {'opcode':>10} {'blen':>5} "
           f"{'[7:11]':>8} {'ctr<<24':>8} plain")
    print(hdr)
    for line, ts, conn, op, hd, body, ctr, tr in rows:
        w = u32be(hd[7:11])
        pl = plaintext(op, body)
        pz = "-" if pl is None else f"{pl.count(0)}/{len(pl)}z"
        print(f"{line:>5} {conn:>4} {ctr:>5} {str(op):>10} {len(body):>5} "
              f"{w:>8x} {ctr << 24:>8x} {pz}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
