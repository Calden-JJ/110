#!/usr/bin/env python3
"""Characterise the game-s2c header words at [7:11] and [11:15].

Both are big-endian u32s that always share their top byte.  Two frames with
byte-identical bodies (6521 `(0,2318)` / 6538 `(1,666)`) share [7:11] but not
[11:15], so [7:11] is a function of the body (or its plaintext) while [11:15]
is something else.  This dumps every S->C game frame so the two can be told
apart, and tests [7:11] against standard 32-bit hashes of the ciphertext *and*
of the plaintext (the tiles are all resolved now, so the plaintext is
available -- the earlier brute force only had the ciphertext).
"""
from __future__ import annotations

import re
import struct
import sys
import zlib
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles as T  # noqa: E402

LOG = paths.LOGS_DIR / "server-20260926.log"

LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) \+\d\d:\d\d (\w+)\s+(\S+)\s+(.*)$")
PKT_RE = re.compile(r"conn=(\d+)\s+(C->S|S->C)\s+(game|channel)\b")
HEX_RE = re.compile(r"\bhex=([0-9a-fA-F]+)")


def plaintext(op, body: bytes) -> bytes | None:
    tile = op.sub % T.ALGO_COUNT
    bs = T.TILES[tile][2]
    if not body or (bs != 4 and len(body) % bs):
        return None
    return T.decrypt_body(tile, body)


def s2c_frames():
    """One tuple per `DEBUG PACKET` S->C game dump:

    `(line_no, hh:mm:ss.mmm, conn, opcode, hdr, body, plain, truncated)`.
    `hdr` is the 16 raw header bytes, `plain` the tile-decrypted body or None.
    """
    with open(LOG, encoding="utf-8", errors="replace") as f:
        for i, ln in enumerate(f, 1):
            m = LINE_RE.match(ln)
            if not m:
                continue
            ts, lvl, tag, msg = m.groups()
            if lvl != "DEBUG" or tag != "PACKET":
                continue
            m2 = PKT_RE.search(msg)
            if not m2 or m2.group(2) != "S->C" or m2.group(3) != "game":
                continue
            hm = HEX_RE.search(msg)
            if not hm:
                continue
            raw = bytes.fromhex(hm.group(1))
            try:
                fr = frame.parse(frame.Link.GAME_S2C, raw, strict=False)
            except frame.ProtocolError:
                continue
            yield (i, ts[11:], int(m2.group(1)), fr.opcode, raw[:16],
                   fr.body, plaintext(fr.opcode, fr.body), "(+" in msg)


def u32be(b: bytes) -> int:
    return struct.unpack(">I", b)[0]


# ---------------------------------------------------------------- hashes

def fnv1a(d: bytes) -> int:
    h = 0x811C9DC5
    for c in d:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h


def djb2(d: bytes) -> int:
    h = 5381
    for c in d:
        h = ((h * 33) + c) & 0xFFFFFFFF
    return h


def sdbm(d: bytes) -> int:
    h = 0
    for c in d:
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def sum4le(d: bytes) -> int:
    n = len(d) // 4 * 4
    return sum(struct.unpack("<%dI" % (n // 4), d[:n])) & 0xFFFFFFFF


def sum4be(d: bytes) -> int:
    n = len(d) // 4 * 4
    return sum(struct.unpack(">%dI" % (n // 4), d[:n])) & 0xFFFFFFFF


def rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def xxh32(d: bytes, seed: int = 0) -> int:
    P1, P2, P3, P4, P5 = (0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D,
                          0x27D4EB2F, 0x165667B1)
    M = 0xFFFFFFFF
    n, i = len(d), 0
    if n >= 16:
        v = [(seed + P1 + P2) & M, (seed + P2) & M, seed & M, (seed - P1) & M]
        while i + 16 <= n:
            for j in range(4):
                lane = struct.unpack_from("<I", d, i + 4 * j)[0]
                v[j] = (rotl((v[j] + lane * P2) & M, 13) * P1) & M
            i += 16
        h = sum(rotl(v[j], (1, 7, 12, 18)[j]) for j in range(4)) & M
    else:
        h = (seed + P5) & M
    h = (h + n) & M
    while i + 4 <= n:
        h = (rotl((h + struct.unpack_from("<I", d, i)[0] * P3) & M, 17) * P4) & M
        i += 4
    while i < n:
        h = (rotl((h + d[i] * P5) & M, 11) * P1) & M
        i += 1
    h ^= h >> 15
    h = (h * P2) & M
    h ^= h >> 13
    h = (h * P3) & M
    h ^= h >> 16
    return h


def murmur3(d: bytes, seed: int = 0) -> int:
    M = 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h, n, i = seed, len(d), 0
    while i + 4 <= n:
        k = struct.unpack_from("<I", d, i)[0]
        k = (rotl((k * c1) & M, 15) * c2) & M
        h ^= k
        h = (rotl(h, 13) * 5 + 0xE6546B64) & M
        i += 4
    k = 0
    for j in range(n - i - 1, -1, -1):
        k = (k << 8) | d[i + j]
    if n - i:
        k = (rotl((k * c1) & M, 15) * c2) & M
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & M
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & M
    h ^= h >> 16
    return h


HASHES = [
    ("crc32", lambda d: zlib.crc32(d) & 0xFFFFFFFF),
    ("adler32", lambda d: zlib.adler32(d) & 0xFFFFFFFF),
    ("fnv1a", fnv1a), ("djb2", djb2), ("sdbm", sdbm),
    ("sum4le", sum4le), ("sum4be", sum4be),
    ("xxh32", xxh32), ("murmur3", murmur3),
]


def main() -> int:
    rows = list(s2c_frames())
    hdr = (f"{'line':>5} {'time':>12} {'cn':>2} {'opcode':>10} {'len':>5} "
           f"{'[7:11]':>8} {'[11:15]':>8} {'b7==b11':>7} plain")
    print(f"{len(rows)} S->C game dumps\n{hdr}\n{'-' * len(hdr)}")

    seen7: dict[int, set] = {}
    bodies: dict[bytes, set] = {}
    conns: dict[int, set] = {}
    for line, ts, conn, op, hd, body, pl, trunc in rows:
        h7, h11 = u32be(hd[7:11]), u32be(hd[11:15])
        seen7.setdefault(h7, set()).add(body)
        bodies.setdefault(body, set()).add(h7)
        conns.setdefault(h7, set()).add(conn)
        pz = "-" if pl is None else f"{pl.count(0)}/{len(pl)}z"
        flag = "yes" if hd[7] == hd[11] else "NO"
        print(f"{line:>5} {ts:>12} {conn:>2} {str(op):>10} {len(body):>5} "
              f"{h7:>8x} {h11:>8x} {flag:>7} {pz}")

    print(f"\ndistinct [7:11]: {len(seen7)}  distinct bodies: {len(bodies)}  "
          f"frames: {len(rows)}")
    multi = {h: v for h, v in seen7.items() if len(v) > 1}
    print(f"[7:11] seen with >1 distinct body: {len(multi)}")
    for h, v in list(multi.items())[:8]:
        print(f"   {h:08x} on {len(v)} bodies, conns {sorted(conns[h])}")
    bad = {b: h for b, h in bodies.items() if len(h) > 1}
    print(f"bodies with >1 distinct [7:11]: {len(bad)}")

    print("\n-- [7:11] vs standard hashes (ciphertext / plaintext) --")
    cands = [r for r in rows if not r[7]]
    for name, fn in HASHES:
        for what in ("ct", "pt"):
            hit = tot = 0
            for line, ts, conn, op, hd, body, pl, trunc in cands:
                d = body if what == "ct" else pl
                if d is None or not d:
                    continue
                tot += 1
                hit += fn(d) == u32be(hd[7:11])
            if hit:
                print(f"  MATCH {name}({what}) {hit}/{tot}")
    print("  (no MATCH line = none of these fit; inputs tried = body bytes, "
          "plaintext bytes)")

    print("\n-- does [7:11] equal anything computable from the header? --")
    n_op = n_conn = n_len = 0
    for line, ts, conn, op, hd, body, pl, trunc in cands:
        h7 = u32be(hd[7:11])
        n_op += h7 == (op.main << 8 | op.sub) or h7 == op.sub
        n_conn += h7 in (conn, conn << 24)
        n_len += h7 == len(body) or h7 == len(body) + 16
    print(f"  == opcode: {n_op}   == conn: {n_conn}   == len: {n_len}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
