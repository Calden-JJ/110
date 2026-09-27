#!/usr/bin/env python3
"""Decompose [7:11] / [11:15] into a shared top-byte tag + low-24 payloads.

Byte [7] == byte [11] in every one of the 61 S->C game dumps, which cannot be
chance.  The exe metadata names include `MakeChecksumToOneByte` next to
`MakeHash` / `MakeHashForSending`, so the natural reading is: the 16-byte header
carries an 8-byte "hash area" that is really two 32-bit words sharing a tag
byte.  This prints the decomposition and tests the cheap structural
hypotheses -- is the tag a function of the body, is either low-24 a counter,
does the tag track the length.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_s2c_hdr import s2c_frames, u32be  # noqa: E402


def main() -> int:
    rows = [r for r in s2c_frames() if not r[7]]
    print(f"{len(rows)} clean frames\n")

    hdr = (f"{'line':>5} {'opcode':>10} {'blen':>5} {'plen':>5} "
           f"{'tag':>4} {'A24':>8} {'B24':>8} {'B-A24':>8}")
    print(hdr)
    print("-" * len(hdr))

    tags: dict[int, list[int]] = {}
    a24s: list[int] = []
    b24s: list[int] = []
    rows_out = []
    for line, ts, conn, op, hd, body, pl, trunc in rows:
        a = u32be(hd[7:11])
        b = u32be(hd[11:15])
        tag, a24, b24 = hd[7], a & 0xFFFFFF, b & 0xFFFFFF
        assert hd[7] == hd[11], f"line {line}: tag bytes differ"
        tags.setdefault(tag, []).append(line)
        a24s.append(a24)
        b24s.append(b24)
        rows_out.append((line, op, body, pl, tag, a24, b24))
        print(f"{line:>5} {str(op):>10} {len(body):>5} "
              f"{(len(pl) if pl is not None else -1):>5} "
              f"{tag:>4x} {a24:>8x} {b24:>8x} {(b24 - a24) & 0xFFFFFF:>8x}")

    print(f"\ndistinct tags: {len(tags)} -> "
          + ", ".join(f"{t:02x}({len(v)})" for t, v in sorted(tags.items())))

    # (a) is the tag a function of the body?
    print("\n-- tag vs simple body statistics --")
    for name, fn in (
        ("len(ct)&ff", lambda b, p: len(b) & 0xFF),
        ("len(ct)+len(pt)&ff", lambda b, p: (len(b) + len(p or b)) & 0xFF),
        ("sum(ct)&ff", lambda b, p: sum(b) & 0xFF),
        ("xor(ct)", lambda b, p: _xorfold(b)),
        ("crc32>>24", lambda b, p: (__import__("zlib").crc32(b) & 0xFFFFFFFF) >> 24),
        ("crc32&ff", lambda b, p: __import__("zlib").crc32(b) & 0xFF),
        ("sum(pt)&ff", lambda b, p: sum(p) & 0xFF if p is not None else None),
    ):
        hit = tot = 0
        for line, op, body, pl, tag, a24, b24 in rows_out:
            v = fn(body, pl)
            if v is None:
                continue
            tot += 1
            hit += v == tag
        print(f"  {name:<20} {hit}/{tot}")

    # (b) counter?  low-24 monotone in capture order, or unique?
    print("\n-- counters? --")
    for label, vals in (("A24", a24s), ("B24", b24s)):
        ups = sum(1 for i in range(1, len(vals)) if vals[i] > vals[i - 1])
        print(f"  {label}: unique {len(set(vals))}/{len(vals)}  "
              f"ascending steps {ups}/{len(vals) - 1}  "
              f"min {min(vals):06x} max {max(vals):06x}")

    # (c) does the tag byte appear anywhere else in the header/body?
    print("\n-- tag occurrences elsewhere in the frame --")
    in_body = in_hdr = 0
    for line, op, body, pl, tag, a24, b24 in rows_out:
        in_body += body.count(bytes([tag]))
        in_hdr += 0
    print(f"  tag byte in ciphertext: {in_body} time(s) "
          f"over {sum(len(r[2]) for r in rows_out)} bytes "
          f"(expected ~{sum(len(r[2]) for r in rows_out) / 256:.1f} by chance)")
    return 0


def _xorfold(b: bytes) -> int:
    v = 0
    for c in b:
        v ^= c
    return v


if __name__ == "__main__":
    raise SystemExit(main())
