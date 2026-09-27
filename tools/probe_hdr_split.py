#!/usr/bin/env python3
"""Test the 24-bit hypothesis: hash(body) split into a tag byte + low 24 bits.

Byte [7] == byte [11] in all 61 S->C dumps and equals a *body-derived* byte
(identical bodies give identical tags), while the low 24 bits of [11:15] vary
per send.  The empty-body frame 6515 has A24 = 0 exactly -- which is what an
unfinalised CRC (init 0, no xorout) gives for an empty input, and what a
plain additive checksum gives too.  If [7:11] is really a 32-bit hash written
big-endian and [11:15] is `(same hash's top byte) | (per-send 24 bits)`, then
a full-word comparison would miss it: only 24 bits would have to match.

So this scores every hash on
    (a) v & 0xFFFFFF  == A24          (low 24 bits)
    (b) v >> 24       == tag          (top byte)
    (c) both at once, over ct and pt, over every input form.
"""
from __future__ import annotations

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_hdr_forms import HASHES, forms  # noqa: E402
from probe_s2c_hdr import s2c_frames, u32be  # noqa: E402


def main() -> int:
    rows = [r for r in s2c_frames() if not r[7]]
    nform = len(forms(b"\x00" * 16, b"x"))
    print(f"{len(rows)} frames, {nform} forms x {len(HASHES)} hashes x ct/pt\n")

    low = {}   # (form, hash, src) -> hits on A24
    top = {}   # (form, hash, src) -> hits on tag
    both = {}
    for line, ts, conn, op, hd, body, pl, trunc in rows:
        tag = hd[7]
        a24 = u32be(hd[7:11]) & 0xFFFFFF
        for src, raw in (("ct", body), ("pt", pl)):
            if raw is None:
                continue
            for fname, data in forms(hd, raw):
                for hname, fn in HASHES:
                    v = fn(data)
                    k = (fname, hname, src)
                    if (v & 0xFFFFFF) == a24:
                        low[k] = low.get(k, 0) + 1
                    if (v >> 24) == tag:
                        top[k] = top.get(k, 0) + 1
                    if (v & 0xFFFFFF) == a24 and (v >> 24) == tag:
                        both[k] = both.get(k, 0) + 1

    # chance baselines
    chance_low = 1 / (1 << 24)
    chance_top = 1 / 256
    print(f"-- low-24 exact (chance ~{chance_low:.2e} per attempt, "
          f"{len(rows) * nform * len(HASHES) * 2} attempts) --")
    for k, n in sorted(low.items(), key=lambda kv: -kv[1])[:15]:
        print(f"  {k[0]:<18} {k[1]:<10} {k[2]}  {n}")
    if not low:
        print("  none")

    print(f"\n-- tag byte exact (chance ~{chance_top:.4f} per attempt) --")
    ranked = sorted(top.items(), key=lambda kv: -kv[1])[:15]
    for k, n in ranked:
        print(f"  {k[0]:<18} {k[1]:<10} {k[2]}  {n}/{len(rows)}")
    if not ranked:
        print("  none")

    print(f"\n-- both --")
    for k, n in sorted(both.items(), key=lambda kv: -kv[1])[:10]:
        print(f"  {k[0]:<18} {k[1]:<10} {k[2]}  {n}")
    if not both:
        print("  none")

    # direct: is the tag byte a simple function of the body at all?
    print("\n-- tag vs single-byte body statistics --")
    for name, fn in (
        ("sum(ct)&ff", lambda b, p: sum(b) & 0xFF),
        ("xor(ct)", lambda b, p: _xor(b)),
        ("len(ct)&ff", lambda b, p: len(b) & 0xFF),
        ("sum(pt)&ff", lambda b, p: None if p is None else sum(p) & 0xFF),
        ("xor(pt)", lambda b, p: None if p is None else _xor(p)),
        ("last(ct)", lambda b, p: b[-1] if b else None),
        ("first(ct)", lambda b, p: b[0] if b else None),
    ):
        hit = tot = 0
        for line, ts, conn, op, hd, body, pl, trunc in rows:
            v = fn(body, pl)
            if v is None:
                continue
            tot += 1
            hit += v == hd[7]
        print(f"  {name:<14} {hit}/{tot}")
    return 0


def _xor(b: bytes) -> int:
    v = 0
    for c in b:
        v ^= c
    return v


if __name__ == "__main__":
    raise SystemExit(main())
