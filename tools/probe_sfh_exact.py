#!/usr/bin/env python3
"""Score the byte-exact SuperFastHash and the tag-fold relation on both links.

`na_dis.py` on 0x580c80 shows Hsieh's SuperFastHash, but with `movzx` in the
rem==1 and rem==3 tails where the C reference uses `signed char` -- and the
earlier probe used the signed form, which is why it scored zero.  0x580c50 is
a 48-byte leaf that rewrites the low byte of its argument to
`(b0^b1^b2^b3) ^ 0x18`, which is exactly the top-byte-shared structure the
S->C header shows.

So this scores, over every frame on both links:
  (a) sfhu(body) / sfhu(pt)  ==  [7:11]  (and &0xffffff, and >>8)
  (b) tag([7:11])            ==  [11:15]
  (c) tag([11:15])           ==  [7:11]
  (d) [11:15]                ==  [7:11] with low byte replaced by tag(...)
  (e) self-consistency: every header word W satisfies tag(W) == W
      (i.e. W's low byte is already the fold of its top three)
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_c2s_hdr import c2s_frames, plaintext  # noqa: E402
from probe_s2c_hdr import s2c_frames, u32be  # noqa: E402

M32 = 0xFFFFFFFF


def sfhu(d: bytes, seed: int | None = None) -> int:
    """SuperFastHash as compiled at 0x580c80: unsigned tail bytes."""
    n = len(d)
    if n <= 0:
        return 0
    h = n if seed is None else seed
    rem, blocks, p = n & 3, n >> 2, 0
    for _ in range(blocks):
        h = (h + (d[p] | d[p + 1] << 8)) & M32
        tmp = ((d[p + 2] | d[p + 3] << 8) << 11) ^ h
        h = ((h << 16) ^ tmp) & M32
        p += 4
        h = (h + (h >> 11)) & M32
    if rem == 3:
        h = (h + (d[p] | d[p + 1] << 8)) & M32
        h ^= (h << 16) & M32
        h ^= (d[p + 2] << 18) & M32
        h = (h + (h >> 11)) & M32
    elif rem == 2:
        h = (h + (d[p] | d[p + 1] << 8)) & M32
        h ^= (h << 11) & M32
        h = (h + (h >> 17)) & M32
    elif rem == 1:
        h = (h + d[p]) & M32
        h ^= (h << 10) & M32
        h = (h + (h >> 1)) & M32
    h ^= (h << 3) & M32
    h = (h + (h >> 5)) & M32
    h ^= (h << 4) & M32
    h = (h + (h >> 17)) & M32
    h ^= (h << 25) & M32
    h = (h + (h >> 6)) & M32
    return h


def tag(w: int) -> int:
    """0x580c50: keep the top three bytes, low byte <- fold4(w) ^ 0x18."""
    f = (w ^ (w >> 8) ^ (w >> 16) ^ (w >> 24)) & 0xFF
    return (w & 0xFFFFFF00) | (f ^ 0x18)


def main() -> int:
    s2 = [r for r in s2c_frames() if not r[7]]
    c2 = [r for r in c2s_frames() if not r[7]]
    print(f"{len(s2)} S->C frames, {len(c2)} C->S frames\n")

    print("-- S->C: sfhu vs [7:11] --")
    for nm, fn in (("sfhu(ct)", lambda r: sfhu(r[5])),
                   ("sfhu(pt)", lambda r: None if r[6] is None else sfhu(r[6])),
                   ("sfhu(ct,0)", lambda r: sfhu(r[5], 0))):
        full = low = mid = 0
        tot = 0
        for r in s2:
            v = fn(r)
            if v is None:
                continue
            tot += 1
            A = u32be(r[4][7:11])
            full += v == A
            low += (v & 0xFFFFFF) == (A & 0xFFFFFF)
            mid += ((v >> 8) & 0xFFFFFF) == (A & 0xFFFFFF)
        print(f"  {nm:<12} full {full}/{tot}   low24 {low}/{tot}   (v>>8)&24 {mid}/{tot}")

    print("\n-- S->C: tag relations --")
    rel = {"tag(A)==B": 0, "tag(B)==A": 0, "B==tag(A)": 0, "A==tag(B)": 0,
           "tag(A)==A": 0, "tag(B)==B": 0}
    for r in s2:
        A = u32be(r[4][7:11])
        B = u32be(r[4][11:15])
        rel["tag(A)==B"] += tag(A) == B
        rel["tag(B)==A"] += tag(B) == A
        rel["B==tag(A)"] += B == tag(A)
        rel["A==tag(B)"] += A == tag(B)
        rel["tag(A)==A"] += tag(A) == A
        rel["tag(B)==B"] += tag(B) == B
    for k, n in rel.items():
        print(f"  {k:<12} {n}/{len(s2)}")

    print("\n-- C->S: word = [7:11] --")
    rel2 = {"tag(W)==W": 0, "tag(W)==W||tag2": 0}
    for r in c2:
        W = u32be(r[4][7:11])
        rel2["tag(W)==W"] += tag(W) == W
    print(f"  tag(W)==W    {rel2['tag(W)==W']}/{len(c2)}")
    # salt sweep: fold ^ c == low byte?
    cnt = {}
    for r in c2:
        W = u32be(r[4][7:11])
        f = (W ^ (W >> 8) ^ (W >> 16) ^ (W >> 24)) & 0xFF
        cnt[(W & 0xFF) ^ f] = cnt.get((W & 0xFF) ^ f, 0) + 1
    top = sorted(cnt.items(), key=lambda kv: -kv[1])[:6]
    print(f"  low ^ fold histogram (top): " +
          "  ".join(f"{k:#04x}:{v}" for k, v in top))

    print("\n-- C->S: sfhu vs [7:11] --")
    for nm, fn in (("sfhu(ct)", lambda r: sfhu(r[5])),
                   ("sfhu(pt)", lambda r: None if plaintext(r[3], r[5]) is None
                    else sfhu(plaintext(r[3], r[5])))):
        full = low = 0
        tot = 0
        for r in c2:
            v = fn(r)
            if v is None:
                continue
            tot += 1
            W = u32be(r[4][7:11])
            full += v == W
            low += (v & 0xFFFFFF) == (W & 0xFFFFFF)
        print(f"  {nm:<12} full {full}/{tot}   low24 {low}/{tot}")

    # the empty frame, verbatim
    print("\n-- empty-body frames, verbatim --")
    for r in s2:
        if not r[5]:
            A = u32be(r[4][7:11]); B = u32be(r[4][11:15])
            print(f"  S->C line {r[0]} op={r[3]}  A={A:#010x} B={B:#010x} "
                  f"tag(A)={tag(A):#010x} tag(B)={tag(B):#010x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
