#!/usr/bin/env python3
"""Byte-position analysis of the C->S [7:11] word, now that S->C is known.

The S->C builder (0x5814b0) writes `tag(crc32(body))` into [7:11] and
`(nonce24 << 8) | lowbyte(tag)` into [11:15] -- both little-endian.  The C->S
word cannot be the first of those (18 bodies repeat with different words), but
it may well be the *second*: `(nonce24 << 8) | body-pure byte`.  That predicts
(a) one fixed byte position per body group, and (b) a zero byte at the top of
the 24-bit nonce if the word is read little-endian.

So: group the 221 frames by body, and for each of the 4 byte positions count
how many groups have a constant value there.  Also check for any byte that is
constant across the whole capture, and for the reverse (big-endian) reading.
"""
from __future__ import annotations

import struct
import sys
from collections import defaultdict
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_c2s_hdr import c2s_frames, plaintext  # noqa: E402


def main() -> int:
    rows = [r for r in c2s_frames() if not r[7]]
    print(f"{len(rows)} C->S frames\n")

    # any byte constant across the whole capture?
    print("-- per-offset distinct count over all frames --")
    for k, nm in ((7, "[7]"), (8, "[8]"), (9, "[9]"), (10, "[10]"),
                  (11, "[11]lo"), (12, "[12]hi")):
        vals = {r[4][k] for r in rows}
        print(f"  {nm:<8} {len(vals)} distinct"
              + (f"  constant = {vals.pop():#04x}" if len(vals) == 1 else ""))

    # group by body: is any word byte body-pure?
    groups = defaultdict(list)
    for r in rows:
        groups[r[5]].append(r)
    multi = {b: rs for b, rs in groups.items() if len(rs) > 1}
    print(f"\n-- {len(groups)} distinct bodies, {len(multi)} sent more than once --")
    print("   (for a body-pure byte, every repeat must agree)")
    for off in (7, 8, 9, 10):
        ok = sum(len({r[4][off] for r in rs}) == 1 for rs in multi.values())
        # also with the counter factored out: value ^ counter?
        ok2 = sum(len({r[4][off] ^ r[6] for r in rs}) == 1 for rs in multi.values())
        print(f"  byte[{off}]: constant in {ok}/{len(multi)} groups; "
              f"xor-counter-constant {ok2}/{len(multi)}")
    # high byte pair
    ok3 = sum(len({struct.unpack('>H', r[4][8:10])[0] for r in rs}) == 1
              for rs in multi.values())
    print(f"  bytes[8:10] u16be: constant in {ok3}/{len(multi)} groups")

    # show a couple of multi-send groups in full
    print("\n-- sample multi-send groups --")
    for b, rs in sorted(multi.items(), key=lambda kv: -len(kv[1]))[:3]:
        print(f"  body len {len(b)} sent {len(rs)}x:")
        for r in rs[:6]:
            w = r[4][7:11]
            print(f"    line {r[0]} ctr={r[6]:<4} word={w.hex()} "
                  f"be={struct.unpack('>I', w)[0]:#010x}")

    # empty-body C->S frames?
    empt = [r for r in rows if not r[5]]
    print(f"\n  empty-body C->S frames: {len(empt)}")
    for r in empt[:4]:
        print(f"    line {r[0]} word={r[4][7:11].hex()} ctr={r[6]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
