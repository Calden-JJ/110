#!/usr/bin/env python3
"""Compare bodies that should be related: the (0,23)/(0,24) pairs and dupes.

The S->C dumps contain six `(0,23)` frames with 16-byte bodies and six
`(0,24)` frames with 20-byte bodies, interleaved in time (6511/6512,
6585/6586, 6640/6641, 6660/6661, 6697/6698, 6825/6826) -- if the 20-byte body
is the 16-byte body plus a 4-byte suffix, then A(20) vs A(16) is a
*prefix-extension differential* for the unknown [7:11], which pins the hash
family far better than unrelated samples do.

Also prints the four body groups that repeat verbatim, to re-confirm that the
tag/A24 are body-pure while B24 is not.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_s2c_hdr import s2c_frames, u32be  # noqa: E402


def main() -> int:
    rows = [r for r in s2c_frames() if not r[7]]

    print("-- the (0,23) / (0,24) families --")
    fam: dict[int, list] = defaultdict(list)
    for line, ts, conn, op, hd, body, pl, trunc in rows:
        if op.main == 0 and op.sub in (23, 24):
            fam[op.sub].append((line, ts, body, hd))
    for sub in sorted(fam):
        print(f"\n (0,{sub}): {len(fam[sub])} frames")
        for line, ts, body, hd in fam[sub]:
            a = u32be(hd[7:11])
            b = u32be(hd[11:15])
            print(f"   {line} {ts} tag={hd[7]:02x} A={a:08x} B={b:08x} "
                  f"body={body.hex()}")

    if 23 in fam and 24 in fam:
        print("\n-- prefix relation, time-adjacent pairs --")
        for (l23, t23, b23, h23), (l24, t24, b24, h24) in zip(fam[23], fam[24]):
            if b24.startswith(b23):
                rel = f"b24 = b23 + {b24[len(b23):].hex()}"
            elif b23.startswith(b24):
                rel = f"b23 = b24 + {b23[len(b24):].hex()}"
            else:
                common = 0
                while common < min(len(b23), len(b24)) and b23[common] == b24[common]:
                    common += 1
                rel = (f"common prefix {common}B; "
                       f"b23[{common}:]={b23[common:].hex()} "
                       f"b24[{common}:]={b24[common:].hex()}")
            print(f"  {l23}/(0,23) vs {l24}/(0,24): {rel}")
            print(f"       A23={u32be(h23[7:11]):08x} A24={u32be(h24[7:11]):08x} "
                  f"tag23={h23[7]:02x} tag24={h24[7]:02x}")

    print("\n-- verbatim body groups --")
    groups: dict[bytes, list] = defaultdict(list)
    for line, ts, conn, op, hd, body, pl, trunc in rows:
        groups[body].append((line, op, u32be(hd[7:11]), u32be(hd[11:15])))
    for body, g in groups.items():
        if len(g) < 2:
            continue
        print(f"  body {body.hex()} ({len(body)}B) x{len(g)}:")
        for line, op, a, b in g:
            print(f"    {line:>5} {str(op):>10} A={a:08x} B={b:08x}")

    print("\n-- bodies that share a long block --")
    blobs: dict[bytes, list] = defaultdict(list)
    for line, ts, conn, op, hd, body, pl, trunc in rows:
        for i in range(0, max(0, len(body) - 8) + 1):
            blobs[body[i:i + 8]].append(line)
    for blk, lines in blobs.items():
        if len(set(lines)) > 1:
            print(f"  8B block {blk.hex()} in lines {sorted(set(lines))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
