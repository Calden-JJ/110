#!/usr/bin/env python3
"""Find E8/E9 xrefs to a code rva across .text."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import D, TXT_S, TXT_E, rva2off, func_of, _lits_in  # noqa


def find(target: int, limit=200):
    o0 = rva2off(TXT_S)
    out = []
    for i in range(0, TXT_E - TXT_S - 5):
        if D[o0 + i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", D, o0 + i + 1)[0]
        t = TXT_S + i + 5 + rel
        if t == target:
            out.append(TXT_S + i)
            if len(out) >= limit:
                break
    return out


def main():
    t = int(sys.argv[1], 0)
    sites = find(t)
    print(f"# {len(sites)} E8 call sites to 0x{t:x}")
    per = {}
    for s in sites:
        f = func_of(s)
        per.setdefault(f[0] if f else None, []).append(s)
    for f, ss in sorted(per.items(), key=lambda kv: (kv[0] is None, kv[0])):
        name = f"func 0x{f:x} +0x{'?'}" if f else "?"
        lits = _lits_in(f, min(f + 0x300, f + 0x300)) if f else []
        print(f"  {name}  x{len(ss)}: " + " ".join(f"0x{x:x}" for x in ss[:8])
              + (f"  {' | '.join(lits)}" if lits else ""))


if __name__ == "__main__":
    main()
