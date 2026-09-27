#!/usr/bin/env python3
"""Find .text sites with rip-relative refs to given RVA(s).

  python litref.py 0x607ef90 [0x...]     # one scan, several targets
  python litref.py --range 0x63b0d00 0x63b0f70
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import D, rva2off, data_note, TXT_S, TXT_E  # noqa

REF_OPS = {0x8D, 0x8B, 0x39, 0x3B, 0x38, 0x3A, 0x89, 0x88, 0x8A,
           0x01, 0x03, 0x29, 0x2B}


def _iter_refs():
    o0 = rva2off(TXT_S)
    n = TXT_E - TXT_S
    for i in range(n - 6):
        op = D[o0 + i]
        if op == 0xFF:
            if D[o0 + i + 1] not in (0x15, 0x25):
                continue
        elif op in REF_OPS:
            if (D[o0 + i + 1] & 0xC7) != 0x05:
                continue
        else:
            continue
        disp = struct.unpack_from("<i", D, o0 + i + 2)[0]
        site = TXT_S + i
        yield site, site + 6 + disp


def scan(targets):
    tset = set(targets)
    hits = {t: [] for t in targets}
    for site, t in _iter_refs():
        if t in tset:
            hits[t].append(site)
    return hits


def main(argv):
    if argv[0] == "--range":
        lo, hi = int(argv[1], 0), int(argv[2], 0)
        out = [(site, t) for site, t in _iter_refs() if lo <= t < hi]
        print(f"{len(out)} refs into [{lo:#x},{hi:#x})")
        for site, t in out:
            print(f"   site {site:#08x} -> {t:#08x}  {data_note(t)[:60]}")
        return 0
    targets = [int(a, 0) for a in argv]
    hits = scan(targets)
    for t in targets:
        print(f"== {t:#x} ({data_note(t)[:50]}): {len(hits[t])} refs")
        for site in hits[t]:
            print(f"   site {site:#08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
