#!/usr/bin/env python3
"""Walk the .data MethodDesc table and annotate every method with its literals.

Each record is 12 bytes: [codeStart RVA][codeEnd RVA][unwind RVA], laid out in
metadata (declaration) order.  Absolute pointers are absent from this image, so
this table is the only place a method's code address can be read off.  Names
are not in the table, but the string literals each method references identify
it well enough: a packet builder names its log fields, a cipher names its key
file, and a hash function references nothing at all -- which is itself a
useful signature when hunting for `MakeHashForSending`.

  python list_methods.py --scan 0x64d0000 0x64d7000
  python list_methods.py --code 0x580000 0x610000   # only this code range
"""
from __future__ import annotations

import bisect
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from na_dis import D, FUNCS, FSTART, rva2off, func_of, data_note  # noqa: E402

TXT_S, TXT_E = 0x1000, 0x1000 + 0xa05bb6


def records(lo, hi):
    """Yield (table_off, start, end, unwind) for plausible records."""
    o = lo
    while o + 12 <= hi:
        s, e, u = struct.unpack_from("<III", D, o)
        if TXT_S <= s < e <= TXT_E and e - s < 0x20000:
            yield o, s, e, u
            o += 12
        else:
            o += 4


def _all_refs():
    out = []
    o0, n = rva2off(TXT_S), TXT_E - TXT_S
    i = 0
    while i < n - 6:
        b = D[o0 + i]
        if b == 0xFF:
            if D[o0 + i + 1] not in (0x15, 0x25):
                i += 1
                continue
        elif b not in (0x8D, 0x8B, 0x39, 0x3B, 0x3D, 0x89, 0x3A):
            i += 1
            continue
        if (D[o0 + i + 1] & 0xC7) != 0x05:
            i += 1
            continue
        disp = struct.unpack_from("<i", D, o0 + i + 2)[0]
        site = TXT_S + i
        out.append((site, site + 6 + disp))
        i += 1
    return out


REFS = None


def func_lits(s, e, limit=4):
    global REFS
    if REFS is None:
        REFS = _all_refs()
        REFS.sort()
    sites = [t for t in REFS if s <= t[0] < e]
    out = []
    for _site, tgt in sites:
        note = data_note(tgt, 44)
        if note.startswith("lit") and note[4:] not in out:
            out.append(note[4:])
        if len(out) >= limit:
            break
    return out


def main(argv) -> int:
    lo = hi = None
    cmin, cmax = 0, 0xFFFFFFFF
    if argv[0] == "--scan":
        lo, hi = int(argv[1], 0), int(argv[2], 0)
    elif argv[0] == "--code":
        cmin, cmax = int(argv[1], 0), int(argv[2], 0)
        lo, hi = 0x64c0000, 0x6500000
    else:
        print(__doc__)
        return 1

    recs = list(records(lo, hi))
    if cmin:
        recs = [r for r in recs if cmin <= r[1] < cmax]
    print(f"{len(recs)} method record(s)\n")
    for off, s, e, u in recs:
        lits = func_lits(s, e)
        lit_s = ("  " + " ".join(lits)) if lits else ""
        print(f"  tab{off:#08x}  code 0x{s:x}..0x{e:x} ({e - s:>5}B){lit_s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
