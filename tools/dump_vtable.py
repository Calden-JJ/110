#!/usr/bin/env python3
"""Dump NativeAOT relative-vtable tables in .data and annotate each slot.

Absolute pointers are absent from this image: a known method's address (found
via `na_funcs.py`/disassembly) appears in .data as a 32-bit RVA.  The packet
class's methods -- `MakeHash`, `MakeHashForSending`, `MakeChecksumToOneByte`,
`SuperFastHash`, `Crc32`, `BuildTable`, `PackBitPairs`, `BuildPacket`, `Seal` --
were located by name in the metadata heap at file 0xaf58cc, but metadata names
carry no code addresses.  However the class's vtable slots do, and the slot
order follows the metadata (declaration) order, so reading the table around a
known method's slot names the rest.

  python dump_vtable.py 0x64d0000 0x64d0200
  python dump_vtable.py --around 0x607ae0     # table containing a known method
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


def lit_refs(site_lo, site_hi):
    """Rip-relative ref targets from instructions inside [site_lo, site_hi)."""
    o0, n = rva2off(TXT_S), TXT_E - TXT_S
    out = []
    for i in range(max(0, rva2off(site_lo) - o0 if rva2off(site_lo) else 0),
                   (rva2off(site_hi) - o0) if rva2off(site_hi) else n - 6):
        b = D[o0 + i]
        if b == 0xFF:
            if D[o0 + i + 1] not in (0x15, 0x25):
                continue
        elif b not in (0x8D, 0x8B):
            continue
        if (D[o0 + i + 1] & 0xC7) != 0x05:
            continue
        disp = struct.unpack_from("<i", D, o0 + i + 2)[0]
        site = TXT_S + i
        if site_lo <= site < site_hi:
            out.append((site, site + 6 + disp))
    return out


def func_lits(f0, f1):
    txt = []
    for _site, t in lit_refs(f0, f1):
        note = data_note(t, 40)
        if note.startswith("lit"):
            txt.append(note[4:])
    seen = []
    for t in txt:
        if t not in seen:
            seen.append(t)
    return seen[:4]


def main(argv) -> int:
    if argv and argv[0] == "--around":
        rva = int(argv[1], 0)
        pat = struct.pack("<I", rva)
        sites = []
        s = 0
        while True:
            i = D.find(pat, s)
            if i < 0:
                break
            sites.append(i)
            s = i + 1
        print(f"{len(sites)} table slot(s) holding rva {rva:#x}")
        for i in sites:
            print(f"  slot at file {i:#x}")
            dump(i - 0x40, i + 0x60)
        return 0
    lo, hi = int(argv[0], 0), int(argv[1], 0)
    dump(lo, hi)
    return 0


def dump(lo, hi):
    print(f"--- {lo:#x}..{hi:#x} ---")
    o = lo
    while o + 4 <= hi:
        v = struct.unpack_from("<I", D, o)[0]
        tag = ""
        if TXT_S <= v < TXT_E:
            f = func_of(v)
            if f:
                lits = func_lits(f[0], f[1])
                tag = f"TEXT func 0x{f[0]:x}+0x{v - f[0]:x} ({f[1] - f[0]}B)"
                if lits:
                    tag += "  lits=" + " ".join(lits)
            else:
                tag = "TEXT?"
        else:
            v2 = struct.unpack_from("<Q", D, o)[0]
            if 0x140000000 <= v2 < 0x140000000 + 0x6500000:
                tag = f"ABSVA {v2:#x}"
        print(f"  {o:#08x}  {v:#010x}  {tag}")
        o += 4


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
