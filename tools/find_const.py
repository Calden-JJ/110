#!/usr/bin/env python3
"""Search the exe for byte patterns, reporting image RVAs (not file offsets).

  python find_const.py <hexbytes> [label] [max]
  python find_const.py --dump <rva> <n>
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import EXE, rva2off  # noqa

D = EXE.read_bytes()


def section_map():
    e = struct.unpack_from("<I", D, 0x3C)[0]
    nsec = struct.unpack_from("<H", D, e + 6)[0]
    optsz = struct.unpack_from("<H", D, e + 20)[0]
    so = e + 24 + optsz
    out = []
    for i in range(nsec):
        o = so + i * 40
        name = D[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, raw = struct.unpack_from("<IIII", D, o + 8)
        out.append((name, va, vs, raw, rs))
    return out


SECS = section_map()


def off2rva(off):
    for name, va, vs, raw, rs in SECS:
        if raw <= off < raw + rs:
            return va + (off - raw), name
    return None, None


def rva2off(rva):
    for name, va, vs, raw, rs in SECS:
        if va <= rva < va + vs:
            return raw + (rva - va)
    return None


def find(hexs, label="", maxn=12):
    b = bytes.fromhex(hexs)
    out = []
    i = 0
    while len(out) < maxn:
        j = D.find(b, i)
        if j < 0:
            break
        rva, sect = off2rva(j)
        out.append(f"{rva:#x}({sect})" if rva else f"off{j:#x}")
        i = j + 1
    print(f"{label or hexs:28} {len(out):3d} {' '.join(out)}")


def dump(rva, n):
    o = rva2off(rva)
    if o is None:
        print(f"rva {rva:#x} not in image")
        return
    b = D[o:o + n]
    for i in range(0, n, 16):
        row = b[i:i + 16]
        q = " ".join(f"{x:08x}" for x in struct.unpack("<4I", row))
        print(f"{rva+i:08x}  {row.hex(' ')}  {q}")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "--dump":
        dump(int(a[1], 0), int(a[2], 0) if len(a) > 2 else 0x40)
    else:
        find(a[0], a[1] if len(a) > 1 else "", int(a[2], 0) if len(a) > 2 else 12)
