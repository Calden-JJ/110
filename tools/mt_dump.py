#!/usr/bin/env python3
"""Dump a NativeAOT MethodTable and its vtable entries.

  python mt_dump.py 0x5e289b8        # rva of a frozen object TEMPLATE (obj[0]=MT)
  python mt_dump.py --mt 0x6340280   # rva of the MethodTable itself
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import D, IMAGE_BASE, TXT_S, TXT_E, rva2off, func_of, disas, lit_text_at  # noqa

TXT_END = 0x1000 + 0xa05bb6


def q(rva):
    o = rva2off(rva)
    if o is None or o + 8 > len(D):
        return None
    return struct.unpack_from("<Q", D, o)[0]


def d(rva):
    o = rva2off(rva)
    return struct.unpack_from("<I", D, o)[0] if o is not None else None


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 2
    if a[0] == "--mt":
        mt = int(a[1], 0)
    else:
        r = int(a[0], 0)
        mtv = q(r)
        if mtv is None or not (IMAGE_BASE <= mtv < IMAGE_BASE + 0x6500000):
            print(f"obj 0x{r:x}: first qword is not a pointer ({mtv!r})")
            return 1
        mt = mtv - IMAGE_BASE
        print(f"obj 0x{r:x} -> MT 0x{mt:x}")
    cs_flags = d(mt)
    base_size = d(mt + 4)
    rel_param = q(mt + 8)
    rel_type = q(mt + 0x10)
    print(f"MT 0x{mt:x}: componentSize={cs_flags & 0xffff} flags=0x{cs_flags >> 16:04x} "
          f"baseSize=0x{base_size:x}")
    for off, nm in ((8, "relatedParam"), (0x10, "relatedType")):
        v = q(mt + off)
        print(f"  +0x{off:x} {nm:<13} = {v:#x}" if v is not None and v > 0xffff else
              f"  +0x{off:x} {nm:<13} = {v}")
    print("  vtable candidates (text pointers):")
    seen = []
    for off in range(0x18, 0x18 + 0x100, 8):
        v = q(mt + off)
        if v is None:
            continue
        rv = v - IMAGE_BASE
        if TXT_S <= rv < TXT_END:
            f = func_of(rv)
            name = f"func 0x{f[0]:x}({f[1]-f[0]}B)" if f else "?"
            if rv != 0x9aad50 and rv not in seen:
                print(f"    +0x{off:02x} -> 0x{rv:06x}  {name}")
                seen.append(rv)
        elif v and v < 0x100000000:
            pass
    if len(a) > 1 and a[1] == "--dis":
        for rv in seen:
            print(f"\n; --- 0x{rv:x} ---")
            disas(rv, rv + 0x180, show_bytes=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
