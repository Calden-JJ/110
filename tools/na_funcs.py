#!/usr/bin/env python3
"""NativeAOT navigation: function boundaries (.pdata), direct calls, RIP refs.

  python na_funcs.py --func 0x59641f           # function containing rva + its refs
  python na_funcs.py --calls 0x5963c0          # direct call/jmp sites into rva
  python na_funcs.py --refs 0x63d87c4          # rip-relative refs to an address
  python na_funcs.py --strings 0x596000 0x597000
  python na_funcs.py --callees 0x607ae0 0x60855a    # direct calls inside a range
  python na_funcs.py --dump 0x5963c0 320
  python na_funcs.py --list 0x596000 0x597000  # .pdata function boundaries in range
"""

from __future__ import annotations

import bisect
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\USLocalServer.Server.exe")

SECS = [
    (".text", 0x00001000, 0x00a05bb6, 0x00000400, 0x00a05c00),
    (".rdata", 0x00a07000, 0x058f39c6, 0x00a06000, 0x058f3a00),
    (".data", 0x062fb000, 0x001e6418, 0x062f9a00, 0x0018a400),
    (".pdata", 0x064e2000, 0x000a5e94, 0x06483e00, 0x000a6000),
    (".rsrc", 0x06588000, 0x00000616, 0x06529e00, 0x00000800),
    (".reloc", 0x06589000, 0x00109d14, 0x0652a600, 0x00109e00),
]
IMAGE_BASE = 0x140000000
IMAGE_END = IMAGE_BASE + 0x6500000
TXT_VA, TXT_VS, TXT_RAW = SECS[0][1], SECS[0][2], SECS[0][3]
PDATA_VA, PDATA_VS, PDATA_RAW = SECS[3][1], SECS[3][2], SECS[3][3]


def rva2off(rva):
    for _n, va, vs, ro, _rs in SECS:
        if va <= rva < va + vs:
            o = ro + (rva - va)
            return o if 0 <= o < len(D) else None
    return None


def off2rva(off):
    for _n, va, _vs, ro, rs in SECS:
        if ro <= off < ro + rs:
            return va + (off - ro)
    return None


D = EXE.read_bytes()

FUNCS = []
for _o in range(PDATA_RAW, PDATA_RAW + PDATA_VS, 12):
    _b, _e, _u = struct.unpack_from("<III", D, _o)
    if _b and _e > _b:
        FUNCS.append((_b, _e))
FUNCS.sort()
FSTART = [f[0] for f in FUNCS]
print(f"{len(FUNCS):,} functions from .pdata", flush=True)


def func_of(rva):
    i = bisect.bisect_right(FSTART, rva) - 1
    if i >= 0 and FUNCS[i][0] <= rva < FUNCS[i][1]:
        return FUNCS[i]
    return None


REFOPS = {0x8D, 0x8B, 0x39, 0x3B, 0x38, 0x3A, 0x89, 0x88, 0x8A,
          0x01, 0x03, 0x29, 0x2B}


def classify(t):
    """('lit', off, text) if t is a frozen-string object, else ('data', off, hex)."""
    o = rva2off(t)
    if o is None or o + 12 > len(D):
        return None
    mt = struct.unpack_from("<Q", D, o)[0]
    if IMAGE_BASE <= mt < IMAGE_END:
        n = struct.unpack_from("<I", D, o + 8)[0]
        if 0 < n <= 4096:
            s = D[o + 12:o + 12 + 2 * n]
            if len(s) == 2 * n and all(x == 0 for x in s[1::2]):
                try:
                    return ("lit", o, s.decode("utf-16-le"))
                except UnicodeDecodeError:
                    pass
    c = D[o:o + 16]
    return ("data", o, " ".join(f"{b:02x}" for b in c))


def refs_in(s, e):
    o0 = rva2off(s)
    if o0 is None:
        return []
    out, seen = [], set()
    for i in range(0, e - s - 6):
        op = D[o0 + i]
        md = D[o0 + i + 1]
        if op == 0xFF:
            if md not in (0x15, 0x25):
                continue
        elif op in REFOPS:
            if (md & 0xC7) != 0x05:
                continue
        else:
            continue
        disp = struct.unpack_from("<i", D, o0 + i + 2)[0]
        t = s + i + 6 - 0 + disp
        key = (s + i, t)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def show_refs(s, e):
    for site, t in refs_in(s, e):
        # the lea target for a frozen string is the object start (-12 from chars);
        # if the site points straight at the chars, retry 12 bytes back
        c = classify(t)
        note = ""
        if c and c[0] == "data":
            c2 = classify(t - 12)
            if c2 and c2[0] == "lit":
                c, note = c2, "  (chars ref, obj-12)"
        if c and c[0] == "lit":
            print(f"   0x{site:06x} -> 0x{c[1]:08x}  lit {c[2][:96]!r}{note}")
        elif c:
            print(f"   0x{site:06x} -> 0x{t:08x}  data {c[2]}")
        else:
            print(f"   0x{site:06x} -> 0x{t:08x}  (unmapped)")


def calls_to(t, also_jmp=True):
    o0, n = rva2off(TXT_VA), TXT_VS
    out = []
    for opcode in ((b"\xe8", b"\xe9") if also_jmp else (b"\xe8",)):
        start = o0
        while True:
            i = D.find(opcode, start, o0 + n - 5)
            if i < 0:
                break
            disp = struct.unpack_from("<i", D, i + 1)[0]
            site = off2rva(i)
            if site + 5 + disp == t:
                out.append((site, opcode[0]))
            start = i + 1
    out.sort()
    return out


def dump(rva, n):
    o = rva2off(rva)
    if o is None:
        print(f"0x{rva:x} unmapped")
        return
    for i in range(0, n, 16):
        c = D[o + i:o + i + 16]
        print(f"  {rva + i:08x}  {' '.join(f'{b:02x}' for b in c):<47}  "
              f"{''.join(chr(b) if 32 <= b < 127 else '.' for b in c)}")


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    if cmd == "--func":
        rva = int(argv[1], 0)
        f = func_of(rva)
        if not f:
            print(f"0x{rva:x} not inside any .pdata function")
            return 1
        print(f"func 0x{f[0]:x} .. 0x{f[1]:x}  ({f[1] - f[0]} B); "
              f"0x{rva:x} at +0x{rva - f[0]:x}")
        show_refs(f[0], f[1])
    elif cmd == "--refs":
        t = int(argv[1], 0)
        print(f"refs to 0x{t:x}:")
        for site, tt in refs_in(0x1000, 0x1000 + TXT_VS):
            if tt in (t, t + 1, t - 1):
                f = func_of(site)
                where = f"func 0x{f[0]:x} +0x{site - f[0]:x}" if f else "?"
                print(f"   0x{site:06x} -> 0x{tt:x}  ({where})")
    elif cmd == "--strings":
        s, e = int(argv[1], 0), int(argv[2], 0)
        show_refs(s, e)
    elif cmd == "--calls":
        t = int(argv[1], 0)
        for site, op in calls_to(t):
            f = func_of(site)
            where = f"func 0x{f[0]:x} +0x{site - f[0]:x}" if f else "?"
            print(f"  {'call' if op == 0xE8 else 'jmp '} 0x{site:06x}  ({where})")
    elif cmd == "--callees":
        s, e = int(argv[1], 0), int(argv[2], 0)
        o0 = rva2off(s)
        for i in range(0, e - s - 5):
            if D[o0 + i] != 0xE8:
                continue
            disp = struct.unpack_from("<i", D, o0 + i + 1)[0]
            site = s + i
            t = site + 5 + disp
            f = func_of(t)
            lits = []
            if f:
                for _s2, tt in refs_in(f[0], min(f[1], f[0] + 0x500)):
                    c = classify(tt)
                    if c and c[0] == "lit":
                        lits.append(c[2][:44])
                    if len(lits) >= 3:
                        break
            tag = f"func 0x{f[0]:06x}" if f else "???"
            print(f"   0x{site:06x} -> 0x{t:06x}  {tag}  {' | '.join(lits)}")
    elif cmd == "--list":
        s, e = int(argv[1], 0), int(argv[2], 0)
        for b, en in FUNCS:
            if b >= e or en <= s:
                continue
            print(f"  0x{b:06x} .. 0x{en:06x}  ({en - b} B)")
    elif cmd == "--dump":
        dump(int(argv[1], 0), int(argv[2], 0) if len(argv) > 2 else 256)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
