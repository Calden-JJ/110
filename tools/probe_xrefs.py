#!/usr/bin/env python3
"""Locate code by UTF-16 string anchors (NativeAOT, no Ghidra available).

v3: a raw UTF-16 substring hit is first resolved to its *containing* frozen
string literal object -- layout [u64 MethodTable*][u32 charcount][utf16 chars]
-- and xrefs are searched against that object, so substring anchors
(e.g. "channelinfo_key_blob" inside
"USLocalServer.Protocol.Bodies.Data.channelinfo_key_blob.bin") resolve
correctly.

Search per anchor rva:
  1. rip-relative refs: one-pass index of every `op modrm=00 rm=101 disp32` in
     .text, looked up for the literal object start (-12), the length field (-4)
     and the char start (0).
  2. absolute 8-byte pointers in the same field window.
  3. code byte-dump around rip hits of the object start.

Usage:  python probe_xrefs.py <regex> [<regex> ...]
        python probe_xrefs.py @0x63bcd8a            # explicit anchor rva
        python probe_xrefs.py --dump 0x607d00 512   # raw byte dump
"""

from __future__ import annotations

import re
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


print(f"loading {EXE.name} ...", flush=True)
D = EXE.read_bytes()
TXT_O = rva2off(0x00001000)
TXT_E = rva2off(0x00001000 + 0x00a05bb6 - 8)

# ---- one-pass rip-relative index over .text -------------------------------
RIP = {}
OPS = {0x8D, 0x8B, 0x89, 0x8A, 0x88, 0x8C, 0x39, 0x3B, 0x3A, 0x38,
       0x01, 0x03, 0x29, 0x2B, 0x84, 0x85, 0x86, 0x87}
seg = D[TXT_O:TXT_E]
for i in range(len(seg) - 6):
    if seg[i] not in OPS:
        continue
    if (seg[i + 1] & 0xC7) != 0x05:
        continue
    disp = struct.unpack_from("<i", seg, i + 2)[0]
    here = off2rva(TXT_O + i)
    RIP.setdefault(here + 6 + disp, []).append(here)
    RIP.setdefault(here + 7 + disp, []).append(here | 0x100000000)  # REX form flag
print(f"rip-relative index: {len(RIP):,} distinct targets", flush=True)


def find_utf16(pat: str, limit=16):
    b = pat.encode("utf-16-le")
    return [m.start() for m in re.finditer(re.escape(b), D, re.I)][:limit]


def literal_at(off, back=8192):
    """All frozen literals whose char range covers `off`, ordered start-first.

    Object layout: [u64 MethodTable*][u32 charcount][utf16 chars][pad].
    """
    hits = []
    for q in range(off, max(12, off - back), -1):
        if D[q - 8:q - 4] != b"\x01\x00\x00\x00":
            continue
        mt = struct.unpack_from("<Q", D, q - 12)[0]
        if not (IMAGE_BASE <= mt < IMAGE_END):
            continue
        n = struct.unpack_from("<I", D, q - 4)[0]
        if n == 0 or n > 4096 or q + 2 * n < off:
            continue
        s = D[q:q + 2 * n]
        if any(x != 0 for x in s[1::2]):
            continue
        try:
            txt = s.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        hits.append((q, txt))
    return hits


def dump(rva, n, tag=""):
    o = rva2off(rva)
    if o is None:
        return
    for i in range(0, n, 16):
        c = D[o + i:o + i + 16]
        h = " ".join(f"{b:02x}" for b in c)
        t = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        print(f"    {tag}{rva + i:08x}  {h:<47}  {t}")


def do_anchor(anchors, label):
    print(f"\n-- anchor {label} rvas {[hex(a) for a in anchors]}")
    code_hits = []
    for anchor_rva in anchors:
        for fo in (-12, -8, -4, 0, 4):
            t = anchor_rva + fo
            hits = RIP.get(t) or RIP.get(t + 1) or RIP.get(t - 1)
            if hits:
                for h in hits[:10]:
                    crva = h & 0xFFFFFFFF
                    print(f"   [rip] {fo:+d} (0x{t:08x})  <- code rva 0x{crva:x}"
                          + (" (rex)" if h & 0x100000000 else ""))
                    code_hits.append(crva)
        for fo in (-12, -8, -4, 0):
            tv = IMAGE_BASE + anchor_rva + fo
            blob = struct.pack("<Q", tv)
            start = 0
            n8 = 0
            while n8 < 3:
                i = D.find(blob, start)
                if i < 0:
                    break
                print(f"   [abs8] ptr to {fo:+d} at file 0x{i:x} (rva 0x{off2rva(i) or 0:08x})")
                start = i + 1
                n8 += 1
    for crva in code_hits[:3]:
        print(f"   -- code around 0x{crva:08x} --")
        dump(crva - 64, 192)


def query(pat):
    print(f"\n===== {pat!r} =====")
    offs = find_utf16(pat)
    if not offs:
        print("  no UTF-16 hit")
        return
    for off in offs[:8]:
        cands = literal_at(off)
        if cands:
            q, txt = cands[-1]
            print(f"\n-- utf16 hit @0x{off:08x} -> literal @0x{q:08x} "
                  f"({len(cands)} cand, len {len(txt)}): {txt[:100]!r}")
        else:
            print(f"\n-- utf16 hit @0x{off:08x} -> no literal header found, raw anchor")
        arvas = []
        for q, _t in cands:
            r = off2rva(q)
            if r is not None and r not in arvas:
                arvas.append(r)
        r = off2rva(off)
        if r is not None and r not in arvas:
            arvas.append(r)
        if not arvas:
            print("   anchor not mapped")
            continue
        do_anchor(arvas, repr(txt[:40]) if cands else pat)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "--dump":
        dump(int(argv[1], 0), int(argv[2], 0) if len(argv) > 2 else 256)
        return 0
    for pat in argv:
        if pat.startswith("@"):
            do_anchor([int(pat[1:], 0)], "explicit")
        else:
            query(pat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
