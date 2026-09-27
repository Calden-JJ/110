#!/usr/bin/env python3
"""Find the S->C game header writer by its store signature.

The 16-byte S->C header is `[0]=main [1:3]=sub(u16le) [3:7]=wire len(u32le)
[7:11]=A [11:15]=B [15]=0`.  Whatever function writes it must store into
displacements 3 (dword), 7 (dword), 11 (dword) and 15 (byte, value 0) of the
same buffer.  Displacement 11 as a dword store is rare on its own, and
7/11/(15 or 3) co-occurring in one function is rarer still, so a byte-level
scan for the x86-64 store encodings nominates candidates without
disassembling 9.4 MB of code.

Accepted encodings, with optional REX (0x40-0x4F):
  89 /r  disp8      mov dword ptr [base+disp], reg      mod=01 rm!=100
  C7 /0  disp8 imm32
  66 89 /r disp8    mov word ptr [base+disp], reg
  66 C7 /0 disp8 i16
  C6 /0  disp8 00   mov byte ptr [base+disp], 0
"""
from __future__ import annotations

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from na_dis import D, TXT_S, TXT_E, rva2off, IMAGE_BASE  # noqa: E402

TARGETS = {3: 4, 7: 4, 11: 4, 15: 1, 5: 4}


def scan():
    """One pass; returns {disp: [(file_off, base_reg)]} for mod=01 disp8."""
    hits = {d: [] for d in TARGETS}
    o0, n = rva2off(TXT_S), TXT_E - TXT_S
    i = 0
    while i < n - 8:
        b = D[o0 + i]
        rex = 0
        j = i
        if 0x40 <= b <= 0x4F:
            rex = b & 0xF
            j = i + 1
            b = D[o0 + j]
        op16 = None
        if b == 0x66:
            op16 = True
            j += 1
            b = D[o0 + j]
        if b in (0x89, 0x8B, 0xC7, 0xC6, 0xC1, 0x88, 0x8A, 0x01, 0x03):
            m = D[o0 + j + 1]
            if (m & 0xC0) == 0x40 and (m & 7) != 4:
                disp = D[o0 + j + 2]
                if disp in TARGETS:
                    base = ((rex & 1) << 3) | (m & 7)
                    width = 4 if op16 is None else 2
                    if b == 0xC6 or b == 0x88 or b == 0x8A:
                        width = 1
                    if width == TARGETS[disp]:
                        # C6/C7 need reg field 0 to be a store-to-mem
                        if b in (0xC6, 0xC7) and (m & 0x38) != 0:
                            i += 1
                            continue
                        if b in (0x88, 0x89, 0xC6, 0xC7):
                            hits[disp].append((o0 + i, base))
        i += 1
    return hits


def func_ranges():
    """Parse .pdata into (start, end) RVA ranges, sorted by start."""
    import struct
    from na_dis import rva2off as r2o
    # .pdata RVA 0x8a5000 size ~0x8f000; entries are 12 bytes: [begin][end][unwind]
    out = []
    for rva in range(0x8a5000, 0x8a5000 + 0x90000, 12):
        o = r2o(rva)
        if o is None:
            continue
        b, e = struct.unpack_from("<II", D, o)
        if 0x1000 <= b < 0x1000 + 0xa05bb6 and e > b:
            out.append((b, e))
    out.sort()
    return out


def main() -> int:
    hits = scan()
    for d in sorted(hits):
        print(f"  [+{d}] width{TARGETS[d]}: {len(hits[d])} store(s)")

    s7 = [o for o, _ in hits[7]]
    s11 = [o for o, _ in hits[11]]
    s15 = [o for o, _ in hits[15]]
    s3 = [o for o, _ in hits[3]]

    print(f"\n-- windows with [+7]dword and [+11]dword within 400B --")
    ranges = func_ranges()
    print(f"   ({len(ranges)} .pdata functions)")

    def func_at(off):
        rva = off - rva2off(TXT_S) + TXT_S
        lo, hi = 0, len(ranges) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if ranges[mid][0] <= rva:
                best = ranges[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    seen = {}
    for o7 in s7:
        for o11 in s11:
            if abs(o11 - o7) <= 400:
                f = func_at(o7)
                key = f[0] if f else o7 >> 8
                if key in seen:
                    continue
                near15 = sum(1 for o in s15 if abs(o - o7) <= 800)
                near3 = sum(1 for o in s3 if abs(o - o7) <= 800)
                mono = abs(o11 - o7)
                seen[key] = (o7, o11, f, near15, near3, mono)
    if not seen:
        print("  none")
    for key, (o7, o11, f, n15, n3, mono) in sorted(seen.items()):
        fr = f"rva 0x{f[0]:x}..0x{f[1]:x}" if f else "?"
        print(f"  file0x{o7:x} rva0x{o7 - rva2off(TXT_S) + TXT_S:x}  "
              f"[+7]&[+11] {mono}B apart  [+15]=0:{n15} [+3]:{n3}   {fr}")
    print(f"\n{len(seen)} candidate window(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
