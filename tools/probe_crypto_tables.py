#!/usr/bin/env python3
"""Recon for the embedded USLocalServer.Protocol.Crypto.Tables.* payloads.

Read-only probe of USLocalServer.Server.exe.  All printed addresses are RVAs
(relative virtual addresses) unless a line says `file`.

Sections:
  0. calibrate the RVA space (Blowfish pi digits, end of the JSON blob)
  1. segment the binary region after the JSON blob against the structural
     signature each crypto table should have (permutation runs, block stats)
  2. hunt for the 334-byte channelinfo key blob (ASCII session-seed prefix)
  3. every resource name, as a UTF-16 literal (code) and as ASCII (manifest),
     plus the manifest entry tail bytes
  4. raw code around the table loads, so size-check immediates show through
  5. re-check the only two 256-byte permutations in the file
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\USLocalServer.Server.exe")
D = EXE.read_bytes()

SECS = [
    (".text", 0x00001000, 0x00a05bb6, 0x00000400, 0x00a05c00),
    (".rdata", 0x00a07000, 0x058f39c6, 0x00a06000, 0x058f3a00),
    (".data", 0x062fb000, 0x001e6418, 0x062f9a00, 0x0018a400),
    (".pdata", 0x064e2000, 0x000a5e94, 0x06483e00, 0x000a6000),
    (".rsrc", 0x06588000, 0x00000616, 0x06529e00, 0x00000800),
    (".reloc", 0x06589000, 0x00109d14, 0x0652a600, 0x00109e00),
]

NAMES = [
    "algo06_misty1_s7.bin",
    "algo06_misty1_s9.bin",
    "algo07_blowfish_sboxes.bin",
    "algo09_rcon.bin",
    "algo09_sbox.bin",
    "algo09_t0.bin",
    "algo09_t1.bin",
    "algo09_t2.bin",
    "algo09_t3.bin",
    "algo09_tbl5.bin",
    "algo11_khazad_t.bin",
    "channelinfo_key_blob.bin",
]


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


def asc(off, n):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in D[off:off + n])


def line(off, n=16):
    c = D[off:off + n]
    h = " ".join(f"{b:02x}" for b in c)
    r = off2rva(off)
    tag = f"rva {r:08x}" if r is not None else f"file {off:08x}"
    print(f"  {tag}  {h:<47}  {asc(off, n)}")


def dump(off, n):
    for i in range(0, n, 16):
        if off + i >= len(D):
            break
        line(off + i)


def u32o(rva, n):
    o = rva2off(rva)
    return struct.unpack_from(f"<{n}I", D, o) if o is not None else ()


def find_runs(base_rva, end_rva, pred, label, minlen=8):
    o, e = rva2off(base_rva), rva2off(end_rva)
    out = []
    off = o
    while off + 4 <= e:
        if pred(struct.unpack_from("<I", D, off)[0]):
            start = off
            while off + 4 <= e and pred(struct.unpack_from("<I", D, off)[0]):
                off += 4
            if (off - start) // 4 >= minlen:
                out.append((off2rva(start), (off - start) // 4))
        else:
            off += 4
    for s, n in out:
        print(f"    {label:14} rva 0x{s:08x}  {n} u32 ({n * 4} B)")
    return out


def main():
    print(f"file {EXE}\n     {len(D):,} bytes\n")

    # -- 0. calibrate ------------------------------------------------------
    print("== 0a. Blowfish pi digits ==")
    for pat in (b"\x88\x6a\x3f\x24", b"\x24\x3f\x6a\x88"):
        hits = [m.start() for m in re.finditer(re.escape(pat), D)]
        print(f"  pattern {pat.hex()}: {len(hits)} hits")
        for h in hits[:4]:
            r = off2rva(h)
            print(f"    file 0x{h:x}  rva 0x{r:08x}" if r else f"    file 0x{h:x}")
    for label, rva in (("rva 0x6417220", 0x6417220), ("rva 0x6042ff8", 0x6042ff8)):
        o = rva2off(rva)
        if o is None:
            print(f"  {label}: unmapped")
            continue
        vals = struct.unpack_from("<8I", D, o)
        pi = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344]
        print(f"  {label} file 0x{o:x}: " + " ".join(f"{v:08x}" for v in vals)
              + f"   pi? {list(vals[:4]) == pi}")

    print("\n== 0b. end of the JSON resource blob (search '3853390931') ==")
    base_rva = None
    for m in re.finditer(rb"3853390931", D):
        o = m.start()
        r = off2rva(o)
        print(f"  file 0x{o:x}  rva 0x{r:08x}")
        dump(o + 10, 64)
        base_rva = (r + 10 + len(b'3853390931')) & ~0xF  # just a guess to show
    # the true base: 16-aligned rva right after the closing braces
    if base_rva is not None:
        print(f"  guess: table base rva 0x{base_rva:08x}")

    # -- 1. segment --------------------------------------------------------
    lo, hi = 0x58EA1F0, 0x58F1000
    print(f"\n== 1. table region segmentation (rva 0x{lo:08x}..0x{hi:08x}) ==")
    find_runs(lo, hi, lambda v: v < 128, "u32 < 128")
    find_runs(lo, hi, lambda v: v < 512, "u32 < 512")
    find_runs(lo, hi, lambda v: v > 0xFFFF, "u32 > 64K")
    print("  -- 1024-byte block stats (min/max/first) --")
    o = rva2off(0x58EAA00)
    o_end = rva2off(0x58F1000)
    k = 0
    while o + 1024 <= o_end:
        blk = struct.unpack_from("<256I", D, o)
        r = off2rva(o)
        print(f"    rva 0x{r:08x}  min={min(blk):08x} max={max(blk):08x} "
              f"first={blk[0]:08x} nfull={sum(1 for v in blk if v > 0xFFFF)}")
        o += 1024
        k += 1
        if k > 46:
            break

    # -- 2. ASCII runs (key blob seed prefix) ------------------------------
    print("\n== 2. ASCII runs >= 10 in rva 0x58EA1F0..0x58F1000 ==")
    so, eo = rva2off(0x58EA1F0), rva2off(0x58F1000)
    for m in re.finditer(rb"[\x20-\x7e]{10,}", D[so:eo]):
        p = so + m.start()
        print(f"    rva 0x{off2rva(p):08x} len {len(m.group())}: {m.group()[:70]!r}")

    # -- 3. resource names -------------------------------------------------
    print("\n== 3. resource names ==")
    for name in NAMES:
        u16 = [m.start() for m in re.finditer(re.escape(name.encode("utf-16-le")), D)]
        a8 = [m.start() for m in re.finditer(re.escape(name.encode()), D)]
        u16s = ", ".join(f"0x{off2rva(h):08x}" for h in u16[:8])
        print(f"  {name}")
        print(f"    utf16 literals (rva): {u16s or '-'}")
        for h in a8[:4]:
            r = off2rva(h)
            print(f"    ascii manifest entry (rva 0x{r:08x}), byte before = "
                  f"0x{D[h-1]:02x} (namelen {len(name)})")
            dump(h - 32, 32)
            line(h)
            print(f"    tail after name:")
            dump(h + len(name), 32)

    # -- 4. code around the table loads ------------------------------------
    def both(label, addr, n):
        print(f"\n== {label} ==")
        for tag, off in (("as-rva", rva2off(addr)), ("as-fileoff", addr)):
            if off is None or off + n > len(D):
                print(f"  -- {tag}: unmapped --")
                continue
            print(f"  -- {tag}: file 0x{off:x} (rva 0x{off2rva(off):08x}) --")
            dump(off, n)

    both("4a. khazad table load site (0x582c60)", 0x582C60, 0x100)
    both("4b. bulk table load site (0x5833c0)", 0x5833C0, 0x200)
    both("4c. channelinfo key blob load site (0x5957e0)", 0x5957E0, 0x260)

    print("\n== 4d. size-check immediates in 0x582c00..0x583600 (as-rva) ==")
    seg_o, seg_e = rva2off(0x582C00), rva2off(0x583600)
    seg = D[seg_o:seg_e] if seg_o and seg_e else b""
    for i in range(len(seg) - 6):
        if seg[i] == 0x48 and seg[i + 1] == 0x81 and seg[i + 2] in (0xF9, 0xF8, 0xFA, 0xFB, 0xC0, 0xC8):
            imm = struct.unpack_from("<i", seg, i + 3)[0]
            if 0 < imm < 1 << 20:
                print(f"    rva 0x{off2rva(seg_o + i):08x}  cmp r{seg[i+2]&7}, 0x{imm:x} ({imm})")
        if seg[i] in (0x48, 0x41) and seg[i + 1] in (0x83, 0x81) and seg[i + 2] in (0xF9, 0xF8):
            if seg[i + 1] == 0x83:
                imm = seg[i + 3]
            else:
                imm = struct.unpack_from("<i", seg, i + 3)[0] & 0xFFFFFFFF
            if 0 < imm < 1 << 20:
                print(f"    rva 0x{off2rva(seg_o + i):08x}  cmp r{seg[i+2]&7}, {imm}")

    # -- 5. the two byte permutations --------------------------------------
    print("\n== 5. 256-byte permutations (known sites) ==")
    seen = []
    for off in (0x5B016D0, 0x5B017D0, 0x5AE96D0):
        for cand in (off, rva2off(off)):
            if cand is None or cand < 0 or cand + 256 > len(D):
                continue
            win = D[cand:cand + 256]
            ok = len(set(win)) == 256
            print(f"  file 0x{cand:x} (rva 0x{off2rva(cand):08x}): "
                  f"{'permutation' if ok else 'not a permutation'}")
            if ok:
                seen.append(cand)
    for off in seen[:4]:
        print(f"  -- file 0x{off:x} (rva 0x{off2rva(off):08x}) --")
        dump(off - 16, 32)
        dump(off + 240, 32)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
