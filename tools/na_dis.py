#!/usr/bin/env python3
"""Annotated disassembler for the NativeAOT server exe (capstone).

  python dis.py 0x5829d0              # disassemble the .pdata function containing rva
  python dis.py 0x5829d0 0x582ac9     # explicit range
  python dis.py --f 0x582920          # same as bare rva (explicit)
  python dis.py --all 0x5829d0        # ignore .pdata boundary, dump 0x400 bytes
  python dis.py --lits 0x581230 0x581483   # literals referenced in range

Annotations:
  lea reg,[rip+x]      -> literal text / data hex / "code 0x..." if it points into .text
  call rel32           -> function start, byte size, and up to 3 literals the callee refs
  immediate byte vals  -> printable char hint
"""
from __future__ import annotations

import bisect
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

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
TXT_S, TXT_E = 0x1000, 0x1000 + 0xa05bb6


def rva2off(rva):
    for _n, va, vs, ro, _rs in SECS:
        if va <= rva < va + vs:
            o = ro + (rva - va)
            return o if 0 <= o < len(D) else None
    return None


D = EXE.read_bytes()

FUNCS = []
_PD_O, _PD_N = rva2off(0x64e2000), 0xa5e94
for _o in range(_PD_O, _PD_O + _PD_N, 12):
    _b, _e, _u = struct.unpack_from("<III", D, _o)
    if _b and _e > _b:
        FUNCS.append((_b, _e))
FUNCS.sort()
FSTART = [f[0] for f in FUNCS]


def func_of(rva):
    i = bisect.bisect_right(FSTART, rva) - 1
    if i >= 0 and FUNCS[i][0] <= rva < FUNCS[i][1]:
        return FUNCS[i]
    return None


def lit_text_at(t):
    """Text if `t` is a frozen literal object start or its chars start."""
    for cand in (t, t - 12):
        o = rva2off(cand)
        if o is None or o + 12 > len(D):
            continue
        mt = struct.unpack_from("<Q", D, o)[0]
        if not (IMAGE_BASE <= mt < IMAGE_END):
            continue
        n = struct.unpack_from("<I", D, o + 8)[0]
        if not (0 < n <= 4096):
            continue
        s = D[o + 12:o + 12 + 2 * n]
        if len(s) != 2 * n or any(x != 0 for x in s[1::2]):
            continue
        try:
            return s.decode("utf-16-le"), cand, cand == t
        except UnicodeDecodeError:
            pass
    return None


def data_note(t, maxlen=48):
    o = rva2off(t)
    if o is None:
        return "(unmapped)"
    if TXT_S <= t < TXT_E:
        f = func_of(t)
        return f"code func 0x{f[0]:x} +0x{t - f[0]:x}" if f else "code"
    lit = lit_text_at(t)
    if lit:
        txt, _c, isobj = lit
        return f"lit {'' if isobj else 'chars '}{txt[:maxlen]!r}"
    c = D[o:o + 16]
    return "data " + " ".join(f"{b:02x}" for b in c)


_REFOPS = {0x8D, 0x8B, 0x39, 0x3B, 0x38, 0x3A, 0x89, 0x88, 0x8A,
           0x01, 0x03, 0x29, 0x2B}
LITCACHE = {}
CALLER_HINT = {}


def _lits_in(s, e, k=3):
    """Up to k frozen literals referenced by rip-relative ops in [s,e)."""
    o0 = rva2off(s)
    if o0 is None:
        return []
    out = []
    for i in range(0, e - s - 6):
        op = D[o0 + i]
        if op == 0xFF:
            md = D[o0 + i + 1]
            if md not in (0x15, 0x25):
                continue
        elif op in _REFOPS:
            if (D[o0 + i + 1] & 0xC7) != 0x05:
                continue
        else:
            continue
        disp = struct.unpack_from("<i", D, o0 + i + 2)[0]
        t = s + i + 6 + disp
        lit = lit_text_at(t) or lit_text_at(t - 12)
        if lit:
            out.append(lit[0][:40])
            if len(out) >= k:
                break
    return out


def callee_hint(t):
    if t in CALLER_HINT:
        return CALLER_HINT[t]
    f = func_of(t)
    txt = ""
    if f:
        ls = _lits_in(f[0], min(f[1], f[0] + 0x400))
        if ls:
            txt = " | ".join(ls)
    h = f"func 0x{f[0]:x}({f[1] - f[0]}B)" if f else ""
    if t in MANUAL:
        h = f"{MANUAL[t]} [{h or hex(t)}]"
    if txt:
        h += "  " + txt
    CALLER_HINT[t] = h
    return h


MANUAL = {
    0x9a9210: "alloc_obj",
    0x9a9330: "alloc_str",
    0x9a9470: "st_field",   # write barrier / field store helper
    0x1b4650: "str_copy_ctor",
}


def disas(s, e, show_bytes=False):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    o, oe = rva2off(s), rva2off(e)
    if o is None:
        print(f"0x{s:x} unmapped")
        return
    code = D[o:oe if oe else len(D)]
    addr, idx, n = s, 0, 0
    while idx < len(code) and addr < e:
        stop = None
        for ins in md.disasm(code[idx:], addr):
            if ins.address >= e:
                break
            note = ""
            imms = []
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp
                    note = data_note(t)
                    break
                if op.type == X86_OP_IMM and ins.size <= 7 and ins.mnemonic in (
                        "call", "jmp", "je", "jne", "jz", "jnz", "jb", "jae",
                        "ja", "jbe", "jl", "jle", "jg", "jge", "js", "jns"):
                    t = op.imm & 0xFFFFFFFFFFFFFFFF
                    if ins.mnemonic in ("call", "jmp") and TXT_S <= t < TXT_E:
                        note = callee_hint(t)
                    break
            if not note:
                for op in ins.operands:
                    if op.type == X86_OP_IMM and 0x20 <= op.imm < 0x7f:
                        imms.append(f"'{chr(op.imm)}'")
                if imms:
                    note = "char " + ",".join(imms)
            bs = " ".join(f"{b:02x}" for b in ins.bytes) if show_bytes else None
            line = f"  {ins.address:06x}  {ins.mnemonic:<6} {ins.op_str}"
            if bs:
                line = f"  {ins.address:06x}  {bs:<24} {ins.mnemonic:<6} {ins.op_str}"
            if note:
                line = f"{line:<64} ; {note}"
            print(line)
            n += 1
            stop = ins.address + ins.size
        if stop is None or stop <= addr:
            print(f"  {addr:06x}  db 0x{code[idx]:02x}")
            addr += 1
            idx += 1
        else:
            idx += stop - addr
            addr = stop
    if n == 0:
        print("  (no instructions decoded)")


def all_refs(s, e):
    """[(site_rva, target, note)] for every rip-relative ref in [s,e)."""
    o0 = rva2off(s)
    out = []
    for i in range(0, e - s - 6):
        op = D[o0 + i]
        if op == 0xFF:
            if D[o0 + i + 1] not in (0x15, 0x25):
                continue
        elif op in _REFOPS:
            if (D[o0 + i + 1] & 0xC7) != 0x05:
                continue
        else:
            continue
        disp = struct.unpack_from("<i", D, o0 + i + 2)[0]
        t = s + i + 6 + disp
        out.append((s + i, t, data_note(t)))
    return out


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "--lits":
        s, e = int(argv[1], 0), int(argv[2], 0)
        for site, t, note in all_refs(s, e):
            if note.startswith("lit"):
                print(f"   0x{site:06x} -> 0x{t:08x}  {note}")
        return 0
    if argv[0] == "--all":
        s = int(argv[1], 0)
        disas(s, s + (int(argv[2], 0) if len(argv) > 2 else 0x400),
              show_bytes=True)
        return 0
    if argv[0] == "--f":
        rva = int(argv[1], 0)
        f = func_of(rva)
        if not f:
            print(f"0x{rva:x} outside .pdata; use --all")
            return 1
        print(f"; func 0x{f[0]:x} .. 0x{f[1]:x}  ({f[1]-f[0]} B)")
        disas(f[0], f[1])
        return 0
    if len(argv) >= 2:
        disas(int(argv[0], 0), int(argv[1], 0))
        return 0
    rva = int(argv[0], 0)
    f = func_of(rva)
    if not f:
        print(f"0x{rva:x} outside .pdata; use --all")
        return 1
    print(f"; func 0x{f[0]:x} .. 0x{f[1]:x}  ({f[1]-f[0]} B), entry +0x{rva-f[0]:x}")
    disas(f[0], f[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
