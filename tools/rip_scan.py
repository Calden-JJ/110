#!/usr/bin/env python3
"""Precise capstone scan: every instruction in .text whose rip-relative operand
resolves to a watched absolute rva.

  python rip_scan.py 0x361d00 0x3635a0 ...
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import D, TXT_S, TXT_E, rva2off, func_of  # noqa

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = 0x140000000


def scan(watch, md=None):
    md = md or Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    D0 = rva2off(TXT_S)
    code = D[D0:D0 + (TXT_E - TXT_S)]
    out = []
    for ins in md.disasm(code, BASE + TXT_S):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp - BASE
                if t in watch:
                    out.append((t, ins.address - BASE, ins))
    return out


def main(argv):
    watch = set()
    for a in argv:
        watch.add(int(a, 0) if not a.startswith("0x1") else int(a, 0) - BASE)
    hits = scan(watch)
    per = {}
    for t, rva, ins in hits:
        per.setdefault(t, []).append((rva, ins))
    for t in sorted(per):
        print(f"\n== watch 0x{t:x}  ({len(per[t])} refs)")
        for rva, ins in per[t]:
            f = func_of(rva)
            fs = f"func 0x{f[0]:x}" if f else "?"
            print(f"   {fs:>14} +0x{rva - (f[0] if f else 0):-<5x}  {rva:#08x}  "
                  f"{ins.mnemonic} {ins.op_str}")


if __name__ == "__main__":
    main(sys.argv[1:])
