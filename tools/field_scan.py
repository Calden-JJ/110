#!/usr/bin/env python3
"""Which functions touch a struct offset -- to name fields by their log literals.

  python field_scan.py 0xf4 0x118 0x120 [--size 1] [--max 60]

Scans every capstone instruction in .text for a non-RIP memory operand with one
of the watched displacements (optionally `--size` filters the access width in
bytes), then prints the enclosure (.pdata function), the instruction, and up to
three frozen literals the function references.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import (D, TXT_S, TXT_E, rva2off, func_of, _lits_in)  # noqa

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = 0x140000000


def scan(disps, size=None):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    o0 = rva2off(TXT_S)
    code = D[o0:o0 + (TXT_E - TXT_S)]
    out = []
    for ins in md.disasm(code, BASE + TXT_S):
        for op in ins.operands:
            if op.type != X86_OP_MEM or op.mem.base == X86_REG_RIP:
                continue
            if op.mem.disp not in disps:
                continue
            if size is not None and op.size != size:
                continue
            out.append((ins.address - BASE, op.mem.disp, op.size, ins))
            break
    return out


def main(argv):
    disps, size, limit = set(), None, 80
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--size":
            i += 1
            size = int(argv[i], 0)
        elif a == "--max":
            i += 1
            limit = int(argv[i], 0)
        else:
            disps.add(int(a, 0))
        i += 1
    per_func: dict[int, list] = {}
    for rva, disp, sz, ins in scan(disps, size):
        f = func_of(rva)
        per_func.setdefault(f[0] if f else 0, []).append((rva, disp, sz, ins))
    print(f"{sum(len(v) for v in per_func.values())} access(es) over "
          f"{len(per_func)} function(s)")
    for start in sorted(per_func):
        rows = per_func[start]
        f = func_of(start) if start else None
        if not f:
            continue
        lits = _lits_in(f[0], min(f[1], f[0] + 0x600), k=4)
        print(f"\n== func 0x{start:x}..0x{f[1]:x} ({f[1] - f[0]} B)  "
              f"{' | '.join(lits)}")
        for rva, disp, sz, ins in rows[:limit]:
            print(f"   0x{rva:06x} +0x{rva - start:<5x} [{disp:#x}:{sz}] "
                  f"{ins.mnemonic} {ins.op_str}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
