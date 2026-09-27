#!/usr/bin/env python3
"""Scratch IL dumper for the launcher assemblies (Phase 0.2 reconnaissance).

Obfuscar 2.2.50 renamed most internal types but left IL intact and public
names readable; string literals are encrypted.  This dumps method bodies with
member/string operands resolved well enough to read control flow and payload
construction.

    python tools/_ildump.py <assembly.dll> <TypeName> [method ...]
    python tools/_ildump.py <assembly.dll> <TypeName> --all
"""
from __future__ import annotations

import sys
from pathlib import Path

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.clr.token import StringToken, Token


def _owner_map(pe: dnfile.dnPE) -> dict[int, str]:
    """MethodDef rid -> owning type name."""
    out: dict[int, str] = {}
    for t in pe.net.mdtables.TypeDef:
        for i, x in enumerate(t.MethodList):
            out[x.row_index] = f"{t.TypeNamespace}.{t.TypeName}".strip(".")
    return out


def resolve(pe: dnfile.dnPE, tok, owners: dict[int, str]) -> str:
    if isinstance(tok, StringToken):
        try:
            s = pe.net.user_strings.get(tok.offset)
            return f'"{s.value}"' if s else "str:?"
        except Exception:
            return f"str@0x{tok.offset:x}"
    if isinstance(tok, Token):
        table, rid = tok.table, tok.rid
        names = {0x01: "TypeRef", 0x02: "TypeDef", 0x04: "Field", 0x06: "MethodDef",
                 0x0A: "MemberRef", 0x11: "StandAloneSig", 0x1B: "TypeSpec",
                 0x2B: "MethodSpec"}
        tn = names.get(table, f"tbl0x{table:02x}")
        try:
            if table == 0x0A:
                r = pe.net.mdtables.MemberRef.rows[rid - 1]
                cls = r.Class
                try:
                    cname = f"{cls.row.TypeNamespace}.{cls.row.TypeName}".strip(".")
                except Exception:
                    cname = "?"
                return f"MemberRef {cname}::{r.Name}"
            if table == 0x06:
                r = pe.net.mdtables.MethodDef.rows[rid - 1]
                own = owners.get(rid, "?")
                return f"{own}::{r.Name}"
            if table == 0x01:
                r = pe.net.mdtables.TypeRef.rows[rid - 1]
                return f"TypeRef {r.TypeNamespace}.{r.TypeName}"
            if table == 0x04:
                r = pe.net.mdtables.Field.rows[rid - 1]
                own = ""
                try:
                    own = f"{r.Type.row.TypeName}." if r.Type else ""
                except Exception:
                    pass
                return f"Field {own}{r.Name}"
            if table == 0x02:
                r = pe.net.mdtables.TypeDef.rows[rid - 1]
                return f"TypeDef {r.TypeName}"
            if table == 0x11:
                return f"sig 0x{rid:x}"
            if table == 0x1B:
                return f"TypeSpec 0x{rid:x}"
            if table == 0x2B:
                r = pe.net.mdtables.MethodSpec.rows[rid - 1]
                return f"MethodSpec {r.Method}"
        except Exception:
            pass
        return f"{tn} 0x{rid:x}"
    return str(tok) if tok is not None else ""


def main(argv: list[str]) -> int:
    asm, tname = Path(argv[1]), argv[2]
    want = argv[3:]
    pe = dnfile.dnPE(str(asm))
    data = pe.__data__
    owners = _owner_map(pe)
    types = [t for t in pe.net.mdtables.TypeDef if t.TypeName == tname]
    if not types:
        print(f"no type named {tname}")
        return 1
    for t in types:
        for x in t.MethodList:
            m = x.row
            if want and want != ["--all"] and m.Name not in want:
                continue
            print(f"\n===== {tname}.{m.Name}  rva=0x{m.Rva:x} =====")
            if not m.Rva:
                print("  (no body)")
                continue
            try:
                body = read_method_body_from_bytes(data[pe.get_offset_from_rva(m.Rva):])
            except Exception as e:
                print("  <no IL>", e)
                continue
            for insn in body.instructions:
                op = resolve(pe, insn.operand, owners) if insn.operand is not None else ""
                print(f"  IL_{insn.offset:04x}: {insn.opcode.name:14s} {op}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
