#!/usr/bin/env python3
"""Recover the string table of an Obfuscar-protected launcher assembly.

Obfuscar 2.2.50 moves every literal into one `<PrivateImplementationDetails>`
type: a static `byte[]` blob (fields ``3``/``4``/``5`` of a compiler-generated
class) whose bytes are folded at class-init time with ``b[i] ^= i ^ 0xAA``, plus
one visible-accessor per string that returns ``Encoding.UTF8.GetString(b, off,
len)``.  Public/renamed method names survive, so dumping the accessor -> string
map recovers log lines, messages and CLI literals verbatim.

    python tools/extract_launcher_strings.py <assembly> [--json out.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes


def _s(h) -> str:
    return f"{h}"


def _find_blob_type(pe: dnfile.dnPE):
    for ti, t in enumerate(pe.net.mdtables.TypeDef):
        mnames = {_s(x.row.Name) for x in t.MethodList}
        fnames = {_s(x.row.Name) for x in t.FieldList}
        if "6" in mnames and {"3", "4", "5"} <= fnames:
            return ti, t
    raise SystemExit("no PrivateImplementationDetails string blob found")


def _blob(pe: dnfile.dnPE) -> bytes:
    """Decrypt the static byte[] (the cctor XORs with the byte index and 0xAA)."""
    md = pe.net.mdtables
    _, t = _find_blob_type(pe)
    rvas = {fr.Field.row_index: fr.Rva for fr in md.FieldRva.rows}
    rid = {_s(x.row.Name): x.row_index for x in t.FieldList}["3"]
    off = pe.get_offset_from_rva(rvas[rid])
    # newarr size lives in the cctor; 20538 for Launcher.dll.  Derive from the
    # next RVA-section boundary instead of hard-coding: walk forward to the
    # nearest FieldRVA above ours, else to the end of the section.
    nxt = sorted(r for r in rvas.values() if r > rvas[rid])
    size = (nxt[0] - rvas[rid]) if nxt else 0
    if size <= 0:
        size = 20538
    enc = bytes(pe.__data__[off:off + size])
    return bytes(b ^ (i & 0xFF) ^ 0xAA for i, b in enumerate(enc))


def _accessors(pe: dnfile.dnPE, blob: bytes) -> dict[str, str]:
    """method name -> decoded string.

    Every accessor is the same 11-instruction stub::

        ldsfld cache; ldc.i4 idx; ldelem.ref; dup; brtrue.s; pop;
        ldc.i4 idx; ldc.i4 off; ldc.i4 len; call <method 6>; ret

    so the string is read off the three literals feeding the ``call``.
    """
    md = pe.net.mdtables
    _, t = _find_blob_type(pe)
    out: dict[str, str] = {}
    for x in t.MethodList:
        m = x.row
        if not m.Rva:
            continue
        try:
            body = read_method_body_from_bytes(pe.__data__[pe.get_offset_from_rva(m.Rva):])
        except Exception:
            continue
        ins = body.instructions
        if len(ins) != 11 or ins[6].opcode.name != "ldc.i4" or ins[9].opcode.name != "call":
            continue
        off, ln = ins[7].operand, ins[8].operand
        if isinstance(off, int) and isinstance(ln, int) and 0 <= off and off + ln <= len(blob):
            out[_s(m.Name)] = blob[off:off + ln].decode("utf-8", "replace")
    return out


def main(argv: list[str]) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    asm = Path(argv[1])
    pe = dnfile.dnPE(str(asm))
    blob = _blob(pe)
    table = _accessors(pe, blob)
    print(f"{asm.name}: blob {len(blob)} B, {len(table)} accessor(s)")
    for name, s in sorted(table.items(), key=lambda kv: kv[0]):
        print(f"  {name:4s} = {s!r}")
    if "--json" in argv:
        out = Path(argv[argv.index("--json") + 1])
        out.write_text(json.dumps(table, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
