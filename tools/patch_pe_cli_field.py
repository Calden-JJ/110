#!/usr/bin/env python3
"""Find a .NET field by name in a PE assembly and flip its IL constant store.

Pure-Python PE + CLI metadata reader.  It locates the Field row for a named
field, then disassembles-enough every MethodDef body to find `ldc.i4.X; stfld
<field>` -- i.e. the C# field initializer -- so a boolean default can be
flipped without a decompiler.

The metadata walk is validated by printing the table layout it derived; if the
row sizes were wrong the named field would not be found and nothing is written.

Usage:
    python patch_pe_cli_field.py asm.dll --find '<packetHexLog>i__Field'
    python patch_pe_cli_field.py asm.dll --find NAME --getter get_packetHexLog
    python patch_pe_cli_field.py asm.dll --find NAME --set 1 --out patched.dll
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


def tok(t: int) -> bytes:
    """Inline metadata operands are 4-byte little-endian tokens (ECMA-335 III.3)."""
    return t.to_bytes(4, "little")


class Pe:
    def __init__(self, data: bytes):
        self.d = data
        lfanew = u32(data, 0x3C)
        if data[lfanew:lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE image")
        coff = lfanew + 4
        nsec, opt_size = u16(data, coff + 2), u16(data, coff + 16)
        opt = coff + 20
        self.plus = u16(data, opt) == 0x20B
        self.dd_off = opt + (112 if self.plus else 96)
        sec = opt + opt_size
        self.sections = []
        for i in range(nsec):
            o = sec + 40 * i
            name = data[o:o + 8].rstrip(b"\0").decode("latin1")
            vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append((name, va, max(vsz, rsz), raw))

    def rva(self, va: int) -> int:
        for name, base, size, raw in self.sections:
            if base <= va < base + size:
                return raw + (va - base)
        raise ValueError(f"RVA 0x{va:x} outside all sections")

    def cli(self) -> int:
        rva, _size = struct.unpack_from("<II", self.d, self.dd_off + 14 * 8)
        if not rva:
            raise ValueError("not a managed assembly (no CLI directory)")
        return self.rva(rva)


class Meta:
    def __init__(self, data: bytes):
        self.data = data
        self.pe = Pe(data)
        d = data
        cli = self.pe.cli()
        self.root = self.pe.rva(u32(d, cli + 8))
        if u32(d, self.root) != 0x424A5342:
            raise ValueError("bad metadata root signature")

        ver_len = u32(d, self.root + 12)
        p = self.root + 16 + ver_len
        n_streams = u16(d, p + 2)
        p += 4
        self.streams: dict[str, tuple[int, int]] = {}
        for _ in range(n_streams):
            off, size = u32(d, p), u32(d, p + 4)
            p += 8
            q = p
            while d[q] != 0:
                q += 1
            name = d[p:q].decode("latin1")
            p = q + 1
            while (p - self.root) % 4:
                p += 1
            self.streams[name] = (self.root + off, size)

        self.str_heap = self.streams["#Strings"][0]
        tn = "#~" if "#~" in self.streams else "#-"
        self.tbl_off = self.streams[tn][0]
        self.heaps = d[self.tbl_off + 6]
        valid = u64(d, self.tbl_off + 8)
        self.rows: dict[int, int] = {}
        p = self.tbl_off + 24
        for i in range(64):
            if valid >> i & 1:
                self.rows[i] = u32(d, p)
                p += 4
        self.tbl_start = p

    # -- heap index widths ---------------------------------------------------
    def s_sz(self): return 4 if self.heaps & 1 else 2
    def g_sz(self): return 4 if self.heaps & 2 else 2
    def b_sz(self): return 4 if self.heaps & 4 else 2
    def idx(self, t): return 4 if self.rows.get(t, 0) >= 0x10000 else 2

    def coded(self, tables, bits):
        mx = max(self.rows.get(t, 0) for t in tables)
        return 2 if mx < (1 << (16 - bits)) else 4

    def row_size(self, t):
        S, G, B = self.s_sz(), self.g_sz(), self.b_sz()
        if t == 0x00: return 2 + S + 3 * G
        if t == 0x01: return self.coded((0x00, 0x1A, 0x23, 0x01), 2) + 2 * S
        if t == 0x02: return 4 + 2 * S + self.coded((0x02, 0x01, 0x1B), 2) \
                            + self.idx(0x04) + self.idx(0x06)
        if t == 0x03: return self.idx(0x04)
        if t == 0x04: return 2 + S + B
        if t == 0x05: return self.idx(0x06)
        if t == 0x06: return 8 + S + B + self.idx(0x08)
        if t == 0x07: return self.idx(0x08)
        if t == 0x08: return 4 + S
        if t == 0x09: return self.idx(0x02) + self.coded((0x02, 0x01, 0x1B), 2)
        if t == 0x0A: return self.coded((0x02, 0x01, 0x1A, 0x06, 0x1B), 3) + S + B
        if t == 0x0B: return 2 + self.coded((0x04, 0x08, 0x17), 2) + B
        if t == 0x0C: return self.coded((0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00,
                                         0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23,
                                         0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B), 5) \
                            + self.coded((0x06, 0x0A), 3) + B
        if t == 0x0D: return self.coded((0x04, 0x08), 1) + B
        if t == 0x0E: return 2 + self.coded((0x02, 0x06, 0x20), 2) + B
        if t == 0x0F: return 6 + self.idx(0x02)
        if t == 0x10: return 4 + self.idx(0x04)
        if t == 0x11: return B
        if t == 0x12: return self.idx(0x02) + self.idx(0x14)
        if t == 0x13: return self.idx(0x14)
        if t == 0x14: return 2 + S + self.coded((0x02, 0x01, 0x1B), 2)
        if t == 0x15: return self.idx(0x02) + self.idx(0x17)
        if t == 0x16: return self.idx(0x17)
        if t == 0x17: return 2 + S + B
        if t == 0x18: return 2 + self.idx(0x06) + self.coded((0x14, 0x17), 1)
        if t == 0x19: return self.idx(0x02) + 2 * self.coded((0x06, 0x0A), 1)
        if t == 0x1A: return S
        if t == 0x1B: return B
        raise NotImplementedError(f"row size unknown for table 0x{t:02x}")

    def table_offset(self, t):
        off = self.tbl_start
        for i in range(t):
            if i in self.rows:
                off += self.rows[i] * self.row_size(i)
        return off

    def heap_str(self, off: int) -> str:
        d, p = self.data, self.str_heap + off
        q = p
        while d[q] != 0:
            q += 1
        return d[p:q].decode("utf-8", "replace")

    def field_rows(self):
        off, sz, S = self.table_offset(0x04), self.row_size(0x04), self.s_sz()
        for rid in range(1, self.rows.get(0x04, 0) + 1):
            o = off + (rid - 1) * sz
            n = u32(self.data, o + 2) if S == 4 else u16(self.data, o + 2)
            yield rid, o, n

    def method_rows(self):
        off, sz, S = self.table_offset(0x06), self.row_size(0x06), self.s_sz()
        for rid in range(1, self.rows.get(0x06, 0) + 1):
            o = off + (rid - 1) * sz
            n = u32(self.data, o + 8) if S == 4 else u16(self.data, o + 8)
            yield rid, u32(self.data, o), n

    def il_body(self, rva: int):
        """Return (code_bytes, file_offset_of_code) for a method body."""
        if not rva:
            return b"", 0
        o = self.pe.rva(rva)
        b0 = self.data[o]
        if b0 & 3 == 2:                     # tiny header
            size = b0 >> 2
            return self.data[o + 1:o + 1 + size], o + 1
        if b0 & 3 == 3:                     # fat header
            size = u32(self.data, o + 4)
            return self.data[o + 12:o + 12 + size], o + 12
        return b"", 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("assembly", type=Path)
    ap.add_argument("--find", default=None, help="exact field name in #Strings")
    ap.add_argument("--token", default=None,
                    help="scan for a raw metadata token instead, e.g. 0x0A00014C")
    ap.add_argument("--getter", default=None,
                    help="method name expected to ldfld the field (sanity check)")
    ap.add_argument("--set", type=int, default=None, choices=(0, 1),
                    help="value to force the ldc.i4 before stfld")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    data = args.assembly.read_bytes()
    m = Meta(data)

    print(f"assembly : {args.assembly}  ({len(data)} bytes)")
    present = ", ".join(f"0x{t:02x}x{n}" for t, n in sorted(m.rows.items()) if t <= 0x0C)
    print(f"heaps    : strings={'4B' if m.s_sz() == 4 else '2B'} "
          f"guid={'4B' if m.g_sz() == 4 else '2B'} blob={'4B' if m.b_sz() == 4 else '2B'}")
    print(f"tables   : {present}")
    print(f"offsets  : Field=0x{m.table_offset(0x04):x}(row {m.row_size(0x04)}B) "
          f"MethodDef=0x{m.table_offset(0x06):x}(row {m.row_size(0x06)}B)")

    if args.token:
        token = int(args.token, 16)
        print(f"\ntoken    : 0x{token:08x} (table 0x{token >> 24:02x}, RID {token & 0xFFFFFF})")
    elif args.find:
        hit = None
        for rid, o, n in m.field_rows():
            if m.heap_str(n) == args.find:
                hit = (rid, o)
                break
        if not hit:
            print(f"\n[!] field {args.find!r} NOT found -- metadata walk is wrong")
            return 1
        rid, row_off = hit
        token = 0x04000000 | rid
        print(f"\nfield    : {args.find!r} -> RID {rid}, token 0x{token:08x} "
              f"(row at file 0x{row_off:x})")
    else:
        print("\n[!] need --find or --token")
        return 2

    uses = {0x7B: "ldfld", 0x7C: "ldflda", 0x7D: "stfld", 0x7E: "ldsfld",
            0x80: "stsfld", 0x73: "newobj", 0x28: "call", 0x6F: "callvirt",
            0xD0: "ldtoken"}
    sites = []
    seen_bytes = n_bodies = 0
    for op, label in uses.items():
        pat = bytes([op]) + tok(token)
        for mrid, rva, n_off in m.method_rows():
            body, code_off = m.il_body(rva)
            if body:
                n_bodies += 1
                seen_bytes += len(body)
            start = 0
            while True:
                i = body.find(pat, start)
                if i < 0:
                    break
                before = data[code_off + i - 1] if i else None
                sites.append({"op": label, "rid": mrid, "name": m.heap_str(n_off),
                              "il_off": i, "prev": before,
                              "file_off": code_off + i - 1, "body": body})
                start = i + 1
    print(f"IL scan  : {n_bodies} bodies, {seen_bytes} bytes scanned "
          f"(operand {tok(token).hex()})")
    if not sites:
        print("  no references found")

    for s in sites:
        prev = f"0x{s['prev']:02x}" if s["prev"] is not None else "??"
        const = {0x16: "ldc.i4.0", 0x17: "ldc.i4.1", 0x15: "ldc.i4.m1"}.get(s["prev"], "")
        print(f"  {s['op']:8} in {s['name']:34} il+0x{s['il_off']:04x}  "
              f"prev={prev} {const}")
        print(f"      file 0x{s['file_off']:x}  ctx: "
              f"{s['body'][max(0, s['il_off'] - 32):s['il_off'] + 5].hex(' ')}")

    if args.getter:
        names = {m.heap_str(n) for _r, _v, n in m.method_rows()}
        print(f"\ngetter   : {args.getter!r} {'present' if args.getter in names else 'ABSENT'}")
        if args.getter not in names:
            print("           (field id unconfirmed -- check the walk above)")

    if args.set is None:
        return 0

    want_ldc = 0x17 if args.set else 0x16
    targets = [s for s in sites
               if s["op"] == "stfld" and s["prev"] in (0x15, 0x16, 0x17)
               and s["prev"] != want_ldc]
    if not targets:
        print("\nnothing to change")
        return 0
    if not args.out:
        print("\n[!] --set given without --out")
        return 2

    buf = bytearray(data)
    for s in targets:
        print(f"patch    : file 0x{s['file_off']:x}  "
              f"{buf[s['file_off']]:02x} -> {want_ldc:02x}  ({s['name']})")
        buf[s["file_off"]] = want_ldc
    args.out.write_bytes(bytes(buf))
    print(f"wrote    : {args.out}  ({len(buf)} bytes, "
          f"{sum(1 for a, b in zip(data, buf) if a != b)} byte(s) changed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
