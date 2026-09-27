#!/usr/bin/env python3
"""Force the launcher to emit `packetHexLog: true` into the server.json it writes.

The launcher rebuilds server.json from an inline anonymous object every launch,
so editing the file by hand never survives.  The object is laid out as

    newobj <>f__AnonymousType6`5::.ctor(string logDirectory, bool packetHexLog,
              int packetHexMaxBytes, bool accountPrivilege, int dungeonPartySlot)
    newobj <>f__AnonymousType1`8::.ctor(... , that, )   // the whole config

so the two constants sit in the 12 bytes right before the diagnostics newobj:

    ... 16 | 20 00 01 00 00 | 17 | 20 ff 00 00 00 | 73 <ctor>
        ^ldc.i4.0  ^ldc.i4 256

Flipping `16`->`17` turns the log on; `01`->`10` raises the cap 256 -> 4096.

Usage:
    python patch_launcher_hexlog.py <dll>                 # dry run
    python patch_launcher_hexlog.py <dll> --apply
    python patch_launcher_hexlog.py <dll> --apply --max-bytes 8192
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

import patch_pe_cli_field as P

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FIELD = "<packetHexLog>i__Field"


def find_diagnostics_ctor(m: P.Meta, data: bytes):
    """Return (memberref_rid, typedef_rid) of the diagnostics anon type ctor."""
    S, B = m.s_sz(), m.b_sz()
    field_rid = None
    off, sz = m.table_offset(0x04), m.row_size(0x04)
    for rid in range(1, m.rows.get(0x04, 0) + 1):
        o = off + (rid - 1) * sz
        if m.heap_str(int.from_bytes(data[o + 2:o + 2 + S], "little")) == FIELD:
            field_rid = rid
    if not field_rid:
        raise SystemExit(f"field {FIELD} not found")

    to, tsz = m.table_offset(0x02), m.row_size(0x02)
    csz = m.coded((0x02, 0x01, 0x1B), 2)
    owner = None
    for rid in range(1, m.rows[0x02] + 1):
        r = to + (rid - 1) * tsz
        fl = int.from_bytes(data[r + 4 + 2 * S + csz:r + 4 + 2 * S + csz + m.idx(0x04)],
                            "little")
        nxt_r = rid + 1
        if nxt_r <= m.rows[0x02]:
            r2 = to + (rid) * tsz
            nxt = int.from_bytes(
                data[r2 + 4 + 2 * S + csz:r2 + 4 + 2 * S + csz + m.idx(0x04)], "little")
        else:
            nxt = m.rows[0x04] + 1
        if fl <= field_rid < nxt:
            owner = rid
    if not owner:
        raise SystemExit("no TypeDef owns the field")

    bh = m.streams["#Blob"][0]

    def blob(i):
        p = bh + i
        b = data[p]
        if b & 0x80 == 0:
            ln, st = b, p + 1
        elif b & 0xC0 == 0x80:
            ln, st = ((b & 0x3F) << 8) | data[p + 1], p + 2
        else:
            ln, st = (((b & 0x1F) << 24) | (data[p + 1] << 16)
                      | (data[p + 2] << 8) | data[p + 3]), p + 4
        return data[st:st + ln]

    tso, tsz2 = m.table_offset(0x1B), m.row_size(0x1B)

    def ts_target(rid):
        r = tso + (rid - 1) * tsz2
        b = blob(int.from_bytes(data[r:r + B], "little"))
        if not b or b[0] != 0x15:
            return None
        return (b[2] >> 2) if (b[2] & 3) == 0 else None

    mo, msz = m.table_offset(0x0A), m.row_size(0x0A)
    ccsz = m.coded((0x02, 0x01, 0x1A, 0x06, 0x1B), 3)
    for rid in range(1, m.rows[0x0A] + 1):
        r = mo + (rid - 1) * msz
        cls = int.from_bytes(data[r:r + ccsz], "little")
        nm = m.heap_str(int.from_bytes(data[r + ccsz:r + ccsz + S], "little"))
        if nm == ".ctor" and (cls & 7) == 4 and ts_target(cls >> 3) == owner:
            return rid, owner
    raise SystemExit("no ctor MemberRef for the diagnostics type")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll", type=Path)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--max-bytes", type=int, default=4096)
    args = ap.parse_args()

    data = args.dll.read_bytes()
    m = P.Meta(data)
    mr_rid, td_rid = find_diagnostics_ctor(m, data)
    token = 0x0A000000 | mr_rid
    print(f"diagnostics type : TypeDef {td_rid}, ctor MemberRef {mr_rid} "
          f"(token 0x{token:08x})")

    pat = b"\x73" + P.tok(token)
    hits = []
    for rid, rva, n_off in m.method_rows():
        body, code_off = m.il_body(rva)
        i = body.find(pat)
        while i >= 0:
            hits.append((m.heap_str(n_off), code_off + i, code_off + i - 12))
            i = body.find(pat, i + 1)
    if len(hits) != 1:
        print(f"[!] expected exactly 1 construction site, found {len(hits)}")
        for nm, fo, _ in hits:
            print(f"    in {nm} @0x{fo:x}")
        return 1

    name, newobj_off, flag_off = hits[0]
    ctx = data[flag_off:newobj_off]
    print(f"built in         : {name}()  newobj @file 0x{newobj_off:x}")
    print(f"constants        : {ctx.hex(' ')}")
    want = bytes.fromhex("1620000100001720ff000000")
    if ctx != want:
        print(f"[!] unexpected constant block (want {want.hex(' ')}) -- refusing")
        return 1

    old_max = struct.unpack_from("<i", data, flag_off + 2)[0]
    print(f"packetHexLog     : false  -> true      (file 0x{flag_off:x})")
    print(f"packetHexMaxBytes: {old_max} -> {args.max_bytes}  (file 0x{flag_off + 2 + 1:x})")
    if not 16 <= args.max_bytes <= 65536:
        print("[!] --max-bytes outside the server's accepted 16..65536")
        return 1

    if not args.apply:
        print("\ndry run -- pass --apply to write")
        return 0

    buf = bytearray(data)
    buf[flag_off] = 0x17
    struct.pack_into("<i", buf, flag_off + 2, args.max_bytes)
    changed = [i for i, (a, b) in enumerate(zip(data, buf)) if a != b]
    if len(changed) != 2:
        print(f"[!] expected 2 changed bytes, would change {len(changed)}")
        return 1

    bak = args.dll.with_suffix(args.dll.suffix + ".bak")
    if not bak.exists():
        bak.write_bytes(data)
        print(f"\nbackup           : {bak}")
    else:
        print(f"\nbackup           : {bak} (already exists, kept)")
    args.dll.write_bytes(bytes(buf))
    print(f"patched          : {args.dll}")
    print(f"  sha256 {hashlib.sha256(data).hexdigest()[:16]} -> "
          f"{hashlib.sha256(bytes(buf)).hexdigest()[:16]}")
    print(f"  restore with   : cp '{bak}' '{args.dll}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
