#!/usr/bin/env python3
"""Decrypt observed packet bodies with candidate ciphers and show plaintext."""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

LOG = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\Logs\server-20260926.log")
BLOB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto\channelinfo_key_blob.bin")
KEYS = {0: (0, 16), 1: (16, 16), 2: (32, 60), 3: (92, 32), 4: (124, 16),
        5: (140, 10), 6: (150, 16), 7: (166, 56), 8: (222, 16), 9: (238, 16),
        10: (254, 8), 11: (262, 16), 12: (278, 16), 13: (294, 40)}
D = BLOB.read_bytes()
RE = re.compile(r"DEBUG PACKET\s+conn=(\d+)\s+([SC])->([SC]) game raw=(\d+) sent hex=([0-9a-f]+)")
RE_CS = re.compile(r"DEBUG PACKET\s+conn=(\d+)\s+([SC])->([SC]) game \((\d+),(\d+)\)"
                   r" wire=(\d+) body=(\d+) state=\S+ hex=([0-9a-f]+)")
HDR = {"S->C": 16, "C->S": 13}


def key_of(ai):
    off, ln = KEYS[ai]
    return D[off:off + ln]


def xor_cycle_dec(ct: bytes, key: bytes, bs: int, global_off: int = 0):
    out = bytearray()
    for i, b in enumerate(ct):
        out.append(b ^ key[(global_off + i) % len(key)])
    return bytes(out)


def show(tag, pt):
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in pt)
    print(f"    {tag:<22} {pt.hex()}")
    print(f"    {'':<22} |{asc}|")


def packets(path, fdir=None):
    for ln, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        m = RE.search(line)
        if m:
            conn, d1, d2, raw, hexs = m.groups()
            d = f"{d1}->{d2}"
            b = bytes.fromhex(hexs)
            if len(b) < HDR[d]:
                continue
            if fdir and d != fdir:
                continue
            sub = int.from_bytes(b[1:3], "little")
            total = int.from_bytes(b[3:7], "little")
            yield ln, conn, d, sub, total, b[HDR[d]:]
            continue
        m = RE_CS.search(line)
        if not m:
            continue
        conn, d1, d2, main, sub, wire, body, hexs = m.groups()
        d = f"{d1}->{d2}"
        if fdir and d != fdir:
            continue
        b = bytes.fromhex(hexs)
        if len(b) < HDR[d]:
            continue
        yield ln, conn, d, int(sub), int.from_bytes(b[3:7], "little"), b[HDR[d]:]


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "xor"
    if what == "xor":
        ai = 10
        k = key_of(ai)
        print(f"XOR-32 key({len(k)}B) = {k.hex()}")
        for ln, conn, d, sub, total, body in packets(LOG):
            if sub % 14 != ai or not body:
                continue
            print(f"  line {ln} {d} sub={sub:#x} body={len(body)}")
            for name, off in (("pkt-local", 0), ):
                show(f"xor cycle off={off}", xor_cycle_dec(body, k, 4, off))
            # try both 4/8-byte cycle phase shifts
            for ph in range(4):
                show(f"xor phase={ph}", xor_cycle_dec(body, k[ph:] + k[:ph], 4, 0))
    elif what == "xtea":
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).parent))
        from dfocipher import xtea_decrypt
        for ai, be in ((0, True), (8, False)):
            k = key_of(ai)
            print(f"XTEA ai={ai} key = {k.hex()}")
            for hexct in ("a7c02233e5721520", "42d6b8d8e9e84eda",
                          "94c6b7441a8ee699", "436ec337946d27d6"):
                pt = xtea_decrypt(bytes.fromhex(hexct), k, be)
                print(f"  D({hexct}) = {pt.hex()}")
    elif what == "dump":
        for ln, conn, d, sub, total, body in packets(LOG, sys.argv[2] if len(sys.argv) > 2 else None):
            ai = sub % 14
            print(f"{ln:5d} {d} sub={sub:#06x} ai={ai:2d} total={total} body={len(body)} {body.hex()}")


if __name__ == "__main__":
    main()
