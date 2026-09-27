#!/usr/bin/env python3
"""Try every cipher transform on observed packets of a given algo id."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from dfocipher import xtea_encrypt, xtea_decrypt, xor32_crypt
from dec_probe import packets, key_of, LOG, show  # noqa


def xt(data: bytes, key: bytes, fn, be: bool):
    out = b""
    n = len(data) - len(data) % 8
    for i in range(0, n, 8):
        out += fn(data[i:i + 8], key, be)
    return out + data[n:]


def main():
    ai = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0
    d1 = sys.argv[2] if len(sys.argv) > 2 else None
    key = key_of(ai)
    print(f"ai={ai} key({len(key)}B)={key.hex()}")
    for ln, conn, d, sub, total, body in packets(LOG, d1):
        if sub % 14 != ai or not body:
            continue
        print(f"\nline {ln} {d} sub={sub:#x} body={len(body)}  ct={body.hex()}")
        if ai in (0, 8):
            for nm, fn, be in (("enc-le", xtea_encrypt, False), ("dec-le", xtea_decrypt, False),
                               ("enc-be", xtea_encrypt, True), ("dec-be", xtea_decrypt, True)):
                show(nm, xt(body, key, fn, be))
        elif ai == 10:
            show("xor", xor32_crypt(body, key))


if __name__ == "__main__":
    main()
