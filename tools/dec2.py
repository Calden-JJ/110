#!/usr/bin/env python3
"""Decrypt observed packets with the code-verified ciphers and show plaintext."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from dfocipher import xtea_encrypt, xtea_decrypt, xor32_crypt, xor32_dword
from dec_probe import packets, key_of, LOG, show  # noqa


def xt(data: bytes, key: bytes, fn, be: bool):
    out = b""
    for i in range(0, len(data) - len(data) % 8, 8):
        out += fn(data[i:i + 8], key, be)
    out += data[len(data) - len(data) % 8:]
    return out


def main():
    ai = int(sys.argv[1], 0) if len(sys.argv) > 1 else 8
    key = key_of(ai)
    print(f"ai={ai} key={key.hex()}")
    for ln, conn, d, sub, total, body in packets(LOG):
        if sub % 14 != ai or not body:
            continue
        print(f"\nline {ln} {d} sub={sub:#x} body={len(body)}  ct={body.hex()}")
        if ai == 8:
            for nm, fn, be in (("enc-le", xtea_encrypt, False), ("dec-le", xtea_decrypt, False),
                               ("enc-be", xtea_encrypt, True), ("dec-be", xtea_decrypt, True)):
                show(nm, xt(body, key, fn, be))
        elif ai == 10:
            show("xor", xor32_crypt(body, key))


if __name__ == "__main__":
    main()
