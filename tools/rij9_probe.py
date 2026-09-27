#!/usr/bin/env python3
"""Probe the server's DFO-Rijndael12 (algo 9) native code as an oracle.

    0x5876f0  SetKey(this, ref span16)
    0x587860  Encrypt(this, ref src, ref dst)   (thunk -> 0x587880, ks=this+8)
    0x587870  Decrypt(this, ref src, ref dst)   (thunk -> 0x587880, ks=this+0x10)

this+8 = enc schedule, this+0x10 = dec schedule (managed int[]/struct).
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dfo_ciphers as DC  # noqa
from probe_util import (FN3, BASE, SPAN, call3, mk_u32_array,  # noqa
                        patch_validator_calls, rd_u32, rd_u64)

SETKEY = 0x5876F0
ENC = 0x587860
DEC = 0x587870
VALIDATORS = (0x5878DD,)

BLOB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto"
            r"\channelinfo_key_blob.bin")

FN2 = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(SPAN))


def dump_arr(ptr, n=128):
    ln = rd_u32(ptr + 8)
    vals = [rd_u32(ptr + 0x10 + 4 * i) for i in range(min(ln, n))]
    return ln, vals


def main():
    patch_validator_calls(VALIDATORS)
    this = (ctypes.c_uint8 * 0x20)()
    key = BLOB.read_bytes()[238:254]

    kb = (ctypes.c_uint8 * 16).from_buffer_copy(key)
    ks = SPAN(ctypes.cast(kb, ctypes.c_void_p), 16)
    FN2(BASE + SETKEY)(this, ctypes.byref(ks))
    pa = rd_u64(ctypes.addressof(this) + 8)
    pb = rd_u64(ctypes.addressof(this) + 0x10)
    print("key:", key.hex())
    for name, p in (("this+8 ", pa), ("this+10", pb)):
        ln, vals = dump_arr(p)
        print(f"{name} obj={p:#x} len={ln}:")
        print("   ", " ".join(f"{v:08x}" for v in vals))

    enc = FN3(BASE + ENC)
    dec = FN3(BASE + DEC)
    for pt in (bytes(16), bytes(range(16)),
               bytes.fromhex("ffff1900010014000000000000000000")):
        n_e = call3(enc, this, pt)
        n_d = call3(dec, this, n_e)
        print(f"  pt={pt.hex()}")
        print(f"    E native={n_e.hex()}")
        print(f"    D native={n_d.hex()}")


if __name__ == "__main__":
    main()
