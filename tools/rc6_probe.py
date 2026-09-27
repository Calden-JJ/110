#!/usr/bin/env python3
"""Probe the server's RC6-480-DFO native code as an oracle.

Builds a fake cipher object ([+8] = managed byte[44] subkey table) and calls
the primitives directly:
    0x5871e0  SetKey(this, ref span64)   -- fills this+8 from a 32B key
    0x587340  EncryptBlock(this, ref src, ref dst)
    0x587520  DecryptBlock(this, ref src, ref dst)

Compares the native results with tools/dfo_ciphers.rc6_dfo_* to pin down where
they diverge.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dfo_ciphers as DC  # noqa
from run_native import BASE, SPAN, map_image  # noqa

BLOCK_ENC = 0x587340
BLOCK_DEC = 0x587520
SETKEY = 0x5871E0
CTOR = 0x586EC0

FN3 = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                       ctypes.POINTER(SPAN), ctypes.POINTER(SPAN))
FN1 = ctypes.CFUNCTYPE(None, ctypes.c_void_p)


def make_slot(nbytes: int):
    """[+0]=EEType(ignored), [+8]=length, [+0x10..]=data."""
    buf = (ctypes.c_uint8 * (0x10 + nbytes))()
    struct.pack_into("<I", buf, 8, nbytes)
    return buf, (ctypes.c_uint8 * nbytes).from_buffer(buf, 0x10)


def make_this(slot) -> ctypes.Array:
    this = (ctypes.c_uint8 * 0x10)()
    struct.pack_into("<Q", this, 8, ctypes.addressof(slot))
    return this


def sp(buf: bytes):
    src = (ctypes.c_uint8 * len(buf)).from_buffer_copy(buf)
    s = SPAN(ctypes.cast(src, ctypes.c_void_p), len(buf))
    return src, s, SPAN(ctypes.cast(src, ctypes.c_void_p), len(buf))


def call3(fn, this, data: bytes) -> bytes:
    src, s, _ = sp(data)
    dst = (ctypes.c_uint8 * len(data))()
    d = SPAN(ctypes.cast(dst, ctypes.c_void_p), len(data))
    fn(this, ctypes.byref(s), ctypes.byref(d))
    return bytes(dst)


def native_setkey(key32: bytes) -> bytes:
    slot, view = make_slot(44)
    this = make_this(slot)
    kb = (ctypes.c_uint8 * len(key32)).from_buffer_copy(key32)
    ks = SPAN(ctypes.cast(kb, ctypes.c_void_p), len(key32))
    FN3(BASE + SETKEY)(this, ctypes.byref(ks), None)
    return bytes(bytearray(view))


def main():
    map_image()
    blob = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto"
                r"\channelinfo_key_blob.bin").read_bytes()
    key60 = blob[32:92]
    key32 = key60[:32]

    nat = native_setkey(key32)
    mine = DC._rc6_dfo_schedule(key60)
    print("native S:", nat.hex())
    print("mine   S:", mine.hex())
    print("schedule match:", nat == mine)
    if nat != mine:
        print("  first diff:", next(i for i in range(44) if nat[i] != mine[i]))

    slot, view = make_slot(44)
    view[:] = nat[:]
    this = make_this(slot)
    enc = FN3(BASE + BLOCK_ENC)
    dec = FN3(BASE + BLOCK_DEC)

    for pt in (bytes(16), bytes(range(16)),
               bytes.fromhex("ffff1900010014000000000000000000")):
        n_enc = call3(enc, this, pt)
        p_enc = DC.rc6_dfo_encrypt(pt, key60)
        n_dec = call3(dec, this, n_enc)
        print(f"  E({pt.hex()[:16]}..) native={n_enc.hex()} mine={p_enc.hex()} "
              f"{'OK' if n_enc == p_enc else 'DIFF'}  D(native)={n_dec.hex()}")


if __name__ == "__main__":
    main()
