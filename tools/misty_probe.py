#!/usr/bin/env python3
"""Probe the server's MISTY1-DFO native code as an oracle.

Builds a fake cipher object ([+8] = int[64] EK, [+0x10]/[+0x18] = live S7/S9
managed arrays pulled out of the image) and calls the primitives:

    0x586ac0  KeySchedule(this, ref span16)
    0x586d00  FL(x, k1, k2)              (no `this`)
    0x586d40  FO(this, x, k)
    0x586e20  FI(this, x, key)
    0x5866e0  Encrypt(this, ref src, ref dst)
    0x5868e0  Decrypt(this, ref src, ref dst)

Compares everything with tools/dfo_ciphers misty1_dfo_* to pin down divergences.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dfo_ciphers as DC  # noqa
from run_native import BASE, SPAN, map_image  # noqa

SCHED = 0x586AC0
BLOCK_ENC = 0x5866E0
BLOCK_DEC = 0x5868E0
FO_RVA = 0x586D40
FL_RVA = 0x586D00
FI_RVA = 0x586E20
VALIDATOR_CALLS = (0x58673A, 0x58692E)

BLOB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto"
            r"\channelinfo_key_blob.bin")

FN2 = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(SPAN))
FN3 = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                       ctypes.POINTER(SPAN), ctypes.POINTER(SPAN))
FLT = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint32,
                       ctypes.c_uint32, ctypes.c_uint32)
FOT = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p,
                       ctypes.c_uint32, ctypes.c_uint32)


def rd_u32(addr):
    return struct.unpack("<I", ctypes.string_at(addr, 4))[0]


def rd_u64(addr):
    return struct.unpack("<Q", ctypes.string_at(addr, 8))[0]


def mk_u32_array(vals):
    buf = (ctypes.c_uint8 * (0x10 + 4 * len(vals)))()
    struct.pack_into("<I", buf, 8, len(vals))
    for i, v in enumerate(vals):
        struct.pack_into("<I", buf, 0x10 + 4 * i, v)
    return buf


# raw S-box tables in .data (the managed arrays are built by the type cctor at
# 0x586470, so the static slot holds no usable pointer in the file image)
S7_RAW = 0x58EA1F0
S9_RAW = 0x58EA3F0


def make_this():
    s7v = [rd_u32(BASE + S7_RAW + 4 * i) for i in range(128)]
    s9v = [rd_u32(BASE + S9_RAW + 4 * i) for i in range(512)]
    print("S7 image==bin:", s7v == DC._M7_DFO, " S9 image==bin:",
          s9v == DC._M9_DFO)
    s7 = mk_u32_array(s7v)
    s9 = mk_u32_array(s9v)
    ek = mk_u32_array([0] * 64)
    this = (ctypes.c_uint8 * 0x20)()
    struct.pack_into("<Q", this, 8, ctypes.addressof(ek))
    struct.pack_into("<Q", this, 0x10, ctypes.addressof(s7))
    struct.pack_into("<Q", this, 0x18, ctypes.addressof(s9))
    return this, ek


def call_blocks(fn, this, data: bytes) -> bytes:
    src = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    dst = (ctypes.c_uint8 * len(data))()
    s = SPAN(ctypes.cast(src, ctypes.c_void_p), len(data))
    d = SPAN(ctypes.cast(dst, ctypes.c_void_p), len(data))
    fn(this, ctypes.byref(s), ctypes.byref(d))
    return bytes(dst)


def patch_validator(stub_rva):
    for call_rva in VALIDATOR_CALLS:
        rel = stub_rva - (call_rva + 5)
        ctypes.memmove(BASE + call_rva, struct.pack("<Bi", 0xE8, rel), 5)


def main():
    patch_validator(map_image())
    this, ek = make_this()
    blob = BLOB.read_bytes()
    key16 = blob[150:166]

    kb = (ctypes.c_uint8 * 16).from_buffer_copy(key16)
    ks = SPAN(ctypes.cast(kb, ctypes.c_void_p), 16)
    FN2(BASE + SCHED)(this, ctypes.byref(ks))
    nat = [rd_u32(ctypes.addressof(ek) + 0x10 + 4 * i) for i in range(64)]
    mine = DC._misty_dfo_ek(key16)
    print("EK native:", " ".join(f"{v:04x}" for v in nat))
    print("EK mine  :", " ".join(f"{v:04x}" for v in mine))
    print("EK match:", nat == mine)
    if nat != mine:
        print("  first diff idx:", next(i for i in range(64) if nat[i] != mine[i]))

    fl = FLT(BASE + FL_RVA)
    fo = FOT(BASE + FO_RVA)
    fi = FOT(BASE + FI_RVA)
    print("\nFI:")
    for x, k in ((0x1234, 0x5678), (0, 0), (0xFFFF, 0x1FF), (0x0ABC, 0x0102)):
        n, m = fi(this, x, k), DC._misty_dfo_fi(x, k)
        print(f"  FI({x:04x},{k:03x}) native={n:04x} mine={m:04x} "
              f"{'OK' if n == m else 'DIFF'}")
    print("\nFL:")
    for x, k1, k2 in ((0x12345678, 0x1111, 0x2222), (0xFFFFFFFF, 0x1, 0x2),
                      (0x0, 0xAAAA, 0x5555)):
        n, m = fl(x, k1, k2), DC._misty_dfo_fl(x, k1, k2)
        print(f"  FL({x:08x},{k1:04x},{k2:04x}) native={n:08x} mine={m:08x} "
              f"{'OK' if n == m else 'DIFF'}")
    print("\nFO:")
    for x, k in ((0x12345678, 0), (0x0, 2), (0xFFFFFFFF, 6)):
        n, m = fo(this, x, k), DC._misty_dfo_fo(x, k, mine)
        print(f"  FO({x:08x},{k}) native={n:08x} mine={m:08x} "
              f"{'OK' if n == m else 'DIFF'}")

    enc = FN3(BASE + BLOCK_ENC)
    dec = FN3(BASE + BLOCK_DEC)
    print("\nblocks (gold pairs):")
    for sub, ct in ((468, bytes.fromhex("5ce916604a93b34f18b64b9b8941119a")),
                    (1280, bytes.fromhex("ec840d2f5460b1e8"))):
        n_e = call_blocks(enc, this, ct)
        n_d = call_blocks(dec, this, ct)
        m_e = DC.misty1_dfo_encrypt(ct, key16)
        m_d = DC.misty1_dfo_decrypt(ct, key16)
        print(f"  sub={sub} ct={ct.hex()}")
        print(f"    E native={n_e.hex()} mine={m_e.hex()} "
              f"{'OK' if n_e == m_e else 'DIFF'}")
        print(f"    D native={n_d.hex()} mine={m_d.hex()} "
              f"{'OK' if n_d == m_d else 'DIFF'}")
        print(f"    D(E(pt)) native={call_blocks(dec, this, n_e).hex()}")


if __name__ == "__main__":
    main()
