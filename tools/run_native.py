#!/usr/bin/env python3
"""Run cipher transforms from the server exe itself as ground truth.

Maps the whole image at its preferred base (0x140000000, no relocs needed),
patches the block-multiple validator call (0x5843b0) inside the XTEA
transforms to a stub returning 8, builds a fake cipher object
([+0]=MT 0x5b78850, [+8]=key uint[4], [+0x1c]=ioBE) and calls:

    0x589080  Encrypt(this, ref srcSpan, ref dstSpan)
    0x589200  Decrypt(this, ref srcSpan, ref dstSpan)

Usage:  python run_native.py
"""
from __future__ import annotations

import ctypes
import struct
import sys
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import rva2off  # noqa

EXE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\USLocalServer.Server.exe")
BLOB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto\channelinfo_key_blob.bin")
BASE = 0x140000000
MT_XTEA = 0x5b78850

ENC_RVA = 0x589080
DEC_RVA = 0x589200
VALIDATOR_CALLS = (0x5890CC, 0x58924C)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                             wintypes.DWORD, wintypes.DWORD]


class SPAN(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("len", ctypes.c_uint64)]


CODE = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                        ctypes.POINTER(SPAN), ctypes.POINTER(SPAN))


def map_image() -> int:
    D = EXE.read_bytes()
    e_lfanew = struct.unpack_from("<I", D, 0x3C)[0]
    optsz = struct.unpack_from("<H", D, e_lfanew + 20)[0]
    nsec = struct.unpack_from("<H", D, e_lfanew + 6)[0]
    size_of_image = struct.unpack_from("<I", D, e_lfanew + 24 + 56)[0]
    size = size_of_image + 0x2000
    p = k32.VirtualAlloc(ctypes.c_void_p(BASE), size, 0x3000, 0x40)
    if p != BASE:
        raise SystemExit(f"VirtualAlloc at {BASE:#x} failed: {p:#x}")
    ctypes.memmove(p, D, 0x1000)
    so = e_lfanew + 24 + optsz
    for i in range(nsec):
        o = so + i * 40
        vs, va, rs, raw = struct.unpack_from("<IIII", D, o + 8)
        n = min(vs, rs)
        if n:
            ctypes.memmove(p + va, D[raw:raw + n], n)
    # stub: mov eax,8 / ret
    stub_rva = size_of_image
    ctypes.memmove(p + stub_rva, b"\xb8\x08\x00\x00\x00\xc3", 6)
    for call_rva in VALIDATOR_CALLS:
        rel = (stub_rva) - (call_rva + 5)
        ctypes.memmove(p + call_rva, struct.pack("<Bi", 0xE8, rel), 5)
    return size_of_image


def make_cipher(key16: bytes, key_be: bool, io_be: bool):
    arr = (ctypes.c_uint8 * 0x40)()
    struct.pack_into("<I", arr, 8, 4)
    k = struct.unpack(">4I" if key_be else "<4I", key16)
    struct.pack_into("<4I", arr, 0x10, *k)
    this = (ctypes.c_uint8 * 0x40)()
    struct.pack_into("<Q", this, 0, BASE + MT_XTEA)
    struct.pack_into("<Q", this, 8, ctypes.addressof(arr))
    struct.pack_into("<I", this, 0x1C, 1 if io_be else 0)
    return this, arr


def call(fn, this, data: bytes) -> bytes:
    n = len(data) - len(data) % 8
    src = (ctypes.c_uint8 * max(n, 8)).from_buffer_copy(data[:n] + b"\0" * (8 - min(n, 8)))
    dst = (ctypes.c_uint8 * max(n, 8))()
    s = SPAN(ctypes.cast(src, ctypes.c_void_p), n)
    d = SPAN(ctypes.cast(dst, ctypes.c_void_p), n)
    fn(this, ctypes.byref(s), ctypes.byref(d))
    return bytes(dst)[:n]


def main():
    map_image()
    blob = BLOB.read_bytes()
    enc = CODE(BASE + ENC_RVA)
    dec = CODE(BASE + DEC_RVA)

    print("== sanity: E(0^8) for every 16B blob slice x (key_be, io_be)")
    zeros = bytes(8)
    for i in range(0, len(blob) - 15):
        key = blob[i:i + 16]
        for kb in (0, 1):
            for iob in (0, 1):
                this, arr = make_cipher(key, kb, iob)
                out = call(enc, this, zeros)
                if out.hex() in ("a7c02233e5721520", "94c6b7441a8ee699",
                                 "436ec337946d27d6"):
                    print(f"  HIT enc slice {i} key_be={kb} io_be={iob}: "
                          f"{out.hex()}  key={key.hex()}")

    print("\n== algo0 gold: D(94c6b7441a8ee699) with blob[0:16], expect 0^8")
    for kb in (0, 1):
        for iob in (0, 1):
            this, arr = make_cipher(blob[0:16], kb, iob)
            out = call(dec, this, bytes.fromhex("94c6b7441a8ee699"))
            print(f"  key_be={kb} io_be={iob}: {out.hex()}")

    print("\n== algo8: D(a7c02233e5721520) with blob[222:238]")
    for kb in (0, 1):
        for iob in (0, 1):
            this, arr = make_cipher(blob[222:238], kb, iob)
            out = call(dec, this, bytes.fromhex("a7c02233e5721520"))
            print(f"  key_be={kb} io_be={iob}: {out.hex()}")

    print("\n== algo0 gold full block decrypt (blob[0:16], kb=1 iob=1)")
    this, arr = make_cipher(blob[0:16], 1, 1)
    ct = bytes.fromhex("a63e03e6afabe22b41b658d12b0c53978fe3111e212bda7a94c6b7441a8ee699")
    print("  D =", call(dec, this, ct).hex())
    print("  expect pt tail 0000000000000000 (block4)")


if __name__ == "__main__":
    main()
