#!/usr/bin/env python3
"""DFO cipher suite — semantics recovered from USLocalServer.Server.exe.

Verified against the exe's own code (tools/run_native.py) and log gold pairs:
  XTEA class  MT 0x5b78850 : BlockSize=8, transform 0x589080 (enc) / 0x589200 (dec)
      key      = this+8 (uint[4]; data at +0x10, len at +8)
      key_be   : 0 = key words are LE u32 of the key bytes, 1 = bswap each
      io_be    = this+0x1c : block words unpacked/packed as BE dwords, else LE
      rounds   = 32, delta = 0x9E3779B9, standard XTEA
      XTEA-BE (algo 0): key_be=1 io_be=1;  XTEA-LE (algo 8): key_be=0 io_be=0
  XOR-32 class MT 0x5b788b8 : BlockSize=4, transform 0x589580
      xor each 4B block with dword(this+8) = key[len-4:len] read LE

Oracle values (encrypt/decrypt of 8 zero bytes with the blob keys):
  E(0^8) = 94c6b7441a8ee699 (XTEA-BE, blob[0:16])
  E(0^8) = a7c02233e5721520 (XTEA-LE, blob[222:238])
"""
from __future__ import annotations

import struct

M32 = 0xFFFFFFFF
DELTA = 0x9E3779B9


def _key_words(key: bytes, key_be: bool) -> tuple:
    return struct.unpack(">4I" if key_be else "<4I", key[:16])


def _block_words(block8: bytes, io_be: bool) -> tuple:
    return struct.unpack(">II" if io_be else "<II", block8)


def _pack_words(v0: int, v1: int, io_be: bool) -> bytes:
    return struct.pack(">II" if io_be else "<II", v0, v1)


def xtea_encrypt(block8: bytes, key16: bytes, io_be: bool = False,
                 key_be: bool | None = None) -> bytes:
    if key_be is None:
        key_be = io_be
    v0, v1 = _block_words(block8, io_be)
    k = _key_words(key16, key_be)
    s = 0
    for _ in range(32):
        v0 = (v0 + (((((v1 << 4) & M32) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M32
        s = (s + DELTA) & M32
        v1 = (v1 + (((((v0 << 4) & M32) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M32
    return _pack_words(v0, v1, io_be)


def xtea_decrypt(block8: bytes, key16: bytes, io_be: bool = False,
                 key_be: bool | None = None) -> bytes:
    if key_be is None:
        key_be = io_be
    v0, v1 = _block_words(block8, io_be)
    k = _key_words(key16, key_be)
    s = (DELTA * 32) & M32
    for _ in range(32):
        v1 = (v1 - (((((v0 << 4) & M32) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M32
        s = (s - DELTA) & M32
        v0 = (v0 - (((((v1 << 4) & M32) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M32
    return _pack_words(v0, v1, io_be)


def xor32_dword(key: bytes) -> int:
    return struct.unpack("<I", key[len(key) - 4:])[0]


def xor32_crypt(data: bytes, key: bytes) -> bytes:
    k = xor32_dword(key)
    out = bytearray()
    for i in range(0, len(data) - len(data) % 4, 4):
        out += struct.pack("<I", struct.unpack("<I", data[i:i + 4])[0] ^ k)
    out += data[len(data) - len(data) % 4:]
    return bytes(out)


if __name__ == "__main__":
    from pathlib import Path
    blob = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto\channelinfo_key_blob.bin").read_bytes()
    k0, k8 = blob[0:16], blob[222:238]
    checks = [
        ("E(0^8) XTEA-BE", xtea_encrypt(bytes(8), k0, True), "94c6b7441a8ee699"),
        ("E(0^8) XTEA-LE", xtea_encrypt(bytes(8), k8, False), "a7c02233e5721520"),
        ("D(94c6..) XTEA-BE", xtea_decrypt(bytes.fromhex("94c6b7441a8ee699"), k0, True),
         "0000000000000000"),
        ("D(a7c0..) XTEA-LE", xtea_decrypt(bytes.fromhex("a7c02233e5721520"), k8, False),
         "0000000000000000"),
    ]
    for name, got, want in checks:
        print(f"  {'OK ' if got.hex() == want else 'BAD'} {name}: {got.hex()}")
    kx = blob[254:262]
    pt = xor32_crypt(bytes.fromhex(
        "15831f5245eb763c67a34c2667ed7b3374e73f066fee7a5606831f662aba3352"), kx)
    print(f"  XOR-32 China Standard Time: {pt.decode('latin1')!r}")
