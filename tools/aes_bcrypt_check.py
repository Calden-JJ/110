#!/usr/bin/env python3
"""Check aes128_* (dfo_ciphers) against the platform's own AES.

algo 4 is stock .NET Aes (ECB / PaddingMode.None, SetKey 0x588af0), which on
Windows is bcrypt-backed (the exe imports bcrypt.dll / BCryptEncrypt), so
matching Windows BCrypt AES-ECB on the same key pins our port to the exact
primitive the server runs.  FIPS-197 / SP 800-38A known-answer vectors are
checked as a sanity gate first.

  python aes_bcrypt_check.py
"""
from __future__ import annotations

import ctypes
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from dfo_ciphers import aes128_decrypt, aes128_encrypt  # noqa

BLOB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto\channelinfo_key_blob.bin")
BCRYPT_ECB = "ChainingModeECB"

bcrypt = ctypes.WinDLL("bcrypt")
NTSTATUS = ctypes.c_int32
ULONG = ctypes.c_uint32


def check(nt, what):
    if nt != 0:
        raise OSError(f"{what}: NTSTATUS {nt:#010x}")


def bcrypt_ecb(key: bytes, data: bytes, encrypt: bool) -> bytes:
    alg = ctypes.c_void_p()
    check(bcrypt.BCryptOpenAlgorithmProvider(
        ctypes.byref(alg), "AES", None, 0), "OpenAlgorithm")
    try:
        mode = BCRYPT_ECB.encode("utf-16-le") + b"\0\0"
        check(bcrypt.BCryptSetProperty(
            alg, "ChainingMode", ctypes.c_char_p(mode), len(mode), 0),
            "SetProperty(ECB)")
        sz = ULONG()
        got = ULONG()
        check(bcrypt.BCryptGetProperty(
            alg, "ObjectLength", ctypes.byref(sz), 4, ctypes.byref(got), 0),
            "GetProperty")
        obj = (ctypes.c_uint8 * sz.value)()
        kh = ctypes.c_void_p()
        check(bcrypt.BCryptGenerateSymmetricKey(
            alg, ctypes.byref(kh), obj, sz.value,
            ctypes.c_char_p(key), len(key), 0), "GenerateKey")
        try:
            out = (ctypes.c_uint8 * len(data))()
            n = ULONG()
            fn = bcrypt.BCryptEncrypt if encrypt else bcrypt.BCryptDecrypt
            check(fn(kh, ctypes.c_char_p(data), len(data), None, None, 0,
                     out, len(data), ctypes.byref(n), 0), "Crypt")
            return bytes(out[:n.value])
        finally:
            bcrypt.BCryptDestroyKey(kh)
    finally:
        bcrypt.BCryptCloseAlgorithmProvider(alg, 0)


def main():
    # FIPS-197 C.1 / SP 800-38A F.1.1
    assert aes128_encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"),
                          bytes.fromhex("000102030405060708090a0b0c0d0e0f")
                          ) == bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes128_encrypt(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
                          bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
                          ) == bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    print("FIPS-197 / SP800-38A vectors: OK")

    key = BLOB.read_bytes()[124:140]
    random.seed(7)
    ok = True
    for t in range(8):
        blk = bytes(random.randrange(256) for _ in range(16 * (1 + t % 3)))
        be = bcrypt_ecb(key, blk, True)
        bd = bcrypt_ecb(key, blk, False)
        pe = aes128_encrypt(blk, key)
        pd = aes128_decrypt(blk, key)
        same = (be == pe) and (bd == pd)
        ok &= same
        print(f"  {len(blk):2d}B blk {blk[:4].hex()}.. "
              f"E bcrypt={be[:4].hex()}.. {'OK' if be == pe else 'DIFF ' + pe[:4].hex()}"
              f" | D {'OK' if bd == pd else 'DIFF ' + pd[:4].hex()}")
    # larger slab + trailing partial block
    big = bytes(random.randrange(256) for _ in range(4096))
    assert bcrypt_ecb(key, big, True) == aes128_encrypt(big, key)
    assert bcrypt_ecb(key, big, False) == aes128_decrypt(big, key)
    tail = aes128_encrypt(big + b"\x01\x02\x03", key)
    assert tail[:4096] == aes128_encrypt(big, key) and tail[4096:] == b"\x01\x02\x03"
    print("4096B slab + partial tail:", "OK" if ok else "FAIL")
    print("bcrypt parity:", "ALL OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
