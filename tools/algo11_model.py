#!/usr/bin/env python3
"""Python model of algo11 ("Khazad-like", 8B block, 16B key), checked against
the native worker 0x586060 through thunks 0x586030 (enc, this+8) / 0x586040
(dec, this+0x10).

Class layout (cctor 0x586470 -> holder static 0x642b870):
  holder +8 = C[9] (u64 round constants, memcpy'd from .rdata 0x5af1500)
  holder +0x10 = R[8] (table refs cloned from Tables+0x60)
  holder +0x18 = Tables+0x68 = R[0] (byte sbox-inverse, read as low byte)

khazad loader 0x583860: raw 16384B -> 8 u64[256] tables t0..t7, then
  R = [t0, t7, t6, t5, t4, t3, t2, t1]  (cont reversed for indices >= 1)

worker: x = bswap(blk) ^ K0; for r in 1..7: x = G(x) ^ K[r];
        y = K8 ^ OR_r (R[r][byte r of x] & (0xFF << 8r)); out = bswap(y)
G(x)   = XOR_r R[r][byte r of x]
inv(x) = XOR_r R[r][ S_INV[byte r of x] ]
sched:  A=bswap(key[0:8]), B=bswap(key[8:16]); K[i] = K[i-2]^G(K[i-1])^C[i]
        (K[-2]=A, K[-1]=B);  dec[0]=K8, dec[8]=K0, dec[i]=inv(K[8-i]).
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run_native import BASE, SPAN, EXE  # noqa
from probe_util import call3, mk_u32_array, patch_validator_calls  # noqa
from na_dis import rva2off  # noqa

WORKER = 0x586060
ENC_THUNK = 0x586030
DEC_THUNK = 0x586040
VALIDATOR_CALL = 0x5860A9
HOLDER_SLOT = 0x642B870
GUARD_CELLS = 0x64203A8               # cctor fn ptr cells (all classes)
C_RVA = 0x5AF1500
M64 = 0xFFFFFFFFFFFFFFFF

D = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto")

RAW = (D / "algo11_khazad_t.bin").read_bytes()
_cont = [list(struct.unpack_from("<256Q", RAW, 2048 * i)) for i in range(8)]
R = [_cont[0]] + _cont[:0:-1]         # R = [t0, t7, t6, t5, t4, t3, t2, t1]
S_INV = bytes(v & 0xFF for v in R[0])
_P = EXE.read_bytes()
C = list(struct.unpack("<9Q", _P[rva2off(C_RVA):rva2off(C_RVA) + 72]))


def G(x):
    y = 0
    for r in range(8):
        y ^= R[r][(x >> (8 * r)) & 0xFF]
    return y & M64


def inv(x):
    y = 0
    for r in range(8):
        y ^= R[r][S_INV[(x >> (8 * r)) & 0xFF]]
    return y & M64


def key_sched(key16: bytes):
    A = int.from_bytes(key16[0:8], "big")
    B = int.from_bytes(key16[8:16], "big")
    enc = []
    rsi, rdi = B, A
    for i in range(9):
        if i:
            rsi, rdi = rdi, rsi
        rdi ^= G(rsi) ^ C[i]
        enc.append(rdi)
    dec = [0] * 9
    dec[0] = enc[8]
    dec[8] = enc[0]
    for i in range(1, 8):
        dec[i] = inv(enc[8 - i])
    return enc, dec


def block(blk8: bytes, sched) -> bytes:
    x = int.from_bytes(blk8, "big") ^ sched[0]
    for r in range(1, 8):
        x = G(x) ^ sched[r]
    y = sched[8]
    for r in range(8):
        y ^= R[r][(x >> (8 * r)) & 0xFF] & (0xFF << (8 * r))
    return (y & M64).to_bytes(8, "big")


def crypt(data, sched):
    n = len(data) - len(data) % 8
    return b"".join(block(data[i:i + 8], sched)
                    for i in range(0, n, 8)) + data[n:]


def mk_u64_array(vals):
    buf = (ctypes.c_uint8 * (0x10 + 8 * len(vals)))()
    struct.pack_into("<I", buf, 8, len(vals))
    for i, v in enumerate(vals):
        struct.pack_into("<Q", buf, 0x10 + 8 * i, v & M64)
    return buf


def install():
    patch_validator_calls((VALIDATOR_CALL,))
    ctypes.memmove(BASE + GUARD_CELLS, b"\0" * 16, 16)
    c_arr = mk_u64_array(C)
    t_arrs = [mk_u64_array(t) for t in R]
    cont = (ctypes.c_uint8 * (0x10 + 8 * 8))()
    struct.pack_into("<I", cont, 8, 8)
    for i, a in enumerate(t_arrs):
        struct.pack_into("<Q", cont, 0x10 + 8 * i, ctypes.addressof(a))
    holder = (ctypes.c_uint8 * 0x40)()
    struct.pack_into("<Q", holder, 8, ctypes.addressof(c_arr))
    struct.pack_into("<Q", holder, 0x10, ctypes.addressof(cont))
    struct.pack_into("<Q", holder, 0x18, ctypes.addressof(t_arrs[0]))
    ctypes.memmove(BASE + HOLDER_SLOT,
                   struct.pack("<Q", ctypes.addressof(holder)), 8)
    return (c_arr, t_arrs, cont, holder)


def main():
    keep = list(install())
    print("C:", " ".join(f"{v:016x}" for v in C))
    print("S_INV perm:", sorted(S_INV) == list(range(256)))
    key = (D / "channelinfo_key_blob.bin").read_bytes()[262:278]
    enc, dec = key_sched(key)
    print("enc:", " ".join(f"{v:016x}" for v in enc))
    print("dec:", " ".join(f"{v:016x}" for v in dec))

    enc_fn = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(SPAN),
                              ctypes.POINTER(SPAN))(BASE + ENC_THUNK)
    dec_fn = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(SPAN),
                              ctypes.POINTER(SPAN))(BASE + DEC_THUNK)

    def native(fn, blk, sched):
        ks = mk_u64_array(sched)
        this = (ctypes.c_uint8 * 0x20)()
        # enc thunk reads [this+8], dec thunk reads [this+0x10]
        struct.pack_into("<Q", this, 8, ctypes.addressof(ks))
        struct.pack_into("<Q", this, 0x10, ctypes.addressof(ks))
        return call3(fn, this, blk), ks, this

    import random
    random.seed(23)
    ok = True
    for t in range(6):
        blk = bytes(random.randrange(256) for _ in range(8))
        ne, kse, _ = native(enc_fn, blk, enc)
        nd, _, _ = native(dec_fn, blk, dec)
        pe = block(blk, enc)
        pd = block(blk, dec)
        same = (ne == pe) and (nd == pd)
        ok &= same
        print(f"  {blk.hex()} E:{ne.hex()} {'OK' if ne == pe else 'DIFF ' + pe.hex()}"
              f" | D:{nd.hex()} {'OK' if nd == pd else 'DIFF ' + pd.hex()}")
        keep.append((kse, _))           # keep sched arrays alive

    # native enc -> native dec roundtrip
    blk = bytes(range(8))
    ct, _, _ = native(enc_fn, blk, enc)
    pt, _, _ = native(dec_fn, ct, dec)
    rt = pt == blk
    print("native roundtrip:", rt)
    print("model roundtrip:", crypt(crypt(blk, enc), dec) == blk)
    print("random vs native:", "ALL OK" if ok else "FAIL")
    return 0 if (ok and rt) else 1


if __name__ == "__main__":
    raise SystemExit(main())
