#!/usr/bin/env python3
"""Python model of algo9 (DFO-Rijndael12) schedule + worker, checked against
the native worker (0x587880) run by rij9_oracle.py on the log's gold pair.

Schedule layout (from the class cctor 0x5884a0 and builder 0x587d40):
  holder +8/+0x10/+0x18/+0x20 = t0..t3,  +0x28 = tbl5, +0x30 = sbox(bcast),
  +0x38 = byte sbox, +0x40 = rcon.
  X0 = key with each 4B word byte-reversed; sched[4i..4i+3] = K4(X_i) (0x587fa0);
  X_{i+1} = expand(X_i, rcon[i]) (0x588240);  dec[i] = f(enc[12-i]) word-wise.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import rij9_oracle as O  # noqa

D = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto")

T = [list(struct.unpack("<256I", (D / f"algo09_t{i}.bin").read_bytes()))
     for i in range(4)]
IDX = list(struct.unpack("<256I", (D / "algo09_sbox.bin").read_bytes()))
TB5 = list(struct.unpack("<256I", (D / "algo09_tbl5.bin").read_bytes()))
RCON = list(struct.unpack("<16I", (D / "algo09_rcon.bin").read_bytes()))
SB = bytes(v & 0xFF for v in IDX)


def expand(st: bytes, rcon: int) -> bytes:
    out = []
    for i in range(4):
        v = (T[0][st[4 * i + 3]] ^ T[1][st[4 * ((i + 3) % 4) + 2]]
             ^ T[2][st[4 * ((i + 2) % 4) + 1]] ^ T[3][st[4 * ((i + 1) % 4)]])
        if i == 0:
            v ^= rcon
        out.append(v & 0xFFFFFFFF)
    return b"".join(struct.pack("<I", w) for w in out)


def byte_sel(table, w):
    v = 0
    for lane in range(4):
        v |= table[(w >> (8 * lane)) & 0xFF] & (0xFF << (8 * lane))
    return v


def G(w, x):
    return (byte_sel(TB5, w) ^ IDX[x & 0xFF]) & 0xFFFFFFFF


def K4(st: bytes):
    res = []
    for j in range(4):
        acc = IDX[st[15 - j]]
        for w in (2, 1, 0):
            acc = G(acc, st[4 * w + (3 - j)])
        res.append(acc)
    return res


def f(w):
    return (T[0][SB[(w >> 24) & 0xFF]] ^ T[1][SB[(w >> 16) & 0xFF]]
            ^ T[2][SB[(w >> 8) & 0xFF]] ^ T[3][SB[w & 0xFF]]) & 0xFFFFFFFF


def build(key16: bytes):
    st = b"".join(key16[4 * i:4 * i + 4][::-1] for i in range(4))
    enc = []
    for i in range(13):
        enc += K4(st)
        if i < 12:
            st = expand(st, RCON[i])
    dec = [0] * 52
    dec[0:4] = enc[48:52]
    dec[48:52] = enc[0:4]
    for i in range(1, 12):
        for j in range(4):
            dec[4 * i + j] = f(enc[48 - 4 * i + j])
    return enc, dec


def main():
    blob = (D / "channelinfo_key_blob.bin").read_bytes()
    key = blob[238:254]
    ct = bytes.fromhex("d1451c4b494af5eb59280cc0fa27abe2"
                       "f257d6fc2d4bf1482f54eab645a72062")
    pt = bytes.fromhex("0300000000000000260d000001000000"
                       "c20d000002000000ac0e000000000000")
    enc, dec = build(key)
    print("key:", key.hex())
    print("enc[0:8] :", " ".join(f"{v:08x}" for v in enc[:8]))
    print("dec[0:8] :", " ".join(f"{v:08x}" for v in dec[:8]))

    fn, this, keep = O.install()
    for name, sched in (("dec", dec), ("enc", enc)):
        got = b"".join(O.run(fn, this, ct[i:i + 16], sched)
                       for i in range(0, len(ct), 16))
        print(f"worker {name}(ct) = {got.hex()}")
        print(f"  match gold pt: {got == pt}")
    for name, sched in (("enc", enc), ("dec", dec)):
        got = b"".join(O.run(fn, this, pt[i:i + 16], sched)
                       for i in range(0, len(pt), 16))
        print(f"worker {name}(pt) = {got.hex()}")
        print(f"  match gold ct: {got == ct}")


if __name__ == "__main__":
    main()
