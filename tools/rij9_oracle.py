#!/usr/bin/env python3
"""Run the algo-9 block worker (0x587880) natively with our own tables.

The worker reads its four T-tables through the static slot at RVA 0x642B878
(pointing at a holder with table refs at +8/+0x10/+0x18/+0x20).  The type cctor
that normally fills it needs the managed runtime, so we pre-fill the slot with
our own managed-array-shaped buffers built from data/crypto/algo09_t*.bin and
call the worker directly with a caller-supplied schedule.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run_native import BASE  # noqa
from probe_util import (SPAN, call3, mk_u32_array,  # noqa
                        patch_validator_calls, rd_u32)

WORKER = 0x587880
TBL_SLOT = 0x642B878
INIT_FLAG = 0x64203B0
VALIDATORS = (0x5878DD,)

D = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto")

FN4 = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(SPAN),
                       ctypes.POINTER(SPAN), ctypes.c_void_p)


def load_tables():
    t = [list(struct.unpack("<256I", (D / f"algo09_t{i}.bin").read_bytes()))
         for i in range(4)]
    arrs = [mk_u32_array(v) for v in t]
    holder = (ctypes.c_uint8 * 0x40)()
    for i, a in enumerate(arrs):
        struct.pack_into("<Q", holder, 8 + 8 * i, ctypes.addressof(a))
    return t, arrs, holder


def install():
    patch_validator_calls(VALIDATORS)
    _t, arrs, holder = load_tables()
    ctypes.memmove(BASE + INIT_FLAG, b"\0" * 8, 8)
    ctypes.memmove(BASE + TBL_SLOT, struct.pack("<Q", ctypes.addressof(holder)), 8)
    fn = FN4(BASE + WORKER)
    this = (ctypes.c_uint8 * 0x20)()
    return fn, this, (holder, arrs)


def run(fn, this, block: bytes, sched_words) -> bytes:
    ks = mk_u32_array(list(sched_words) + [0] * (52 - len(sched_words)))
    src = (ctypes.c_uint8 * 16).from_buffer_copy(block)
    dst = (ctypes.c_uint8 * 16)()
    s = SPAN(ctypes.cast(src, ctypes.c_void_p), 16)
    d = SPAN(ctypes.cast(dst, ctypes.c_void_p), 16)
    fn(this, ctypes.byref(s), ctypes.byref(d), ctypes.cast(ks, ctypes.c_void_p))
    return bytes(dst)


def main():
    fn, this, keep = install()
    print("zero-schedule worker on single-bit inputs:")
    for bit in range(4):
        blk = bytes([1 << bit] + [0] * 15)
        out = run(fn, this, blk, [0] * 52)
        print(f"  bit{bit:3d} {blk.hex()} -> {out.hex()}")
    # per-byte impulse under output-word-0 key = 0: use key word0 = ffff..
    sched = [0] * 52
    for pos in range(16):
        blk = bytes(16)
        blk = blk[:pos] + bytes([0x41]) + blk[pos + 1:]
        out = run(fn, this, blk, sched)
        print(f"  b{pos:02d} 41 -> {out.hex()}")
    sched2 = [0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10] + [0] * 48
    blk = bytes(16)
    print("init-key test (only key0 set):", run(fn, this, blk, sched2).hex())


if __name__ == "__main__":
    main()
