#!/usr/bin/env python3
"""Trace the intermediates of the algo-12 round function (0x585500).

Copies the function to scratch memory, fixes the two relative `call F`s, then
appends `mov [rsi], reg ; ret` at each stage so the register of interest can be
observed from outside.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dfo_ciphers as DC  # noqa
from probe_util import BASE, mk_u32_array, patch_validator_calls  # noqa

FUNC = 0x585500
LEN = 0xD8
CALLS = (0x35, 0x6B)          # rel32 call sites inside the function
F_ADDR = 0x5854F0
STORE = {0x3A: (b"\x89\x06", "eax=e0"), 0x50: (b"\x44\x89\x2e", "r13"),
         0x5F: (b"\x89\x06", "eax=t1"), 0x67: (b"\x44\x89\x26", "r12"),
         0x70: (b"\x89\x06", "eax=e1"), 0x7B: (b"\x89\x0e", "ecx=q"),
         0x85: (b"\x89\x16", "edx=dd"), 0x96: (b"\x89\x06", "eax=p"),
         0xA2: (b"\x89\x0e", "ecx=qn"), 0xAE: (b"\x89\x16", "edx=ddn")}

RT = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_void_p,
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32))


def build(cut: int) -> int:
    buf = ctypes.create_string_buffer(LEN + 0x10)
    addr = ctypes.addressof(buf)
    code = bytearray(ctypes.string_at(BASE + FUNC, cut))
    for off in CALLS:
        if off + 5 <= cut:
            rel = (F_ADDR - (0x140000000 + addr - 0x140000000)) - (off + 5)
            rel = (F_ADDR + BASE - addr) if False else \
                (F_ADDR - ((addr - BASE) + off + 5))
            struct.pack_into("<i", code, off + 1, rel)
    code += STORE[cut][0] + b"\xc3"
    ctypes.memmove(addr, bytes(code), len(code))
    return addr


def main():
    patch_validator_calls(())
    ks = mk_u32_array([0, 0, 0, 0])
    ksp = ctypes.cast(ks, ctypes.c_void_p)
    states = [(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1),
              (0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210)]
    for st in states:
        print(f"state={tuple(hex(v) for v in st)}  rc=0 ks=0")
        for cut in sorted(STORE):
            fn = RT(build(cut))
            wa, wb, wc, wd = [ctypes.c_uint32(v) for v in st]
            fn(0, ksp, ctypes.byref(wa), ctypes.byref(wb),
               ctypes.byref(wc), ctypes.byref(wd))
            print(f"    +{cut:02x} {STORE[cut][1]:8} = {wb.value:08x}")


if __name__ == "__main__":
    main()
