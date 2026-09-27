#!/usr/bin/env python3
"""Shared helpers for the native cipher probes (fake managed objects etc.)."""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run_native import BASE, SPAN, map_image  # noqa

FN3 = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                       ctypes.POINTER(SPAN), ctypes.POINTER(SPAN))


def rd_u32(addr):
    return struct.unpack("<I", ctypes.string_at(addr, 4))[0]


def rd_u64(addr):
    return struct.unpack("<Q", ctypes.string_at(addr, 8))[0]


def mk_u32_array(vals):
    """Fake managed uint[]: [+8] = length, [+0x10..] = data."""
    buf = (ctypes.c_uint8 * (0x10 + 4 * len(vals)))()
    struct.pack_into("<I", buf, 8, len(vals))
    for i, v in enumerate(vals):
        struct.pack_into("<I", buf, 0x10 + 4 * i, v & 0xFFFFFFFF)
    return buf


def call3(fn, this, data: bytes) -> bytes:
    src = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    dst = (ctypes.c_uint8 * len(data))()
    s = SPAN(ctypes.cast(src, ctypes.c_void_p), len(data))
    d = SPAN(ctypes.cast(dst, ctypes.c_void_p), len(data))
    fn(this, ctypes.byref(s), ctypes.byref(d))
    return bytes(dst)


def patch_validator_calls(call_rvas):
    stub = map_image()
    for call_rva in call_rvas:
        rel = stub - (call_rva + 5)
        ctypes.memmove(BASE + call_rva, struct.pack("<Bi", 0xE8, rel), 5)
    return stub
