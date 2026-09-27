#!/usr/bin/env python3
"""Probe the server's DFO-Custom-16B (algo 12) native code as an oracle.

    0x585370  SetKey(this, ref span16)
    0x585000  Encrypt(this, ref src, ref dst)
    0x5851c0  Decrypt(this, ref src, ref dst)

this+8 = enc schedule (uint[4]), this+0x10 = dec schedule (uint[4]).
"""
from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dfo_ciphers as DC  # noqa
from probe_util import FN3, BASE, SPAN, call3, mk_u32_array, patch_validator_calls  # noqa

SETKEY = 0x585370
ENC = 0x585000
DEC = 0x5851C0
VALIDATORS = (0x585058, 0x585218)

BLOB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto"
            r"\channelinfo_key_blob.bin")


def make_this():
    ks_e, ks_d = mk_u32_array([0] * 4), mk_u32_array([0] * 4)
    this = (ctypes.c_uint8 * 0x20)()
    struct.pack_into("<Q", this, 8, ctypes.addressof(ks_e))
    struct.pack_into("<Q", this, 0x10, ctypes.addressof(ks_d))
    return this, ks_e, ks_d


RT = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_void_p,
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32))
FT = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32),
                      ctypes.POINTER(ctypes.c_uint32))


def words(vals):
    return [ctypes.c_uint32(v) for v in vals]


def main():
    patch_validator_calls(VALIDATORS)
    this, ks_e, ks_d = make_this()
    key = BLOB.read_bytes()[278:294]

    kb = (ctypes.c_uint8 * 16).from_buffer_copy(key)
    ks = SPAN(ctypes.cast(kb, ctypes.c_void_p), 16)
    FN3(BASE + SETKEY)(this, ctypes.byref(ks), None)
    nat_e = [struct.unpack_from("<I", ks_e, 0x10 + 4 * i)[0] for i in range(4)]
    nat_d = [struct.unpack_from("<I", ks_d, 0x10 + 4 * i)[0] for i in range(4)]
    mine_e, mine_d = DC._rij12_key(key)
    print("ks_enc native:", [f"{v:08x}" for v in nat_e], "mine:", [f"{v:08x}" for v in mine_e], nat_e == mine_e)
    print("ks_dec native:", [f"{v:08x}" for v in nat_d], "mine:", [f"{v:08x}" for v in mine_d], nat_d == mine_d)

    print("\nround functions vs python (ks = enc schedule):")
    rd_f = RT(BASE + 0x585500)
    rd_i = RT(BASE + 0x5855E0)
    fin = FT(BASE + 0x5856C0)
    ks_ptr = ctypes.cast(ks_e, ctypes.c_void_p)
    for start in ((0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210),
                  (0, 0, 0, 0)):
        for rc, fn, py in (
                (DC._RIJ12_K[0], rd_f,
                 DC._rij12_round(*start, DC._RIJ12_K[0], mine_e)),
                (DC._RIJ12_K[5], rd_i,
                 DC._rij12_round_inv(*start, DC._RIJ12_K[5], mine_e))):
            wa, wb, wc, wd = words(list(start))
            fn(rc & 0xFFFFFFFF, ks_ptr, ctypes.byref(wa), ctypes.byref(wb),
               ctypes.byref(wc), ctypes.byref(wd))
            got = (wa.value, wb.value, wc.value, wd.value)
            print(f"  rc={rc:02x} native={tuple(hex(v) for v in got)}")
            print(f"          python={tuple(hex(v) for v in py)} "
                  f"{'OK' if got == py else 'DIFF'}")
        wa, wb, wc, wd = words(list(start))
        e = DC._rij12_f(start[0] ^ start[2] ^ DC._RIJ12_K[16])
        fin(e, DC._RIJ12_K[16], ks_ptr, ctypes.byref(wa), ctypes.byref(wb),
            ctypes.byref(wc), ctypes.byref(wd))
        got = (wa.value, wb.value, wc.value, wd.value)
        py = DC._rij12_final(*start, e, DC._RIJ12_K[16], mine_e)
        print(f"  final      native={tuple(hex(v) for v in got)}")
        print(f"             python={tuple(hex(v) for v in py)} "
              f"{'OK' if got == py else 'DIFF'}")

    enc = FN3(BASE + ENC)
    dec = FN3(BASE + DEC)
    for pt in (bytes(16), bytes(range(16)),
               bytes.fromhex("ffff1900010014000000000000000000")):
        n_e = call3(enc, this, pt)
        n_d = call3(dec, this, n_e)
        m_e = DC.dfo16_encrypt(pt, key)
        m_d = DC.dfo16_decrypt(n_e, key)
        print(f"  pt={pt.hex()}")
        print(f"    E native={n_e.hex()} mine={m_e.hex()} "
              f"{'OK' if n_e == m_e else 'DIFF'}")
        print(f"    D(native)={n_d.hex()} mine={m_d.hex()} "
              f"{'OK' if n_d == m_d else 'DIFF'}")


if __name__ == "__main__":
    main()
