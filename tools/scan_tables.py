#!/usr/bin/env python3
"""Scan the server exe for cryptographic constant tables.

Signatures used:
  - 256-byte permutation  -> Skipjack F / Twofish q0,q1 / Khazad S
  - 128-byte permutation  -> MISTY1 S7
  - 512 u16 permutation   -> MISTY1 S9
  - 256 u32 table (CAST-style S-box): all values < 2**31, 256 distinct

  python scan_tables.py
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from na_dis import EXE  # noqa

D = EXE.read_bytes()


def section_map():
    e = struct.unpack_from("<I", D, 0x3C)[0]
    nsec = struct.unpack_from("<H", D, e + 6)[0]
    optsz = struct.unpack_from("<H", D, e + 20)[0]
    so = e + 24 + optsz
    out = []
    for i in range(nsec):
        o = so + i * 40
        name = D[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, raw = struct.unpack_from("<IIII", D, o + 8)
        out.append((name, va, vs, raw, rs))
    return out


SECS = section_map()


def off2rva(off):
    for name, va, vs, raw, rs in SECS:
        if raw <= off < raw + rs:
            return va + (off - raw), name
    return None, None


def rva2file(rva):
    for name, va, vs, raw, rs in SECS:
        if va <= rva < va + vs:
            return raw + (rva - va)
    return None


def perms(nbytes, step=1):
    """Find offsets where D[o:o+nbytes] is a permutation of 0..nbytes-1."""
    arr = np.frombuffer(D, dtype=np.uint8)
    tgt_sum = nbytes * (nbytes - 1) // 2
    cs = np.concatenate(([0], np.cumsum(arr, dtype=np.int64)))
    sums = cs[nbytes:] - cs[:-nbytes]
    idx = np.flatnonzero(sums == tgt_sum)
    hits = []
    for o in idx[::step]:
        o = int(o)
        blk = D[o:o + nbytes]
        if len(set(blk)) == nbytes:
            hits.append(o)
    return hits


def u16_perms(count):
    arr = np.frombuffer(D[:len(D) - len(D) % 2], dtype="<u2")
    n = len(arr)
    cs = np.concatenate(([0], np.cumsum(arr, dtype=np.int64)))
    tgt = count * (count - 1) // 2
    sums = cs[count:] - cs[:-count]
    idx = np.flatnonzero(sums == tgt)
    hits = []
    for i in idx:
        blk = arr[i:i + count]
        if blk.max() == count - 1 and len(np.unique(blk)) == count:
            hits.append(int(i) * 2)
    return hits


def dedupe(offs, size):
    out = []
    for o in sorted(offs):
        if out and o < out[-1][1]:
            out[-1][1] = max(out[-1][1], o + size)
            continue
        out.append([o, o + size])
    return out


def merge(*groups):
    allh = sorted((o, sz) for offs, sz in groups for o in offs)
    out = []
    for o, sz in allh:
        if out and o < out[-1][1]:
            out[-1][1] = max(out[-1][1], o + sz)
            continue
        out.append([o, o + sz])
    return out


def main():
    groups = []
    g128 = perms(128)
    groups.append((g128, 128))
    g256 = perms(256)
    groups.append((g256, 256))
    g512 = u16_perms(512)
    groups.append((g512, 1024))
    for offs, sz in groups:
        print(f"== {sz}-byte signatures: {len(offs)}")
    print("\n-- merged regions:")
    for a, b in merge(*groups):
        rva, sect = off2rva(a)
        # skip the q0/q1 pair region? no - report and label
        head = D[a:a + 16]
        print(f"  rva {rva:#x} ({sect}) off {a:#x}-{b:#x} len {b-a:#x}  head {head.hex(' ')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
