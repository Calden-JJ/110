#!/usr/bin/env python3
"""Scan the server exe for the constants / type names of known hash functions.

The S->C header word at [7:11] is a function of the frame body (`probe_s2c_hdr`
shows 57/57 distinct, duplicates exactly on duplicate bodies, and it ignores
the opcode), but it is not the output of any unseeded standard hash -- frame
6515's empty body maps to 0x18000000, while xxh32("")=02cc5d05, murmur3("")=0,
crc32("")=0, md5("")[0:4]=d41d8cd9, sha1("")[0:4]=da39a3ee.

If the server computes it, the algorithm is compiled in.  NativeAOT keeps
metadata names as UTF-8/UTF-16 strings and constants as little-endian
immediates inside the code stream, so a byte scan can name the family even
when the function itself has to be read out of the disassembly later.
"""
from __future__ import annotations

import mmap
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\USLocalServer.Server.exe")

CONSTS = {
    "xxh32 P1 9E3779B1": (0x9E3779B1, 4),
    "xxh32 P2 85EBCA77": (0x85EBCA77, 4),
    "xxh32 P3 C2B2AE3D": (0xC2B2AE3D, 4),
    "xxh32 P4 27D4EB2F": (0x27D4EB2F, 4),
    "xxh32 P5 165667B1": (0x165667B1, 4),
    "murmur3 c1 CC9E2D51": (0xCC9E2D51, 4),
    "murmur3 c2 1B873593": (0x1B873593, 4),
    "murmur3 c3 E6546B64": (0xE6546B64, 4),
    "murmur3 f1 85EBCA6B": (0x85EBCA6B, 4),
    "murmur3 f2 C2B2AE35": (0xC2B2AE35, 4),
    "murmur2 c1 5BD1E995": (0x5BD1E995, 4),
    "fnv prime 01000193": (0x01000193, 4),
    "fnv offset 811C9DC5": (0x811C9DC5, 4),
    "crc32 poly EDB88320": (0xEDB88320, 4),
    "crc32c poly 82F63B78": (0x82F63B78, 4),
    "crc32k poly EB31D82E": (0xEB31D82E, 4),
    "golden 9E3779B9": (0x9E3779B9, 4),
    "djb2 33": None,          # too common, skipped
    "sdbm 1003F": (0x0001003F, 4),
    "xxh64 P1 9E3779B185EBCA87": (0x9E3779B185EBCA87, 8),
    "xxh64 P2 C2B2AE3D27D4EB4F": (0xC2B2AE3D27D4EB4F, 8),
    "xxh64 P3 165667B19E3779F9": (0x165667B19E3779F9, 8),
    "xxh64 P4 85EBCA77C2B2AE63": (0x85EBCA77C2B2AE63, 8),
    "xxh64 P5 27D4EB2F165667C5": (0x27D4EB2F165667C5, 8),
}

STRINGS = [
    "XxHash", "xxHash", "Murmur", "murmur", "Crc32", "CRC32", "Crc64",
    "CityHash", "FarmHash", "SipHash", "SpookyHash", "HashAlgorithm",
    "System.IO.Hashing", "GetHashCode", "Checksum", "checksum",
    "ComputeChecksum", "checksum32", "Hash32",
]


def main() -> int:
    with open(EXE, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        print(f"exe {len(mm):,} bytes\n")

        print("-- constants (little-endian immediates) --")
        for name, spec in CONSTS.items():
            if spec is None:
                continue
            val, width = spec
            pat = val.to_bytes(width, "little")
            hits = []
            start = 0
            while True:
                i = mm.find(pat, start)
                if i < 0:
                    break
                hits.append(i)
                start = i + 1
                if len(hits) > 8:
                    break
            if hits:
                print(f"  {name:<28} {len(hits)} hit(s): "
                      + ", ".join(f"0x{h:x}" for h in hits[:6]))

        print("\n-- type / method names (UTF-8 and UTF-16LE) --")
        for s in STRINGS:
            for enc, label in ((s.encode(), "utf8"), (s.encode("utf-16-le"), "utf16")):
                hits = []
                start = 0
                while True:
                    i = mm.find(enc, start)
                    if i < 0:
                        break
                    hits.append(i)
                    start = i + 1
                    if len(hits) > 5:
                        break
                if hits:
                    print(f"  {s!r:<22} {label:<5} {len(hits)} hit(s): "
                          + ", ".join(f"0x{h:x}" for h in hits[:5]))
        mm.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
