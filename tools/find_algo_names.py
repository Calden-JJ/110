#!/usr/bin/env python3
"""Find the AlgoId ordering in the exe by locating the cipher name strings.

The `channelinfo_key_blob.bin` is 14 concatenated key entries and the rule
`algo = TABLE[sub % 14]` is confirmed on 9 indices, but two tiles (0 and 8)
resist identification from the log alone.  The exe must contain a switch or a
static table naming all 14 ciphers, in AlgoId order.

All .NET strings in the binary are UTF-16LE, so an ASCII grep returns 0 hits.
This scans the exe in chunks and reports every occurrence of a cipher name,
sorted by file offset -- if the names sit in one contiguous region, their
order there *is* the AlgoId order.

Nothing large is read into memory: 8 MB chunks, only offsets kept.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\USLocalServer.Server.exe")

NAMES = ["Cast128", "CAST128", "Cast-128", "Skipjack", "Blowfish", "Twofish",
         "Misty", "MISTY", "Khazad", "Aes128", "AES128", "Aes", "Rc6", "RC6",
         "Rijndael", "Rij12", "Rijndael12", "Dfo16", "DFO16", "Dfo9", "DFO9",
         "Dfo11", "Dfo13", "Xor32", "Xor", "Custom8", "Custom 8",
         "AlgoId", "InitializeCiphers", "session ciphers"]

CHUNK = 8 << 20
OVERLAP = 4096


def main() -> int:
    pats = {n: re.compile(n.encode("utf-16-le")) for n in NAMES}
    hits: list[tuple[int, str]] = []
    with open(EXE, "rb") as f:
        base = 0
        prev = b""
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            data = prev + buf
            start = base - len(prev)
            for name, pat in pats.items():
                for m in pat.finditer(data):
                    hits.append((start + m.start(), name))
            prev = data[-OVERLAP:]
            base += len(buf)
    hits.sort()
    print(f"{len(hits)} name occurrences in {EXE.name}\n")
    for off, name in hits:
        print(f"   0x{off:08x}  {name}")

    print("\n== gaps between consecutive distinct names (clusters = a table) ==")
    last = None
    for off, name in hits:
        if last is not None and off - last > 0:
            gap = off - last
            if gap < 0x2000:
                print(f"   0x{off:08x}  +{gap:6d}  {name}")
        last = off
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
