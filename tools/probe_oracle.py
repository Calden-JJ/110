#!/usr/bin/env python3
"""Hunt the known-plaintext oracle + key material across every readable binary.

Targets, in order of value:
  * E(0^16) = d8542ae1bbeac96b9ccf9ac12d501244  (cipher self-test / fixed vector)
  * Xor32 key  06 83 1f 52
  * first 16 B of channelinfo_key_blob.bin  (01 83 b1 cd 7b 3a 17 63 e0 5b 69 0c ac 2b 38 bc)
  * the blob seed prefix, if the derivation wrote it as text

Managed (decompilable) assemblies are the jackpot: same suite in IL.
"""

from __future__ import annotations

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(r"E:\DFO_2.31.1.117")
KB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto\channelinfo_key_blob.bin")

ORACLE_LE = bytes.fromhex("4412502dc19acf9c6bc9eabbe12a54d8")
ORACLE_BE = bytes.fromhex("d8542ae1bbeac96b9ccf9ac12d501244")
XOR32 = bytes.fromhex("06831f52")
KB16 = KB.read_bytes()[:16] if KB.exists() else b"\x01\x83\xb1\xcd\x7b\x3a\x17\x63"
KB_TAIL = KB.read_bytes()[256:272] if KB.exists() else b""

PATTERNS = [
    ("oracle-LE", ORACLE_LE),
    ("oracle-BE", ORACLE_BE),
    ("xor32-key", XOR32),
    ("keyblob[0:16]", KB16),
    ("keyblob[256:272]", KB_TAIL),
]

FILES = []
for pat in ("*.exe", "*.dll"):
    FILES += sorted(ROOT.glob(pat))
FILES += sorted(ROOT.glob("*/*.dll"))
FILES += sorted(ROOT.glob("*/*.exe"))
seen = set()
uniq = []
for f in FILES:
    try:
        k = f.resolve()
    except OSError:
        continue
    if k in seen or f.stat().st_size > 300 * 1024 * 1024:
        continue
    seen.add(k)
    uniq.append(f)


def main():
    for f in uniq:
        try:
            d = f.read_bytes()
        except OSError as e:
            print(f"-- {f}: unreadable ({e})")
            continue
        hits = []
        for tag, pat in PATTERNS:
            start = 0
            n = 0
            while n < 6:
                i = d.find(pat, start)
                if i < 0:
                    break
                hits.append((tag, i))
                start = i + 1
                n += 1
        if hits:
            print(f"\n== {f}  ({len(d):,} B) ==")
            for tag, i in sorted(hits, key=lambda h: (h[1], h[0])):
                ctx = d[max(0, i - 24):i + len(pat) + 24]
                txt = "".join(chr(c) if 32 <= c < 127 else "." for c in ctx)
                print(f"   {tag:18} @ 0x{i:08x}  ctx: {ctx.hex()}")
                print(f"   {'':18} {'':12} txt: {txt}")


if __name__ == "__main__":
    raise SystemExit(main())
