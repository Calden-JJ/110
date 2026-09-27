#!/usr/bin/env python3
"""Decode the `(0,1)` CHANNELINFO body -- the one frame that resists.

Facts already established, so nothing here re-tests them:

* S->C game, header 16B, wire 527 = 16 + 511.  The server logs `CHANNELINFO
  conn=N sent first packet wire=527B plain=511B; session ciphers initialized`.
  `plain=` is the pre-compression size elsewhere in the same log (channel
  `SCRIPT_ACK plain=1384B wire=1208B`), so plaintext and body are both 511B,
  and the frame goes out *before* the session ciphers exist.
* Its only constant run is 117x `0xD6` at `body[388:505)`, and 505 = 511 - 6.
  A run that long cannot survive any cipher, so `[388:505)` is passthrough.
  The body contains no 0x00 byte at all (198 distinct values).
* Xor32 (`06831f52`) is not it, and neither is any one block cipher over the
  whole body.

So this sweeps identity, single-byte XOR, XOR against every window of the key
blob (plus the blob tiled), every suite cipher in ECB both directions over
several spans, and the standard decompressors.  Candidates are ranked by
printable-ASCII ratio -- coherent output stands out from a ~30% noise floor.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import sys
import zlib
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import crypto as C  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402

LOG = paths.LOGS_DIR / "server-20260926.log"
LINE = 6392
BLOB = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()

TILES = [(0, 16), (16, 32), (32, 92), (92, 124), (124, 140), (140, 150),
         (150, 166), (166, 222), (222, 238), (238, 254), (254, 262),
         (262, 278), (278, 294), (294, 334)]
FNS = [(n[:-8], getattr(C, n)) for n in dir(C)
       if n.endswith("_decrypt") and n != "ecb_decrypt"]


def body() -> bytes:
    for pk in logs.iter_packets(LOG):
        if pk.line_no == LINE:
            f = frame.parse(frame.Link.GAME_S2C, pk.hex.data)
            assert (f.opcode.main, f.opcode.sub) == (0, 1), f.opcode
            return f.body
    raise SystemExit(f"line {LINE} has no hex dump")


def score(data: bytes) -> float:
    """Printable-ASCII ratio, nudged towards letters and digits."""
    if not data:
        return 0.0
    good = sum(1 for c in data if 32 <= c < 127)
    nice = sum(1 for c in data if 48 <= c < 58 or 65 <= c < 91 or 97 <= c < 123)
    return (good + 2 * nice) / (3 * len(data))


def preview(data: bytes, limit: int = 96) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in data[:limit])


def main() -> int:
    b = body()
    print(f"CHANNELINFO body {len(b)}B  first16={b[:16].hex()}")
    print(f"noise floor (identity) {score(b):.3f}\n")

    hits: list[tuple[float, str, bytes]] = []
    hits.append((score(b), "identity", b))

    for k in range(256):
        hits.append((score(bytes(c ^ k for c in b)), f"xor1 {k:#04x}", b))
    hits.append((score(bytes(c ^ k for c in b)), "xor1 0xd6", b))

    for klen in (1, 2, 4, 8, 16, 32, 60, 64, 128, 256):
        for o in range(0, len(BLOB) - klen + 1):
            k = BLOB[o:o + klen]
            x = bytes(c ^ k[i % klen] for i, c in enumerate(b))
            hits.append((score(x), f"xorb {klen}B blob[{o}:{o+klen}]", x))
    tiled = (BLOB * 3)[:len(b)]
    hits.append((score(bytes(c ^ t for c, t in zip(b, tiled))), "xorb tiled blob", b))

    spans = [(0, 384), (0, 388), (0, 504), (0, 505), (0, 511)]
    for name, fn in FNS:
        enc = getattr(C, name + "_encrypt")
        for a, z in spans:
            for bs in (8, 16):
                if (z - a) % bs:
                    continue
                for to, tl in TILES:
                    k = BLOB[to:to + tl]
                    tag = f"tile[{to}:{to+tl}] bs={bs} span[{a}:{z}]"
                    try:
                        hits.append((score(C.ecb_decrypt(fn, b[a:z], k, bs)),
                                     f"dec {name} {tag}", b[a:z]))
                        hits.append((score(C.ecb_encrypt(enc, b[a:z], k, bs)),
                                     f"enc {name} {tag}", b[a:z]))
                    except Exception:
                        pass

    for name, fn in (("zlib", zlib.decompress), ("gzip", gzip.decompress),
                     ("bz2", bz2.decompress), ("lzma", lzma.decompress)):
        for cut in (0, 4, 8, 16):
            try:
                out = fn(b[cut:])
                hits.append((score(out), f"{name} body[{cut}:]", out))
            except Exception:
                pass

    hits.sort(key=lambda t: -t[0])
    print("== top candidates ==")
    for s, why, data in hits[:12]:
        print(f"  {s:.3f}  {why:<46} {preview(data)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
