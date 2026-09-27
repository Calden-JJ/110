#!/usr/bin/env python3
"""What encrypts the CHANNELINFO first packet (S->C game (0,1), 511B body)?

Established before this script:

* C->S at ctr >= 3 is a 16B ECB block cipher with `E(0^16) = d8542ae1...`.
  `probe_c2s_cipher` (inline) matched that against every algorithm x every
  key window of `channelinfo_key_blob.bin` and got exactly one hit:
  **DFO-16B (algo 12), key = blob[278:294]**.
* S->C session packets are Xor32 with `06 83 1f 52` -- proven on 20+ bodies,
  e.g. `(0,2432)` decrypts to 207 zeros.
* CHANNELINFO is *not* Xor32 (best phase leaves only 3 zeros).

So this asks the obvious next question: is CHANNELINFO DFO-16B as well?

It also dumps the body's block structure, because the 117-byte 0xD6 run
starting at 388 cannot be block-cipher output: it is 117 bytes long, so it
cannot be a whole number of 16B blocks however the grid is offset, and a
block cipher cannot produce a 12-byte suffix equal to the next block's
12-byte prefix.  Whatever the run is, it is *passthrough*.
"""

from __future__ import annotations

import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import crypto as C  # noqa: E402

HDR = 16
PAD_BYTE = 0xD6


def asc(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def hexd(b: bytes, base: int = 0, width: int = 16, limit: int | None = None) -> None:
    b = b if limit is None else b[:limit]
    for i in range(0, len(b), width):
        c = b[i:i + width]
        print(f"  {base + i:04x}  {' '.join(f'{x:02x}' for x in c):<47}  {asc(c)}")


def zeros(b: bytes) -> tuple[int, int]:
    return b.count(0), max((len(m.group()) for m in re.finditer(rb"\x00+", b)), default=0)


def channelinfo() -> bytes:
    for ln in logs.stream(paths.LOGS_DIR / "server-20260926.log"):
        if ln.tag == "PACKET" and "raw=527" in ln.msg:
            return logs.find_hex_field(ln.msg, "hex").data[HDR:]
    raise SystemExit("no 527B packet in the log")


def main() -> int:
    body = channelinfo()
    blob = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()
    key = blob[278:294]
    print(f"body {len(body)}B, DFO-16B key blob[278:294] = {key.hex()}\n")

    print("== where the 0xD6 run sits ==")
    for m in re.finditer(rb"\xd6{4,}", body):
        print(f"   run [{m.start()}, {m.end()})  len={m.end() - m.start()}"
              f"   start%16={m.start() % 16}  end%16={m.end() % 16}")
    print(f"   body = 511 = 4 + 31*16 + 11? {4 + 31 * 16 + 11}")

    print("\n== DFO-16B ECB decrypt at every grid offset ==")
    for off in range(16):
        pt = C.ecb_decrypt(C.dfo16_decrypt, body[off:], key, 16)
        z, run = zeros(pt)
        print(f"   off={off:2d}  zeros={z:4d}  longest_zero_run={run:4d}  first8={pt[:8].hex()}")

    print("\n== every algo x every blob key window, scored by longest zero run ==")
    hits = []
    for name, _enc, dec, _o, klen, bs in C.SELFTEST:
        for o in range(0, len(blob) - klen + 1):
            k = blob[o:o + klen]
            for off in (0, 4):
                try:
                    pt = C.ecb_decrypt(dec, body[off:], k, bs)
                except Exception:
                    continue
                z, run = zeros(pt)
                if run >= 32:
                    hits.append((run, z, name, o, off, pt[:24].hex()))
    for h in sorted(hits, reverse=True)[:12]:
        print(f"   run={h[0]:4d} zeros={h[1]:4d} {h[2]:10s} blob[{h[3]}:] off={h[4]}  {h[5]}")
    print(f"   ({len(hits)} hits with a zero run >= 32)")

    print("\n== body, for reference ==")
    hexd(body[:64])
    print("   ...")
    hexd(body[368:400], base=368)
    print("   ...")
    hexd(body[496:], base=496)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
