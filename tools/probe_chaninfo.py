#!/usr/bin/env python3
"""Decode the (0,1) CHANNELINFO body with the transform found at 0x582880.

0x582880 -- called only from the (0,1) sender 0x5811b0, whose result goes
straight into the frame builder's body -- is a byte-wise permutation:

    out[i] = rol8(in[i] ^ 0xb5, 2)

So the inverse is `ror8(b, 2) ^ 0xb5`.  `FromChannelInfoPlaintext` (0x582c40)
expects a byte[] with u32le length prefixes, so a correct decode shows ASCII
slot text (timezone name, channel list, ...).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_s2c_hdr import s2c_frames  # noqa: E402


def dec(b: bytes) -> bytes:
    return bytes(((x >> 2) | (x << 6)) & 0xFF ^ 0xB5 for x in b)


def enc(b: bytes) -> bytes:
    return bytes((((x ^ 0xB5) << 2) | ((x ^ 0xB5) >> 6)) & 0xFF for x in b)


def main() -> int:
    rows = [r for r in s2c_frames() if not r[7]]
    targets = [r for r in rows if (r[3].main, r[3].sub) == (0, 1)]
    print(f"{len(rows)} S->C frames, {len(targets)} with opcode (0,1)\n")
    for r in targets:
        line, ts, conn, op, hd, body, pl, trunc = r
        print(f"--- line {line} conn {conn} body {len(body)}B truncated={trunc} ---")
        if pl is not None:
            print(f"  log plain= is present ({len(pl)}B); round-trip: "
                  f"{enc(pl) == body}")
        d = dec(body)
        print(f"  decoded head: {d[:64].hex()}")
        # printable scan
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in d)
        print(f"  ascii: {txt[:200]}")
        # u32le length-prefixed slot walk
        p = 0
        slots = []
        while p + 4 <= len(d):
            n = struct.unpack_from("<I", d, p)[0]
            if n > len(d) - p - 4:
                slots.append((p, "BADLEN", n))
                break
            s = d[p + 4:p + 4 + n]
            slots.append((p, n, s))
            p += 4 + n
        print(f"  slots walked: {len(slots)} (consumed {p}/{len(d)})")
        for off, n, s in slots[:20]:
            if isinstance(s, bytes):
                rep = s.decode("utf-8", "replace") if all(32 <= c < 127 or c in (9, 10, 13) for c in s) else s[:24].hex()
                print(f"    +{off:<4} n={n:<5} {rep!r}")
            else:
                print(f"    +{off:<4} {n} {s}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
