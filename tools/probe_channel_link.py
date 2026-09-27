#!/usr/bin/env python3
"""Dump every channel-link (port 7001) frame in wire order, both directions.

The channel link is the smallest complete sub-protocol: 3 C->S frames and 3
S->C frames in the whole capture, all of them carried a declared length, so
it is the right place to build a byte-exact replayer first.

For each frame: header fields, body size, whether the body is plain zlib, and
the raw/decompressed bytes.
"""
from __future__ import annotations

import sys
import zlib
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from uslocalserver.protocol import frame  # noqa: E402
from probe_s2c_hdr import HEX_RE, LINE_RE, LOG, PKT_RE  # noqa: E402


def channel_frames():
    """(line, hh:mm:ss.mmm, conn, direction, hdr, body, truncated)."""
    out = []
    with open(LOG, encoding="utf-8", errors="replace") as f:
        for i, ln in enumerate(f, 1):
            m = LINE_RE.match(ln)
            if not m:
                continue
            ts, lvl, tag, msg = m.groups()
            if lvl != "DEBUG" or tag != "PACKET":
                continue
            m2 = PKT_RE.search(msg)
            if not m2 or m2.group(3) != "channel":
                continue
            hm = HEX_RE.search(msg)
            if not hm:
                continue
            c2s = m2.group(2) == "C->S"
            link = frame.Link.CHANNEL_C2S if c2s else frame.Link.CHANNEL_S2C
            raw = bytes.fromhex(hm.group(1))
            try:
                fr = frame.parse(link, raw, strict=False)
            except frame.ProtocolError:
                continue
            out.append((i, ts[11:], int(m2.group(1)), "C->S" if c2s else "S->C",
                        raw[:11], fr.body, "(+" in msg))
    out.sort()
    return out


def ascii_scan(b: bytes, width: int = 96) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:width])


def show(body: bytes, trunc: bool) -> None:
    print(f"    body {len(body)}B{'  TRUNCATED' if trunc else ''}")
    if not body:
        return
    if body[:1] == b"\x78":
        try:
            d = zlib.decompress(body)
        except zlib.error as e:
            print(f"    zlib FAILED: {e}")
            return
        print(f"    zlib -> {len(d)}B")
        print(f"      {d[:48].hex(' ')}")
        print(f"      ascii: {ascii_scan(d)}")
        return
    print(f"    {body[:64].hex(' ')}")
    print(f"    ascii: {ascii_scan(body)}")


def main() -> int:
    rows = channel_frames()
    print(f"CHANNEL-LINK FRAMES (port 7001), wire order -- {len(rows)} total\n")
    for line, ts, conn, direction, hdr, body, trunc in rows:
        raw_op = int.from_bytes(hdr[:2], "big")
        stated = int.from_bytes(hdr[2:6], "little")
        print(f"line {line}  {ts}  conn={conn}  {direction}  rawop={raw_op:#06x} "
              f"(main={raw_op >> 8},sub={raw_op & 0xFF})  len={stated}  "
              f"trailer={hdr[6:].hex(' ')}")
        show(body, trunc)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
