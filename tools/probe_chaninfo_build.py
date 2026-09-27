#!/usr/bin/env python3
"""Rebuild the (0,1) CHANNELINFO body from its four inputs and diff the capture.

`0x593dc0` writes every field with an explicit field number and value, so the
whole plaintext is a pure function of (server, channel, advertiseHost,
unixSeconds):

    [u32le 507][protobuf]
      2  varint 1                     magic
      3  bytes[334]  the cipher key blob (from the static holder)
      4  bytes       "ch." + channel
      5  varint 0xb423                constant
      6  varint 0x3e401207            constant
      7  varint server
      8  varint channel
      9  varint 0                     constant
     10  varint 0                     constant
     11  varint unixSeconds
     12  bytes[128] advertiseHost, NUL padded
     13  varint 0x907                 constant
     14  varint 0x908                 constant

and the wire body is `rol8(b ^ 0xb5, 2)` over that.  If the rebuild is
byte-identical to the capture, the (0,1) frame is fully solved.
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
from uslocalserver.protocol.crypto import KEY_BLOB  # noqa: E402


def enc(b: bytes) -> bytes:
    return bytes((((x ^ 0xB5) << 2) | ((x ^ 0xB5) >> 6)) & 0xFF for x in b)


def dec(b: bytes) -> bytes:
    return bytes((((x >> 2) | (x << 6)) & 0xFF) ^ 0xB5 for x in b)


def varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def build(server: int, channel: int, host: str, unix_seconds: int,
          blob: bytes) -> bytes:
    p = bytearray()
    p += tag(2, 0) + varint(1)
    p += tag(3, 2) + varint(len(blob)) + blob
    ep = b"ch." + str(channel).encode()
    p += tag(4, 2) + varint(len(ep)) + ep
    p += tag(5, 0) + varint(0xB423)
    p += tag(6, 0) + varint(0x3E401207)
    p += tag(7, 0) + varint(server)
    p += tag(8, 0) + varint(channel)
    p += tag(9, 0) + varint(0)
    p += tag(10, 0) + varint(0)
    p += tag(11, 0) + varint(unix_seconds)
    hb = host.encode()[:128].ljust(128, b"\x00")
    p += tag(12, 2) + varint(len(hb)) + hb
    p += tag(13, 0) + varint(0x907)
    p += tag(14, 0) + varint(0x908)
    return struct.pack("<I", len(p)) + bytes(p)


def main() -> int:
    rows = [r for r in s2c_frames() if not r[7] and (r[3].main, r[3].sub) == (0, 1)]
    if not rows:
        print("no (0,1) frame")
        return 1
    line, ts, conn, op, hd, body, pl, trunc = rows[0]
    plain = dec(body)
    print(f"capture: line {line} body {len(body)}B  prefix={struct.unpack_from('<I', plain, 0)[0]}")

    # pull the four inputs back out of the capture
    print("reading inputs back out of the capture:")
    print(f"  server        = 1        (from log ROUTE)")
    print(f"  channel       = 10       (from log ROUTE)")
    print(f"  advertiseHost = 192.168.1.6")
    unix_seconds = None
    # field 11 sits right after the advertiseHost's tag; locate it by rebuilding
    # candidates instead: scan the plaintext's tail for the two trailing constants
    import re
    m = re.search(rb"\x58(\xc0\xa7\xdf\xd5)?\x06", plain)
    # simpler: the tail after the 128-byte host is tag13 varint tag14 varint
    tail = plain[-8:]
    print(f"  tail bytes    = {tail.hex(' ')}")
    # decode the last two varints
    def rv(b, p):
        v = s = 0
        while True:
            c = b[p]; p += 1
            v |= (c & 0x7F) << s
            if not c & 0x80:
                return v, p
            s += 7
    host_off = plain.find(b"192.168.1.6")
    p = host_off + 128
    f13, p = rv(plain, p + 1)
    f14, p = rv(plain, p + 1)
    print(f"  field13={f13:#x} field14={f14:#x}  (consumed to {p}/{len(plain)})")
    # field 11: walk from the start
    p = 4
    val = {}
    while p < host_off - 2:
        t, p = rv(plain, p)
        f, w = t >> 3, t & 7
        if w == 0:
            v, p = rv(plain, p); val[f] = v
        elif w == 2:
            n, p = rv(plain, p)
            val[f] = plain[p:p+n] if f != 3 else f"<{n}B blob>"
            p += n
    print(f"  field11 (unixSeconds) = {val.get(11)}")

    us = val.get(11)
    built = build(1, 10, "192.168.1.6", us, KEY_BLOB.read_bytes())
    print(f"\nrebuilt plaintext {len(built)}B vs capture {len(plain)}B")
    same_plain = built == plain
    print(f"  plaintext identical: {same_plain}")
    if not same_plain:
        for i in range(min(len(built), len(plain))):
            if built[i] != plain[i]:
                print(f"  first diff at +{i}: built {built[i]:#04x} capture {plain[i]:#04x}")
                lo = max(0, i - 8)
                print(f"    built   {built[lo:i+16].hex(' ')}")
                print(f"    capture {plain[lo:i+16].hex(' ')}")
                break
    else:
        print("  *** the (0,1) CHANNELINFO plaintext is fully reproduced ***")

    b2 = enc(built)
    print(f"\nbody identical: {b2 == body}")
    if b2 != body:
        for i in range(min(len(b2), len(body))):
            if b2[i] != body[i]:
                print(f"  first body diff at +{i}")
                break
    else:
        print("  *** the (0,1) CHANNELINFO wire body is byte-identical ***")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
