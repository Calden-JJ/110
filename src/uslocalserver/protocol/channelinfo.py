"""The `(0,1)` CHANNELINFO body: the first frame a game connection ever sees.

It goes out *before* the session ciphers exist -- the reference logs it as
"sent first packet ... ; session ciphers initialized" -- so it is not one of
the 14 tiles.  It is `rol8(b ^ 0xb5, 2)` over a 511-byte plaintext:

    [u32le 507][protobuf]
      2  varint 1                      magic
      3  bytes[334]  the cipher key blob
      4  bytes       "ch." + channel
      5  varint 0xb423                 constant
      6  varint 0x3e401207             constant
      7  varint server
      8  varint channel
      9  varint 0                      constant
     10  varint 0                      constant
     11  varint unixSeconds
     12  bytes[128] advertiseHost, NUL padded
     13  varint 0x907                 constant
     14  varint 0x908                 constant

Field numbers and values come from the writer at `0x593dc0`, which sets every
field explicitly.  The whole thing is a pure function of (server, channel,
host, unixSeconds), and rebuilding it from those four inputs reproduces the
captured 511 bytes byte-for-byte -- see `tools/probe_chaninfo_build.py`.  So
the frame is *generated*, not replayed, which is what makes the timestamp
fresh rather than a day stale.

The client's use of field 11 is unknown, as is whether it validates the
timestamp at all.  Generating is the conservative choice: a replay would be
wrong if it does, and identical if it does not.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import time
from typing import Final

from .crypto import KEY_BLOB

MAGIC: Final[int] = 1
CONST_5: Final[int] = 0xB423
CONST_6: Final[int] = 0x3E401207
CONST_13: Final[int] = 0x907
CONST_14: Final[int] = 0x908
HOST_FIELD_LEN: Final[int] = 128
XOR_BYTE: Final[int] = 0xB5


def _varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tv(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _bytes_field(field: int, data: bytes) -> bytes:
    return _tv(field, 2) + _varint(len(data)) + data


def _int_field(field: int, value: int) -> bytes:
    return _tv(field, 0) + _varint(value)


def encode(plain: bytes) -> bytes:
    """`rol8(b ^ 0xb5, 2)` -- the wire form of a CHANNELINFO plaintext."""
    return bytes((((x ^ XOR_BYTE) << 2) | ((x ^ XOR_BYTE) >> 6)) & 0xFF for x in plain)


def decode(body: bytes) -> bytes:
    """Inverse of `encode`: `ror8(b, 2) ^ 0xb5`."""
    return bytes((((x >> 2) | (x << 6)) & 0xFF) ^ XOR_BYTE for x in body)


def build_plaintext(server: int, channel: int, advertise_host: str,
                    unix_seconds: int | None = None,
                    blob: bytes | None = None) -> bytes:
    """The 511-byte plaintext, `[u32le len][protobuf]`."""
    p = bytearray()
    p += _int_field(2, MAGIC)
    p += _bytes_field(3, blob if blob is not None else KEY_BLOB.read_bytes())
    p += _bytes_field(4, b"ch." + str(channel).encode())
    p += _int_field(5, CONST_5)
    p += _int_field(6, CONST_6)
    p += _int_field(7, server)
    p += _int_field(8, channel)
    p += _int_field(9, 0)
    p += _int_field(10, 0)
    p += _int_field(11, int(time.time()) if unix_seconds is None else unix_seconds)
    p += _bytes_field(12, advertise_host.encode()[:HOST_FIELD_LEN]
                      .ljust(HOST_FIELD_LEN, b"\x00"))
    p += _int_field(13, CONST_13)
    p += _int_field(14, CONST_14)
    return struct.pack("<I", len(p)) + bytes(p)


def build(server: int, channel: int, advertise_host: str,
          unix_seconds: int | None = None) -> bytes:
    """The 511-byte wire body."""
    return encode(build_plaintext(server, channel, advertise_host, unix_seconds))


def local_address(fallback: str = "127.0.0.1") -> str:
    """The primary private IPv4, the way the reference auto-detects it.

    A connected UDP socket makes the kernel pick the interface for us; nothing
    is sent.  Loopback and link-local come back only when there is no route.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 53))
            addr = s.getsockname()[0]
        ip = ipaddress.ip_address(addr)
        if ip.is_loopback or ip.is_link_local:
            return fallback
        return addr
    except OSError:
        return fallback
