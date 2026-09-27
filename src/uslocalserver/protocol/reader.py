"""Little-endian cursor for decoding packet bodies.

The protocol is .NET BinaryReader-ish: lengths are u32 and precede their
payload.  Everything raises `TruncatedBody` rather than returning short data,
so a mis-sized body shows up as an error instead of silently short fields.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


class TruncatedBody(ValueError):
    """Not enough bytes left for the field being read."""


@dataclass
class BodyReader:
    data: bytes
    pos: int = 0
    label: str = ""

    @classmethod
    def of_hex(cls, text: str, *, label: str = "") -> "BodyReader":
        return cls(bytes.fromhex(text), 0, label)

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    @property
    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def _need(self, n: int) -> None:
        if self.remaining < n:
            raise TruncatedBody(
                f"{self.label or 'body'}: need {n}B at offset {self.pos}, have {self.remaining}B"
            )

    def take(self, n: int) -> bytes:
        self._need(n)
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def rest(self) -> bytes:
        out = self.data[self.pos:]
        self.pos = len(self.data)
        return out

    def skip(self, n: int) -> None:
        self._need(n)
        self.pos += n

    def u8(self) -> int:
        return self.take(1)[0]

    def u16le(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u16be(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32le(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u32be(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def i32le(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def u64le(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def len_prefixed_bytes(self, *, width: int = 4, endian: str = "<") -> bytes:
        n = int.from_bytes(self.take(width), "little" if endian == "<" else "big")
        return self.take(n)

    def len_prefixed_str(self, *, encoding: str = "utf-8", width: int = 4,
                         endian: str = "<", errors: str = "replace") -> str:
        return self.len_prefixed_bytes(width=width, endian=endian).decode(encoding, errors)

    def cstring(self, *, encoding: str = "utf-8", errors: str = "replace") -> str:
        end = self.data.find(b"\x00", self.pos)
        if end < 0:
            raise TruncatedBody(f"{self.label or 'body'}: unterminated string at {self.pos}")
        out = self.data[self.pos:end].decode(encoding, errors)
        self.pos = end + 1
        return out

    def expect_zero(self, n: int) -> None:
        tail = self.take(n)
        if tail != bytes(n):
            raise ValueError(f"{self.label or 'body'}: expected {n} zero bytes, got {tail.hex()}")

    def expect_eof(self) -> None:
        if not self.eof:
            raise ValueError(f"{self.label or 'body'}: {self.remaining}B left over at {self.pos}")
