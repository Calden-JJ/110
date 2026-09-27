"""Wire framing for the four DFO links.

    link          hdr  opcode                    length        trailer
    channel-c2s   11   u16BE @0                  u32le @2      [6:11]
    channel-s2c   11   u16BE @0                  u32le @2      [6:11]
    game-c2s      13   u8 main @0 + u16le @1      u32le @3      [7:13]
    game-s2c      16   u8 main @0 + u16le @1      u32le @3      [7:16]

All four were measured off `DEBUG PACKET ... hex=` dumps in
server-20260926.log (221/61/3/3 frames), not inferred: the length field is
always the whole frame size, including the header.

On the game links `main` is a direction/response flag, not an opcode family.
game-c2s is 1 on every one of its 221 frames.  game-s2c is 0 on 47/61 and 1
on 14/61 -- and 13 of those 14 land 0-24 ms after a c2s frame carrying the
*same* sub (three (1,433)s answered by three (1,433)s), so an s2c `main=1`
frame reuses the opcode of the request it answers.  The exception, (1,845),
has no c2s match anywhere in the capture.  main=0 subs are otherwise a
disjoint server-initiated set.  (An earlier draft of this module said
game-s2c's main "is 0"; that was wrong.)

The channel trailer, always `00 00 00 00 01`, stays opaque -- its meaning is
unknown.

The game-s2c trailer does *not*.  It is `[7:11] = LE32(v)`, `[11] = v & 0xFF`,
`[12:15] = nonce24`, `[15] = flag`, where `v = header_tag(body_digest(body))`
over the *encrypted* body -- read off the exe's builder at `0x5814b0` and
corroborated on all 57 untruncated S->C frames of the capture.  Note the four
bytes `[7:11]` are *not* equal to `[11:15]` (0/61); an earlier draft of this
module concluded they were, and that wrong conclusion is worth keeping nailed
down by a test.

Bodies are kept exactly as they appear on the wire (still encrypted, or
still zlib-compressed for channel-s2c).  Decryption is a separate step so the
frame layer stays testable against the raw dumps on its own.
"""
from __future__ import annotations

import enum
import struct
from dataclasses import dataclass, field
from typing import Final, Iterator

CHANNEL_TRAILER: Final[bytes] = b"\x00\x00\x00\x00\x01"

#: The game links' body digest.  Reflected CRC-32 like the standard one but
#: poly 0x4DB89129, seed 0, final xor 0xFFFFFFFF -- not zlib.crc32.
CRC_POLY: Final[int] = 0x4DB89129
_M32: Final[int] = 0xFFFFFFFF


def _crc_table(poly: int) -> tuple[int, ...]:
    out = []
    for i in range(0x100):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (poly if c & 1 else 0)
        out.append(c & _M32)
    return tuple(out)


_BODY_TABLE: Final[tuple[int, ...]] = _crc_table(CRC_POLY)


def body_digest(body: bytes) -> int:
    c = _M32
    for b in body:
        c = (c >> 8) ^ _BODY_TABLE[(c ^ b) & 0xFF]
    return c ^ _M32


def header_tag(w: int) -> int:
    """`0x580c50`: fold the CRC's four bytes into its own low byte, xor 0x18."""
    f = (w ^ (w >> 8) ^ (w >> 16) ^ (w >> 24)) & 0xFF
    return (w & 0xFFFFFF00) | (f ^ 0x18)


class ProtocolError(Exception):
    """Base class for every framing failure."""


class ShortFrame(ProtocolError):
    """Not enough bytes buffered yet -- normal control flow for FrameStream."""


class LengthMismatch(ProtocolError):
    """The length field disagrees with the bytes actually present."""


class FrameTooLarge(ProtocolError):
    """Declared size exceeds the configured cap; the stream is unrecoverable."""


class BadFixedTail(ProtocolError):
    """The channel trailer is not the expected constant."""


class BadGameTrailer(ProtocolError):
    """game-s2c's last header byte is not zero."""


class BadGameDigest(ProtocolError):
    """game-s2c's `[7:11]` is not `tag(crc32(body))`."""


class ForeignOpcode(ProtocolError):
    """An opcode encoded for a different link was passed to build()."""


class Link(enum.Enum):
    CHANNEL_C2S = "channel-c2s"
    CHANNEL_S2C = "channel-s2c"
    GAME_C2S = "game-c2s"
    GAME_S2C = "game-s2c"

    @property
    def namespace(self) -> str:
        """Opcodes are numbered per server, so channel and game never mix."""
        return self.value.split("-")[0]


class OpcodeEncoding(enum.Enum):
    U8_U16LE = "u8+u16le"   # game:   [0]=main, [1:3]=sub
    U16BE = "u16be"         # channel: [0:2] packed


@dataclass(frozen=True, slots=True)
class Opcode:
    main: int
    sub: int
    encoding: OpcodeEncoding
    main_is_semantic: bool = True

    @classmethod
    def from_game(cls, buf: bytes | memoryview) -> "Opcode":
        return cls(buf[0], struct.unpack_from("<H", buf, 1)[0], OpcodeEncoding.U8_U16LE, True)

    @classmethod
    def from_channel(cls, buf: bytes | memoryview) -> "Opcode":
        raw = struct.unpack_from(">H", buf, 0)[0]
        # The 0x7c prefix on server->client channel frames is unexplained
        # (main=124 or a response flag).  Until it is pinned, main is not
        # treated as a semantic field and the value stays out of the game
        # namespace -- flipping this bool is the only change that takes.
        return cls(raw >> 8, raw & 0xFF, OpcodeEncoding.U16BE, False)

    def to_bytes(self) -> bytes:
        if self.encoding is OpcodeEncoding.U8_U16LE:
            return bytes([self.main]) + struct.pack("<H", self.sub)
        return struct.pack(">H", (self.main << 8) | self.sub)

    def key(self) -> tuple[int, int]:
        return (self.main, self.sub)

    def __str__(self) -> str:
        return f"({'' if self.main_is_semantic else '?'}{self.main},{self.sub})"


@dataclass(frozen=True, slots=True)
class LinkSpec:
    link: Link
    header_len: int
    length_offset: int
    opcode_encoding: OpcodeEncoding
    opcode_len: int
    trailer_len: int
    fixed_trailer: bytes | None
    body_encrypted: bool
    body_may_be_zlib: bool
    doc: str = ""

    def default_trailer(self, *, seq: int = 0) -> bytes:
        if self.fixed_trailer is not None:
            return self.fixed_trailer
        if self.link is Link.GAME_S2C:
            # Not a constant, and not nine zero bytes either (0/61 measured
            # frames look like that): `[7:11]` is a digest of the body, which
            # this method has no way to see.  `build` derives it; reaching
            # here means a trailer was asked for with no frame under it.
            raise ProtocolError("game-s2c's trailer is a function of the body; "
                                "build the frame instead")
        pad = bytes(self.trailer_len - 2)
        return pad + struct.pack("<H", seq) if self.link is Link.GAME_C2S else bytes(self.trailer_len)


SPECS: Final[dict[Link, LinkSpec]] = {
    Link.CHANNEL_C2S: LinkSpec(
        Link.CHANNEL_C2S, 11, 2, OpcodeEncoding.U16BE, 2, 5, CHANNEL_TRAILER,
        body_encrypted=True, body_may_be_zlib=False,
        doc="client -> channel server (port 7001)",
    ),
    Link.CHANNEL_S2C: LinkSpec(
        Link.CHANNEL_S2C, 11, 2, OpcodeEncoding.U16BE, 2, 5, CHANNEL_TRAILER,
        body_encrypted=False, body_may_be_zlib=True,
        doc="channel server -> client; body is often plain zlib (78 9c)",
    ),
    Link.GAME_C2S: LinkSpec(
        Link.GAME_C2S, 13, 3, OpcodeEncoding.U8_U16LE, 3, 6, None,
        body_encrypted=True, body_may_be_zlib=False,
        doc="client -> game server (ports 10011-10021), main is 1",
    ),
    Link.GAME_S2C: LinkSpec(
        Link.GAME_S2C, 16, 3, OpcodeEncoding.U8_U16LE, 3, 9, None,
        body_encrypted=True, body_may_be_zlib=False,
        doc="game server -> client; main 1 = response echoing the request, 0 = push",
    ),
}


def spec(link: Link) -> LinkSpec:
    return SPECS[link]


def header_len(link: Link) -> int:
    return SPECS[link].header_len


def declared_size(link: Link, buf: bytes | bytearray | memoryview) -> int | None:
    """Frame size read from the header, or None if the header is incomplete."""
    sp = SPECS[link]
    if len(buf) < sp.header_len:
        return None
    off = sp.length_offset
    return struct.unpack_from("<I", buf, off)[0]


def parse(link: Link, data: bytes, *, strict: bool = True,
          expect_size: int | None = None) -> Frame:
    """Decode exactly one frame.

    `expect_size` states the frame's true size when the dump is truncated
    (`hex=<4096B>...(+NNB)` in the logs), so the length field can still be
    validated against it.
    """
    sp = SPECS[link]
    n = len(data)
    if n < sp.header_len:
        raise ShortFrame(f"{link.value}: {n}B is shorter than the {sp.header_len}B header")

    header = bytes(data[:sp.header_len])
    wire_size = struct.unpack_from("<I", data, sp.length_offset)[0]
    body = bytes(data[sp.header_len:])
    warning_list: list[str] = []

    stated = n if expect_size is None else expect_size
    truncated = stated > n
    if wire_size != stated:
        msg = f"{link.value}: length field says {wire_size}, have {stated}"
        if strict:
            raise LengthMismatch(msg)
        warning_list.append(msg)
    if not truncated and wire_size != sp.header_len + len(body):
        msg = (f"{link.value}: length field {wire_size} != "
               f"{sp.header_len}B header + {len(body)}B body")
        if strict:
            raise LengthMismatch(msg)
        warning_list.append(msg)

    opcode = (Opcode.from_game(header) if sp.opcode_encoding is OpcodeEncoding.U8_U16LE
              else Opcode.from_channel(header))

    if sp.fixed_trailer is not None:
        got = header[sp.header_len - sp.trailer_len:]
        if got != sp.fixed_trailer:
            msg = f"{link.value}: trailer {got.hex()} != {sp.fixed_trailer.hex()}"
            if strict:
                raise BadFixedTail(msg)
            warning_list.append(msg)

    if link is Link.GAME_S2C and header[15] != 0x00:
        msg = f"game-s2c: final header byte is {header[15]:#04x}, expected 0x00"
        if strict:
            raise BadGameTrailer(msg)
        warning_list.append(msg)
    if link is Link.GAME_S2C and header[7] != header[11]:
        warning_list.append(
            f"game-s2c: header[7]={header[7]:#04x} != header[11]={header[11]:#04x} "
            "(holds for 61/61 measured frames)"
        )
    if link is Link.GAME_S2C and not truncated:
        want = header_tag(body_digest(body))
        if header[7:11] != struct.pack("<I", want):
            msg = (f"game-s2c: header[7:11]={header[7:11].hex()} != "
                   f"LE32(tag(crc(body)))={struct.pack('<I', want).hex()}")
            if strict:
                raise BadGameDigest(msg)
            warning_list.append(msg)

    return Frame(link, opcode, body, wire_size, header, tuple(warning_list))


def try_parse(link: Link, data: bytes, *, expect_size: int | None = None) -> Frame | None:
    try:
        return parse(link, data, strict=True, expect_size=expect_size)
    except ProtocolError:
        return None


def build(link: Link, opcode: Opcode, body: bytes = b"", *,
          seq: int = 0, trailer: bytes | None = None) -> bytes:
    """Encode a frame.

    `trailer` overrides the header bytes after the length field, which is what
    makes a byte-exact round-trip of a captured frame possible.  Left out,
    game-s2c derives its own from the body -- so what this function builds is
    always something `parse` accepts.  The two fields the body cannot decide,
    the nonce and the flag, are `build_s2c`'s.
    """
    sp = SPECS[link]
    if opcode.encoding is not sp.opcode_encoding:
        raise ForeignOpcode(f"{opcode} is {opcode.encoding.value}, {link.value} wants "
                            f"{sp.opcode_encoding.value}")
    if trailer is None and link is Link.GAME_S2C:
        return build_s2c(opcode, body)
    if trailer is None:
        trailer = sp.default_trailer(seq=seq)
    if len(trailer) != sp.trailer_len:
        raise ProtocolError(f"trailer must be {sp.trailer_len}B, got {len(trailer)}B")
    total = sp.header_len + len(body)
    return opcode.to_bytes() + struct.pack("<I", total) + trailer + body


def s2c_header(opcode: Opcode, body: bytes, *, nonce: bytes | None = None,
               flag: bool = False) -> bytes:
    """The 16-byte game-s2c header for `body`, as `0x5814b0` builds it.

    `nonce` is the 3 bytes the capture carries at `[12:15]`.  When it is None
    those bytes hold `v >> 8` instead -- what the builder leaves there when its
    nonce flag is clear.  Passing a captured nonce is the faithful choice; the
    flag byte at `[15]` is 0 on every frame of the capture either way.
    """
    v = header_tag(body_digest(body))
    tail = (bytes([(v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF])
            if nonce is None else nonce)
    if len(tail) != 3:
        raise ProtocolError(f"nonce must be 3B, got {len(tail)}B")
    return (bytes([opcode.main & 0xFF]) + struct.pack("<H", opcode.sub)
            + struct.pack("<I", SPECS[Link.GAME_S2C].header_len + len(body))
            + struct.pack("<I", v) + bytes([v & 0xFF]) + tail
            + bytes([1 if flag else 0]))


def build_s2c(opcode: Opcode, body: bytes, *, nonce: bytes | None = None,
              flag: bool = False) -> bytes:
    """A whole game-s2c frame: derived header + body, no bytes passed through."""
    return s2c_header(opcode, body, nonce=nonce, flag=flag) + body


@dataclass(frozen=True, slots=True)
class Frame:
    link: Link
    opcode: Opcode
    body: bytes
    wire_size: int
    header: bytes
    warnings: tuple[str, ...] = field(default=())

    @property
    def header_len(self) -> int:
        return len(self.header)

    @property
    def frame_size(self) -> int:
        return len(self.header) + len(self.body)

    @property
    def trailer(self) -> bytes:
        return self.header[self.header_len - SPECS[self.link].trailer_len:]

    @property
    def seq(self) -> int | None:
        """game-c2s's per-connection counter at [11:13].  Measured on conn=2:
        221 frames running exactly 0..220, no gaps."""
        if self.link is not Link.GAME_C2S:
            return None
        return struct.unpack_from("<H", self.header, 11)[0]

    def with_body(self, body: bytes) -> "Frame":
        return Frame(self.link, self.opcode, body, self.header_len + len(body),
                     self.header, self.warnings)

    def rebuild(self) -> bytes:
        return self.header + self.body

    def __str__(self) -> str:
        return f"<{self.link.value} {self.opcode} {self.frame_size}B>"


class FrameStream:
    """Incremental framer for a TCP connection.

    The link must be given explicitly.  Auto-detecting it is not possible:
    channel headers are 11B and game headers 16B, and a game-s2c frame may
    legitimately start with 0x00.
    """

    def __init__(self, link: Link, *, strict: bool = True,
                 max_body: int = 4 << 20, max_buffer: int = 8 << 20) -> None:
        self.link = link
        self.strict = strict
        self.max_body = max_body
        self.max_buffer = max_buffer
        self._buf = bytearray()
        self._poisoned = False

    @property
    def pending(self) -> int:
        return len(self._buf)

    @property
    def poisoned(self) -> bool:
        return self._poisoned

    def reset(self) -> None:
        self._buf.clear()
        self._poisoned = False

    def feed(self, data: bytes) -> None:
        if self._poisoned:
            raise ProtocolError("stream is poisoned; discard the connection")
        self._buf += data
        if len(self._buf) > self.max_buffer:
            self._poisoned = True
            raise FrameTooLarge(f"buffer exceeded {self.max_buffer}B without a full frame")

    def next_frame(self) -> Frame | None:
        if self._poisoned:
            raise ProtocolError("stream is poisoned; discard the connection")
        sp = SPECS[self.link]
        if len(self._buf) < sp.header_len:
            return None
        size = struct.unpack_from("<I", self._buf, sp.length_offset)[0]
        if size < sp.header_len:
            # No amount of further bytes can make this consistent.
            self._poisoned = True
            raise LengthMismatch(f"declared size {size} < {sp.header_len}B header")
        if size > sp.header_len + self.max_body:
            self._poisoned = True
            raise FrameTooLarge(f"declared size {size} exceeds the {self.max_body}B body cap")
        if len(self._buf) < size:
            return None
        frame = parse(self.link, bytes(self._buf[:size]), strict=self.strict)
        del self._buf[:size]
        return frame

    def frames(self) -> list[Frame]:
        out = []
        while (f := self.next_frame()) is not None:
            out.append(f)
        return out

    def __iter__(self) -> Iterator[Frame]:
        while True:
            f = self.next_frame()
            if f is None:
                return
            yield f
