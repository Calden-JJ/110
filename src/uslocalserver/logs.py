"""Parsing of the reference server's log files.

The rewritten server must emit the same format so M1's packet diff has
something to compare against, so this lives in the package rather than in
tools/.

Line layout (note `PACKET` is the *tag* column, not a level):

    2026-09-26 22:16:32.032 +08:00 DEBUG PACKET     conn=1 C->S ... hex=...
    └──────── group 1 ────────┘ └2┘ └── 3 ──┘ └── 4 ──┘ └── group 5 ──────┘

Both `hex=` and `plain=` truncate long dumps as `<hex>...(+NNB)`.  Stripping
only the `(+NNB)` leaves the `...` behind and `bytes.fromhex` raises, so the
ellipsis must be consumed together with the count.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) ([+-]\d\d:\d\d) (\w+)\s+(\S+)\s+(.*)$")

# Opcodes only ever appear as `conn=N (main,sub)`; a bare \((\d+),(\d+)\)
# also matches coordinates -- COMBAT-DIE-39 has cell=(1,0) boss=(3,0) and
# TOWN-AREA-36 has (town, area).  Always anchor on `conn=`.
OPCODE = re.compile(r"conn=\d+\s+\((\d+),(\d+)\)")

_SEEN_LIST = re.compile(r"seen=\[([^\]]*)\]")
_SEEN_OP = re.compile(r"\((\d+),\s*(\d+)\)")
_RESP_OP = re.compile(r"->\s*\((\d+),(\d+)\)")

_MAIN, _SUB = 1, 2

PKT = re.compile(r"conn=(\d+)\s+(C->S|S->C)\s+(game|channel)\b(.*)$")
PKT_OP = re.compile(r"\((\d+),(\d+)\)")
PKT_WIRE = re.compile(r"\b(?:wire|raw)=(\d+)")
PKT_BODY = re.compile(r"\bbody=(\d+)")
PKT_STATE = re.compile(r"\bstate=(\S+)")

_HEXEX = re.compile(r"^([0-9a-fA-F]+)$")
_TRUNC = re.compile(r"^([0-9a-fA-F]*)\.\.\.\(\+(\d+)B\)$")
_LENGTH = re.compile(r"^(\d+)B$")


@dataclass(frozen=True, slots=True)
class LogLine:
    line_no: int
    ts: str
    tz: str
    level: str
    tag: str
    msg: str


def stream(path: str | Path) -> Iterator[LogLine]:
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for n, raw in enumerate(f, 1):
            m = LINE.match(raw.rstrip("\r\n"))
            if m:
                yield LogLine(n, m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))


@dataclass(frozen=True, slots=True)
class HexField:
    """A `key=<hex>` dump.  Three shapes occur in the logs:

    ``130000004368696e61``      full dump
    ``13000000...(+304B)``      truncated, N bytes elided
    ``1384B``                   a byte *count*, not a dump (only for `plain=`)
    """
    data: bytes
    declared: int | None
    truncated: bool
    is_length: bool

    @property
    def full_size(self) -> int:
        return len(self.data) + (self.declared or 0) if self.truncated else len(self.data)


def parse_hex_field(text: str) -> HexField:
    m = _LENGTH.match(text)
    if m:
        return HexField(b"", int(m.group(1)), False, True)
    m = _TRUNC.match(text)
    if m:
        body = m.group(1)
        if len(body) % 2:
            body = body[:-1]          # a nibble survived the 4096-byte cut
        return HexField(bytes.fromhex(body), int(m.group(2)), True, False)
    m = _HEXEX.match(text)
    if m:
        return HexField(bytes.fromhex(text), None, False, False)
    raise ValueError(f"unrecognised hex field: {text[:40]!r}")


_TRAILING = ",;)]"


def find_hex_field(msg: str, key: str) -> HexField | None:
    m = re.search(rf"(?<![\w=]){key}=([^\s]+)", msg)
    if not m:
        return None
    token = m.group(1)
    # The dump is followed by whatever punctuates the sentence around it, and
    # `[^\s]+` swallows it: `(plain=412B)`, `plain=511B;`, `plain=<hex>,`.  So
    # a token that does not parse is retried with up to three separators off
    # the end.  A token that *does* parse is never touched -- which is what
    # keeps `...(+304B)` whole, since it parses on the first try.
    for end in range(len(token), max(len(token) - len(_TRAILING) - 1, 0), -1):
        try:
            return parse_hex_field(token[:end])
        except ValueError:
            pass
    raise ValueError(f"unrecognised hex field: {token[:40]!r}")


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """One `DEBUG PACKET` line -- a whole frame as it went over the wire."""
    line_no: int
    ts: str
    conn: int
    direction: str                 # "C->S" | "S->C"
    link: str                      # "game" | "channel"
    opcode: tuple[int, int] | None # only logged for C->S; S->C needs a header decode
    wire: int | None               # wire=/raw= -- the true frame size
    body_len: int | None
    state: str | None
    hex: HexField | None

    @property
    def truncated(self) -> bool:
        return bool(self.hex and self.hex.truncated)

    @property
    def frame_bytes(self) -> bytes:
        if self.hex is None:
            raise ValueError(f"line {self.line_no}: no hex dump")
        return self.hex.data


def iter_packets(path: str | Path) -> Iterator[PacketRecord]:
    for ln in stream(path):
        if ln.tag != "PACKET":
            continue
        m = PKT.search(ln.msg)
        if not m:
            continue
        conn, direction, link, rest = m.group(1), m.group(2), m.group(3), m.group(4)
        op = PKT_OP.search(rest)
        wire = PKT_WIRE.search(rest)
        body = PKT_BODY.search(rest)
        state = PKT_STATE.search(rest)
        yield PacketRecord(
            line_no=ln.line_no,
            ts=ln.ts,
            conn=int(conn),
            direction=direction,
            link=link,
            opcode=(int(op.group(1)), int(op.group(2))) if op else None,
            wire=int(wire.group(1)) if wire else None,
            body_len=int(body.group(1)) if body else None,
            state=state.group(1) if state else None,
            hex=find_hex_field(ln.msg, "hex"),
        )


_CONNECT = re.compile(r"conn=(\d+) (game|channel):(\d+)")
_DISCONNECT = re.compile(r"conn=(\d+) after ")


@dataclass(frozen=True, slots=True)
class Session:
    """One connection's lifetime within a log file.

    A log holds many sessions and `conn=` restarts from 1 every time the
    server restarts, so `conn=` alone silently concatenates distinct sessions
    -- `server-20260926.log` holds six game sessions and the last one is
    `conn=2` again.  Scope by line range, never by `conn=` alone.
    """
    conn: int
    kind: str                      # "game" | "channel"
    port: int
    first: int                     # line numbers, inclusive
    last: int
    hex_dumps: int

    @property
    def is_corpus(self) -> bool:
        """Whether this session was logged with `packetHexLog` on."""
        return self.hex_dumps > 0

    def __str__(self) -> str:
        return f"{self.kind}:{self.port} conn={self.conn} lines {self.first}..{self.last}"


def sessions(path: str | Path) -> list[Session]:
    """Every connection in the file, in the order they opened."""
    out: list[Session] = []
    cur: dict | None = None
    for ln in stream(path):
        if ln.tag == "CONNECT" and (m := _CONNECT.search(ln.msg)):
            cur = {"conn": int(m.group(1)), "kind": m.group(2), "port": int(m.group(3)),
                   "first": ln.line_no, "last": ln.line_no, "hex_dumps": 0}
            out.append(cur)
        elif cur is not None:
            if ln.tag == "PACKET" and "hex=" in ln.msg:
                cur["hex_dumps"] += 1
            cur["last"] = ln.line_no
            if ln.tag == "DISCONNECT" and _DISCONNECT.search(ln.msg):
                cur = None
    return [Session(**s) for s in out]


def corpus_session(path: str | Path, kind: str = "game") -> Session:
    """The last session of `kind` that has hex dumps -- the usable corpus."""
    found = [s for s in sessions(path) if s.kind == kind and s.is_corpus]
    if not found:
        raise LookupError(f"{path}: no {kind} session was logged with packetHexLog on")
    return found[-1]


def seen_opcodes(msg: str) -> list[tuple[int, int]]:
    """`seen=[(1,1), (1,2), ...]` -- the full opcode set a session received."""
    m = _SEEN_LIST.search(msg)
    if not m:
        return []
    return [(int(a), int(b)) for a, b in _SEEN_OP.findall(m.group(1))]


def response_opcodes(msg: str) -> list[tuple[int, int]]:
    return [(int(a), int(b)) for a, b in _RESP_OP.findall(msg)]


def tag_suffix_opcode(tag: str) -> tuple[int, int] | None:
    """`DUNGEON-ENTER-16` -> (1, 16).

    A *candidate* only: 550 lines corroborate the rule, but it must still be
    confirmed by an explicit opcode somewhere before it enters the registry.
    """
    m = re.search(r"-(\d+)$", tag)
    return (1, int(m.group(1))) if m else None
