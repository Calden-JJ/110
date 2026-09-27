"""The rewritten server's log, in the reference server's format.

`tools/diff_packets.py` compares a rewrite session against a captured one, so
the shape of these lines is a contract: `uslocalserver.logs` parses them, and
the S->C opcode is not written down anywhere -- it is decoded back out of the
dumped frame header.  That is deliberate: a rewrite that gets a length field
or a trailer wrong then shows up as a `bad` frame in the diff rather than as
silence.

Layout:

    2026-09-26 22:16:32.032 +08:00 DEBUG PACKET     conn=1 C->S ... hex=...
    └──────── group 1 ────────┘ └2┘ └── 3 ──┘ └── 4 ──┘ └── group 5 ──────┘

Levels are padded to 5 and tags to 11 in the capture; keep it, the logs are
meant to be diffed against each other by eye as well as by script.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import TextIO

from ..protocol import frame

HEX_DUMP_LIMIT = 4096


def _dumps(data: bytes) -> str:
    """`hex=<...>`, truncated the way the reference logger truncates it."""
    if len(data) <= HEX_DUMP_LIMIT:
        return f"hex={data.hex()}"
    return f"hex={data[:HEX_DUMP_LIMIT].hex()}...(+{len(data) - HEX_DUMP_LIMIT}B)"


class Log:
    def __init__(self, path: str | Path | None = None, *, level: str = "DEBUG",
                 stream: TextIO | None = None) -> None:
        self.level = level
        self._fh: TextIO | None = None
        self._owns = False
        if stream is not None:
            self._fh = stream
        elif path is not None:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fh = p.open("w", encoding="utf-8", newline="\n")
            self._owns = True

    def close(self) -> None:
        if self._owns and self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "Log":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @staticmethod
    def _stamp() -> tuple[str, str]:
        now = dt.datetime.now().astimezone()
        z = now.strftime("%z")            # +0800
        return (now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d}",
                f"{z[:3]}:{z[3:]}")

    def line(self, level: str, tag: str, msg: str) -> None:
        if self._fh is None:
            return
        ts, tz = self._stamp()
        # Column widths measured off the capture: the message starts at byte 48
        # for any tag up to 11 chars, one further out for each char beyond.
        # That is a 10-wide tag plus a separator -- a 11-wide field would push
        # every line one column right, and a longer tag must not be truncated.
        self._fh.write(f"{ts} {tz} {level:<5} {tag:<10} {msg}\n")
        self._fh.flush()

    def info(self, tag: str, msg: str) -> None:
        self.line("INFO", tag, msg)

    def debug(self, tag: str, msg: str) -> None:
        if self.level == "DEBUG":
            self.line("DEBUG", tag, msg)

    def warn(self, tag: str, msg: str) -> None:
        self.line("WARN", tag, msg)

    # ------------------------------------------------------------- packets

    def packet(self, conn: int, link: frame.Link, wire: bytes, *,
               from_client: bool, state: str | None = None,
               extra: str = "") -> None:
        """One `DEBUG PACKET` line for a frame that actually went over a socket.

        `wire` is the whole frame, header included.  The opcode is written out
        for C->S only, exactly as the reference does.
        """
        if self._fh is None:
            return
        direction = "C->S" if from_client else "S->C"
        kind = "channel" if link.namespace == "channel" else "game"
        body_len = len(wire) - frame.header_len(link)
        if from_client:
            op = frame.Opcode.from_channel(wire) if link.namespace == "channel" else frame.Opcode.from_game(wire)
            # `str(op)` would print `(?0,11)` -- channel's main is not a semantic
            # field.  The reference log writes the raw pair either way, and the
            # log parser reads it back with `\((\d+),(\d+)\)`.
            head = (f"conn={conn} {direction} {kind} ({op.main},{op.sub}) "
                    f"wire={len(wire)} body={body_len}")
            if state:
                head += f" state={state}"
        else:
            head = f"conn={conn} {direction} {kind} raw={len(wire)} sent"
        if extra:
            head += f" {extra}"
        self.debug("PACKET", f"{head} {_dumps(wire)}")
