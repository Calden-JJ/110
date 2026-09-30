"""`(1,143)`'s opening act: the tutorial flag the client reports, and its row.

Every `(1,143)` request the corpus holds -- ten of them, 09-26 through 09-29 --
decrypts to the same 16B shape: a big-endian `u16` whose low byte is the flag
and whose high byte is a `prefix`, then a big-endian `u32` `reward` (1 in every
sample), then ten zero bytes.  The byte order is the `reward` field's doing:
read little-endian it would be 16777216, and the reference prints 1.

**The line.**  The handler reads the request before it decides what the request
*is*: from `CharacterSelected` the same packet draws the town-entry burst,
from `InTown` a duplicate that draws the one-frame ack -- and either way the
flag line is the run's first, built from the literals at `0x46a198`-`0x46a4a1`::

    INFO TUTORIAL-FLAGS conn=N key=K client reported flag={F} (raw={R}
    prefix={P} reward={W}) stored|already stored

`flag` is the low byte, `raw` the whole `u16`, `prefix` its high byte, and the
two verdicts are `stored` / `already stored` picked by the insert's own result.
The corpus carries flags 30, 31, 36 and 38, and `character_tutorial_flags`
holds exactly those rows per character.  `flag_index` is the low byte; the two
readings cannot be told apart where the row is written, since `raw <= 101`
forces `prefix == 0` and then `flag == raw`.

**The row.**  `already stored` neither writes nor re-dates: character 1's flag
36 is dated 09-19 21:36:04 through every later re-report (09-26 09:58, 12:00,
19:58).  So the write is an insert that leaves an existing row alone.

**The out-of-range branch.**  `raw` is checked against `0..101` before the
line: outside it the reference builds `flag {raw} is outside 0..101; not
stored` and logs it under `TUTORIAL-FLAG-143` (`0x46a52f`-`0x46a679`), then
falls into the same tail -- the flow line and the reply still follow.  No such
send is in the corpus; the bound is the table's own `CHECK(flag_index BETWEEN
0 AND 101)`.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from ...protocol import frame

OPCODE = frame.Opcode(1, 143, frame.OpcodeEncoding.U8_U16LE, True)
#: The report's tag, and the one the out-of-range branch logs under.
TAG = "TUTORIAL-FLAGS"
OUT_OF_RANGE_TAG = "TUTORIAL-FLAG-143"

#: The fields' offsets in the plaintext, and how much of it they need.
RAW_AT = 0
REWARD_AT = 2
SIZE = REWARD_AT + 4

#: The bound the write checks, `character_tutorial_flags`' own.
MAX_FLAG = 101

STORED = "stored"
ALREADY_STORED = "already stored"


@dataclass(frozen=True, slots=True)
class Report:
    """The request's `u16` and `u32`, as the reference reads them."""

    raw: int
    reward: int

    @property
    def flag(self) -> int:
        """The low byte -- the `flag_index` a row is written under."""
        return self.raw & 0xFF

    @property
    def prefix(self) -> int:
        """The high byte, its own field in every printed line."""
        return self.raw >> 8


def parse(plain: bytes) -> Report | None:
    """The request's fields, or None for a body too short to carry them.

    No `(1,143)` shorter than 16B has been seen; the guard is the wire's, not
    the reference's -- a short body would leave the replayed line in place.
    """
    if len(plain) < SIZE:
        return None
    return Report(raw=int.from_bytes(plain[RAW_AT:RAW_AT + 2], "big"),
                  reward=int.from_bytes(plain[REWARD_AT:REWARD_AT + 4], "big"))


def record(conn: sqlite3.Connection, character_id: int, key: int, report: Report,
           now: int | None = None) -> tuple[str, str]:
    """Store the flag and return the `(tag, prose)` the reference logs.

    In range this is the report line with the insert's own verdict; out of
    range it is the `TUTORIAL-FLAG-143` refusal, and nothing is written.
    """
    if not 0 <= report.raw <= MAX_FLAG:
        return OUT_OF_RANGE_TAG, out_of_range_line(report)
    cursor = conn.execute(
        "insert or ignore into character_tutorial_flags "
        "(character_id, flag_index, updated_at) values (?, ?, ?)",
        (character_id, report.flag, int(time.time()) if now is None else now))
    conn.commit()
    verdict = STORED if cursor.rowcount > 0 else ALREADY_STORED
    return TAG, report_line(key, report, verdict)


def report_line(key: int, report: Report, verdict: str) -> str:
    """The `TUTORIAL-FLAGS` prose after the bare `conn=N `."""
    return (f"key={key} client reported flag={report.flag} (raw={report.raw} "
            f"prefix={report.prefix} reward={report.reward}) {verdict}")


def out_of_range_line(report: Report) -> str:
    """The refusal the out-of-range branch builds, after the bare `conn=N `."""
    return f"flag {report.raw} is outside 0..{MAX_FLAG}; not stored"
