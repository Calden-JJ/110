"""`(0,173)` CLIENT-SETTINGS -- the account's 492-byte client-options blob.

The blob is the save's `account_client_settings.options`, keyed by
`account_id` (a single row; the column's own `CHECK(length(options)=492)`).

**The push.**  It is the first of the four frames the `(1,4)` character
selection answers with -- `(0,173)` 504B, then `(1,4)` 1296B, `(0,1370)`
16B and `(0,2082)` 28B -- and its body is `u32le(492)` + the row + 8 zero
bytes.  One dump exists (09-26 22:16:34.470, conn=2, the packetHexLog
session) and it equals the save's row byte for byte, so the frame is a pure
function of the row.  Its line is `CLIENT-SETTINGS conn={conn} S0/173 504B
recommendedGuideShown={N}`; 40 of them, 09-19 21:21:29 through 09-27 13:23
(36 of those in the corpus logs).

**The save.**  `(1,197)` comes back from the client as the written blob and
the reference stores it, logging `CLIENT-SETTINGS conn={conn} saved C1/197
492B recommendedGuideShown={N}` with no reply and no DISPATCH line (264
lines, all 492B, 09-19 21:25:29 through 09-26 20:13:05).  What the *request body* looks like has never
been observed -- every `(1,197)` in the corpus predates a packet-dump window
-- so `parse_save` accepts the reading the line supports, the 492-byte blob
itself, and the handler dumps the plaintext and refuses to write anything
else.  The sibling `(1,439)` write shows the same client padding its body
four bytes past the stored blob (`stored 1028B (body 1032B incl. padding)`,
see `game.town.charsettings`); whether `(1,197)` does too is what
`tools/probe_clientsettings.py`'s report answers from a live dump.

**`recommendedGuideShown`.**  The value the reference prints from the blob:
32767 at the first-ever push (09-19 21:21:29), then 0 at the first save
(21:25:29) and the 21:36:04 push, then 1 from 21:36:14 on -- 301 of the 304
lines.  Which u16 slot holds it is *not* pinned -- all three values are
widespread in the blob (95 zeros, 49 ones, 40 sentinels), every artifact
that carries the blob is from after the last
write that changed it, and no dumper of the blob (a `(1,197)` body, another
save line with a different N) exists.  `GUIDE_SHOWN_AT` is None until
`tools/probe_clientsettings.py` pins it in one client login; see it for the
recipe.
"""
from __future__ import annotations

import sqlite3
import struct

from ...protocol import frame

PUSH_OPCODE = frame.Opcode(0, 173, frame.OpcodeEncoding.U8_U16LE, True)
SAVE_OPCODE = frame.Opcode(1, 197, frame.OpcodeEncoding.U8_U16LE, True)
#: The save's ack: `(0,343)` 8B, one capture (09-27 22:55:43, to the only
#: `(1,197)` whose body was ever dumped).
SAVE_REPLY_OPCODE = frame.Opcode(0, 343, frame.OpcodeEncoding.U8_U16LE, True)
SAVE_REPLY_BODY = bytes.fromhex("0200020000000000")

#: Where the push sits in the `(1,4)` run, 0-based: the run's first frame.
SELECTION_AT = 0

#: The row's size, and what the wire adds to it: a `u32le(ROW_SIZE)` head
#: and 8 zero bytes on the push.
ROW_SIZE = 492
PUSH_TRAILER = bytes(8)

#: The u16 slot in the blob the reference's lines print as
#: `recommendedGuideShown`.  None = not yet pinned; see the module docstring.
GUIDE_SHOWN_AT: int | None = None

#: What the lines print while `GUIDE_SHOWN_AT` is None: the value 301 of the
#: 304 lines carry.  A stand-in, not a derivation -- a fresh account's first
#: push reads 32767 there.
GUIDE_SHOWN_WHEN_UNPINNED = 1


def load(conn: sqlite3.Connection, account_id: int) -> bytes | None:
    """The account's row, or None when there is none to push."""
    row = conn.execute("select options from account_client_settings "
                       "where account_id = ?", (account_id,)).fetchone()
    return None if row is None else row[0]


def push_body(options: bytes) -> bytes:
    """The 504B `(0,173)` body: `u32le(492)`, the row, 8 zero bytes."""
    return struct.pack("<I", ROW_SIZE) + options + PUSH_TRAILER


def parse_save(plain: bytes) -> bytes | None:
    """The blob out of a `(1,197)` request, or None when it is not one.

    The request is `u32le(ROW_SIZE)` + the row -- 496B on the wire, the head
    the client echoes back from the 504B push.  The bare 492B reading is what
    the reference's own `saved C1/197 492B` line supports and it is what the
    pre-dump code assumed, but the one dumped body (09-27) carries the head,
    and the reference stored the 492B behind it.
    """
    if len(plain) == ROW_SIZE + 4 and struct.unpack_from("<I", plain)[0] == ROW_SIZE:
        return plain[4:]
    return plain if len(plain) == ROW_SIZE else None


def save(conn: sqlite3.Connection, account_id: int, options: bytes) -> None:
    conn.execute("insert into account_client_settings (account_id, options) "
                 "values (?, ?) on conflict(account_id) do update set "
                 "options = excluded.options", (account_id, options))
    conn.commit()


def recommended_guide_shown(options: bytes) -> int:
    if GUIDE_SHOWN_AT is None:
        return GUIDE_SHOWN_WHEN_UNPINNED
    return struct.unpack_from("<H", options, GUIDE_SHOWN_AT)[0]


def push_line(options: bytes, size: int) -> str:
    """The `CLIENT-SETTINGS` prose after the bare `conn=N `, push form."""
    return (f"S0/173 {size}B "
            f"recommendedGuideShown={recommended_guide_shown(options)}")


def save_line(options: bytes) -> str:
    """The `CLIENT-SETTINGS` prose after the bare `conn=N `, save form."""
    return (f"saved C1/197 {len(options)}B "
            f"recommendedGuideShown={recommended_guide_shown(options)}")
