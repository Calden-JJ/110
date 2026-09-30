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

**The save.**  `(1,197)` comes back from the client as `u32le(492)` + the
written blob (496B; the dump below shows the head, and the reference's own
parser rejects a body whose head is not 492 with `Invalid settings length
prefix`).  The reference validates it, stores it, and logs
`CLIENT-SETTINGS conn={conn} saved C1/197 492B recommendedGuideShown={N}`
(264 lines, all 492B, 09-19 21:25:29 through 09-26 20:13:05).

**Then the CLASS-AVATAR step.**  After that line the handler answers
`(0,343)` -- the body is `u16le(key) + u8(flags)` padded to 8, not a
constant: the 09-27 capture (`02 00 02 ...`, key 2) and every 09-28 reply
(`03 00 02 ...`, key 3) differ only in the key byte pair.  It logs
`CLASS-AVATAR conn={conn} key={K} preference={P} flags={F}; N343` first
(225 lines, 09-19 through 09-28, all `preference=1 flags=2`).  `key` is the
character's own number (the same one the other lines print), `preference`
is read from the *blob the client just sent* -- `blob[2:4]` mapped through
`0x597b10`, which reads the `0x7fff` sentinel as 4 and anything above 4 as 0
-- and `flags` is that value clamped by unread avatar-profile numbers and
looked up in the table at `0x597b79`.

**The step is gated on a dungeon run.**  The gates after the saved line
(`0x3d21f9`, three of the fields `(1,309)` checks) silence both the
CLASS-AVATAR line and the reply: the 09-28 session's sixth `(1,197)`
(21:13:22.742, inside the dungeon-6 run its own `DUNGEON-SELECT-15` line
calls "an existing dungeon run") stored the blob and logged the
CLIENT-SETTINGS line, then answered nothing.  The store and its line are
outside the gates; the table is inside.  `server.game`'s handler reads the
gate as a live `DungeonSession.run`.

**`recommendedGuideShown`.**  The value the reference prints from the blob:
32767 at the first-ever push (09-19 21:21:29), then 0 at the first save
(21:25:29) and the 21:36:04 push, then 1 from 21:36:14 on -- 301 of the 304
lines.  The slot is `[396:398]`, read sign-extended by both line builders
(`0x4458e0` on the push's `S0/173` path, `0x3d21d0` on the save's), and the
one dumped blob holds 1 there.  It is *not* the `0x7fff`-sentinel slot the
CLASS-AVATAR `preference` reads (`[2:4]`); the two are different fields
that happen to hold 1 in every artifact.
"""
from __future__ import annotations

import sqlite3
import struct

from ...protocol import frame

PUSH_OPCODE = frame.Opcode(0, 173, frame.OpcodeEncoding.U8_U16LE, True)
SAVE_OPCODE = frame.Opcode(1, 197, frame.OpcodeEncoding.U8_U16LE, True)
#: The save's ack: `(0,343)` 8B.  One capture (09-27 22:55:43, to the only
#: `(1,197)` whose body was ever dumped) plus the 09-28 session's five.
SAVE_REPLY_OPCODE = frame.Opcode(0, 343, frame.OpcodeEncoding.U8_U16LE, True)
AVATAR_TAG = "CLASS-AVATAR"

#: Where the push sits in the `(1,4)` run, 0-based: the run's first frame.
SELECTION_AT = 0

#: The row's size, and what the wire adds to it: a `u32le(ROW_SIZE)` head
#: and 8 zero bytes on the push.
ROW_SIZE = 492
PUSH_TRAILER = bytes(8)

#: The u16 slot both line builders read for `recommendedGuideShown`, signed.
GUIDE_SHOWN_AT = 396

#: The u16 slot `preference` reads, with the own sentinel and its mapped
#: value -- `0x597b10` reads `[2:4]`, maps `0x7fff` to 4 (the blob's "unset"
#: marker), passes 0..4 through and everything else to 0.
PREFERENCE_AT = 2
PREFERENCE_UNSET = 0x7FFF
PREFERENCE_UNSET_VALUE = 4

#: The `flags` table at `0x597b79`, indexed by `min(preference, cap) - 1`.
FLAGS_BY_PREFERENCE = (2, 0x10, 0x20)

#: The clamp the table index passes through.  The cap is a pair of numbers on
#: the avatar-profile row the handler looks up (`X+0x54`/`X+0x58` in the
#: disassembly), which this rewrite does not read.  Every corpus line carries
#: preference 1, where any cap >= 1 answers 2; 2 is the value the dead
#: `r8d == 2` branch names.
AVATAR_PROFILE_CAP = 2


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
    return struct.unpack_from("<h", options, GUIDE_SHOWN_AT)[0]


def preference(options: bytes) -> int:
    """The CLASS-AVATAR `preference`: `[2:4]`, sentinel-mapped, 0 off-size."""
    if len(options) != ROW_SIZE:
        return 0
    value = struct.unpack_from("<H", options, PREFERENCE_AT)[0]
    if value == PREFERENCE_UNSET:
        return PREFERENCE_UNSET_VALUE
    return value if value <= PREFERENCE_UNSET_VALUE else 0


def flags(preference: int) -> int:
    """The CLASS-AVATAR `flags`: the table at the clamped preference."""
    index = min(preference, AVATAR_PROFILE_CAP) - 1
    return FLAGS_BY_PREFERENCE[index] if 0 <= index < len(FLAGS_BY_PREFERENCE) else 0


def avatar_line(key: int, preference: int, flags: int) -> str:
    """The `CLASS-AVATAR` prose after the bare `conn=N `, `; N343` included."""
    return f"key={key} preference={preference} flags={flags}; N343"


def avatar_reply_body(key: int, flags: int) -> bytes:
    """The 8B `(0,343)` body: `u16le(key)`, the flags byte, zero padding."""
    return (struct.pack("<H", key) + bytes([flags])).ljust(8, b"\x00")


def push_line(options: bytes, size: int) -> str:
    """The `CLIENT-SETTINGS` prose after the bare `conn=N `, push form."""
    return (f"S0/173 {size}B "
            f"recommendedGuideShown={recommended_guide_shown(options)}")


def save_line(options: bytes) -> str:
    """The `CLIENT-SETTINGS` prose after the bare `conn=N `, save form."""
    return (f"saved C1/197 {len(options)}B "
            f"recommendedGuideShown={recommended_guide_shown(options)}")
