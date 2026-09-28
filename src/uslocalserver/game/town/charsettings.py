"""`(0,376)` TOWN-QUICKSLOT -- the 1028-byte "character options" blob.

Measured 2026-09-27 off the reference's own logs; the blob is the save's
`character_quickslots.payload`, keyed by `character_id`.

**The push.**  Town entry carries one `(0,376)` frame -- index 15 of the
33-frame `(1,143)` burst, between `(0,53)` cera and `(0,440)` hotkeys -- and
its body is the row's `payload` followed by 12 zero bytes, 1040 in all.  Five
dumped frames agree byte for byte (09-26 22:16:37, 09-27 12:51:18.781 /
13:01:17.303 / 13:05:30.922 / 13:23:41.001, `conn=2`) and all five equal the
save's row, so the frame is a pure function of the payload.  The reference's
`TOWN-QUICKSLOT` line calls it "restoring 1028B of character options".

**The blob.**  Self-describing: `u32le(1024)` then the 1024 bytes it counts,
1028 in all -- the first four bytes are the blob's own `len - 4`.  Unused
slots read `0xFFFF` (both real payloads are 0xFFFF everywhere outside their
live fields), and the quickbar's first five entries sit in the first ten
bytes after the count.  `awakeningLinks` in the write's log line is the two
i16le at byte offsets 212/214: XRenYing's row carries 291,-1 and its lines
say `291,-1`; LRouDao's carries -1,-1 and its lines say `-1,-1`.

**The write, not implemented here.**  `(1,439)` CHARACTER-SETTINGS-439 comes
back from the client as 1032B and the reference stores 1028 of them -- its
line reads `stored 1028B (body 1032B incl. padding)` and notes the client
has no receive handler, so no reply is sent and no DISPATCH is logged.  Every
`(1,439)` in the corpus predates the packet-dump windows, so *which* 1028
bytes the body carries has never been observed; the account-settings sibling
`(1,197)` writes its 492B blob unpadded, which points at four trailing pad
bytes, but the padding is not measured.  Sending a probe is the next step;
until then this module builds the push only.
"""
from __future__ import annotations

import sqlite3
import struct

from ...protocol import frame

PUSH_OPCODE = frame.Opcode(0, 376, frame.OpcodeEncoding.U8_U16LE, True)
SAVE_OPCODE = frame.Opcode(1, 439, frame.OpcodeEncoding.U8_U16LE, True)

#: Where the push sits in the `(1,143)` burst, 0-based: the 16th of 33.
ENTRY_AT = 15

#: The row's size, and the sizes the wire adds to it: 12 zero bytes on the
#: push, and (measured from a log line only) 4 more than the row on the write.
PAYLOAD_SIZE = 1028
PUSH_TRAILER = bytes(12)
SAVE_BODY_SIZE = 1032

AWAKENING_LINKS_AT = 212
DEFAULT_FILL = b"\xff"


def load(conn: sqlite3.Connection, character_id: int) -> bytes | None:
    """The selected character's row, or None when there is none to restore."""
    row = conn.execute("select payload from character_quickslots "
                       "where character_id = ?", (character_id,)).fetchone()
    return None if row is None else row[0]


def default_payload() -> bytes:
    """What to push when the row is missing.

    A synthesis, not a measurement: no corpus session ever entered town
    without a row (all 39 `TOWN-QUICKSLOT` lines say "restoring").  It keeps
    the blob's own shape -- `u32le(1024)` + 1024 bytes -- and fills the body
    with the `0xFFFF` that every unused slot in both real payloads carries.
    """
    return struct.pack("<I", PAYLOAD_SIZE - 4) + DEFAULT_FILL * (PAYLOAD_SIZE - 4)


def push_body(payload: bytes) -> bytes:
    """The 1040B `(0,376)` body: the row, then 12 zero bytes."""
    return payload + PUSH_TRAILER


def awakening_links(payload: bytes) -> tuple[int, int]:
    """The two links the write's log line prints, signed."""
    return struct.unpack_from("<hh", payload, AWAKENING_LINKS_AT)
