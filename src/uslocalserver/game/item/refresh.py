"""The frames a cross-container `(1,19)` move draws -- M2.2 and M2.3.

Measured 2026-09-27 by replaying the oracle run's own cross-container round
(`Logs-m2oracle/server-20260927.log`, conn=2) frame by frame, and pinned to
101 probe bins.  An *accepted* cross move answers with eight frames, in this
order::

    (1,19)  ack          the same 16B ack a same-container move gets
    (0,14)  168B         the source address, post-move
    (0,14)  168B         the destination address, post-move
    (0,2)   header+records+tail   the small USERINFO -- subtype 0, 1280/1312B
    (0,2)   4.5-4.7KB             the *second* USERINFO -- the giant, `giant.py`
    (0,2265) 16B         the same version u16 the (0,2) header carries
    (0,2432) 208B        captured constant
    (0,1361) 96B         captured constant

The two USERINFO frames are what the reference's outcome line means by "both
USERINFO frames": the small one built here and the giant subtype-1 built in
`giant.py`.  They share a version u16 -- `[134:136)` and `[24:26)` -- and go
out back to back, so `build()` computes it once from the small frame's record
stream and hands it to both.

Two things about the direction, both read off the ack-then-frames order rather
than assumed.  The request's `src`/`dst` do *not* name a direction: as in the
same-container case it is the filled end that gives and the empty end that
receives, so `src=(0,6) dst=(3,19)` with slot 19 occupied unequips *out* of
slot 19 into inventory slot 6.  And the two `(0,14)` frames carry the state
*after* the move -- slot 19 reads `FF FF FF FF` on its way out, and the pair
sends the moved slot exactly as the DB now has it.

A rejected cross move answers with its ack alone: the sealed-slot branch
(`dst=(3,35)` in the capture) sends no refresh frames at all, and the reference
logs nothing for it.  So does a move that only swaps within one list.

The record layouts and the four things this module cannot yet derive are
written up in `references/protocol.md`.
"""
from __future__ import annotations

import binascii
import sqlite3
import struct
from dataclasses import dataclass

from ...persistence import items
from ...persistence.characters import CharacterSummary
from ...protocol import frame
from . import giant
from .inventory import MoveRequest

EQUIPMENT_LIST = 3
SLOT_BODY_SIZE = 168
EMPTY_ITEM_ID = 0xFFFFFFFF

USERINFO_HEADER_SIZE = 216
RECORD_SIZE = 31
RECORD_FLAG = 0x1B
VERSION_AT = 134
NAME_LENGTH_AT = 198
NAME_AT = 202
CLASS_AT = 210
GROW_AT = 211
LEVEL_AT = 212
COUNT_AT = 215
#: `[93:97]` carries the item in this slot; it is also the first creature's
#: item id in the save, and the two readings agree in every capture.
PET_SLOT = 32
#: Above the version the header is fixed: `00 01 00 01 0a 00 00 00`.
HEADER_PREFIX = bytes.fromhex("000100010a000000")

OPCODE_SLOT = frame.Opcode(0, 14, frame.OpcodeEncoding.U8_U16LE, True)
OPCODE_USERINFO = frame.Opcode(0, 2, frame.OpcodeEncoding.U8_U16LE, True)
OPCODE_VERSION = frame.Opcode(0, 2265, frame.OpcodeEncoding.U8_U16LE, True)
OPCODE_STATE = frame.Opcode(0, 2432, frame.OpcodeEncoding.U8_U16LE, True)
OPCODE_BOARD = frame.Opcode(0, 1361, frame.OpcodeEncoding.U8_U16LE, True)

#: The `(0,2)` tail, byte-identical across every captured state (all 31 worn,
#: 30 without slot 19's item, 30 without slot 13's).  `[22:26]` is equipment
#: slot 26's item (== the third creature's item id); `[30]`, `[73]` and `[85]`
#: are unexplained one-byte values -- see protocol.md.
TAIL = bytes.fromhex(
    "000000000000000000000000000000000000000000003f83dc1d000000000100"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000100000000000000000000000200000000000000000000"
    "00000000000000000000000000000000000000000000")

#: `(0,2432)`: `65` then zeros, 208B.  One unique payload over every send --
#: town entry and each accepted cross move alike.
STATE_BODY = b"\x65" + bytes(207)

#: `(0,1361)`: 96B, one unique payload over every send.
BOARD_BODY = bytes.fromhex(
    "1901100103013e000104013f00010c003d00010d002800010e003800010f0037"
    "000110003500011100300001120036000113002f000114002e000115002d0001"
    "16003f0001170040000119003e00011a07010000000000000000000000000000")

#: The outcome line's continuation, for the log -- the reference's wording.
NOTE_SUFFIX = "re-sent both USERINFO frames with {worn} worn item(s)"


def equipment(conn: sqlite3.Connection, character_id: int) -> list[items.ItemStack]:
    """The character's worn rows, in slot order -- the `(0,2)` record order."""
    rows = conn.execute(
        f'select {", ".join(items.COLUMNS)} from character_items '
        "where character_id = ? and list_type = ? order by slot_index",
        (character_id, EQUIPMENT_LIST)).fetchall()
    return [items.ItemStack.from_row(r) for r in rows]


def display_id(stack: items.ItemStack) -> int:
    """What the client shows: the clone appearance when there is one."""
    return stack.clone_appearance_id or stack.item_id


def record(stack: items.ItemStack) -> bytes:
    """One `(0,2)` record: slot, display id, then a flag at `[9]` that the 11
    items with options carry as `0x1b` and the other 20 do not."""
    out = bytearray(RECORD_SIZE)
    out[0] = stack.slot_index
    struct.pack_into("<I", out, 1, display_id(stack))
    if (stack.reinforcement or stack.enchant_card_id or stack.amplify_type
            or stack.amplify_value or stack.growth_experience):
        out[9] = RECORD_FLAG
    return bytes(out)


def version(records: bytes) -> int:
    """The version u16 `(0,2)` and `(0,2265)` both carry -- a stand-in.

    The reference's own value is a pure function of the worn set (0x88dd with
    all 31 items, 0x7eb0 without slot 19's, 0x858c without slot 13's, the same
    across four sessions) that no checksum tried so far reproduces; see
    protocol.md for the battery.  This is a CRC-16 over the record stream, so
    it has the two properties that matter for a state stamp -- one state, one
    value, and a changed state changes it -- and `tools/diff_item_move.py`
    masks the two bytes when it diffs.
    """
    return binascii.crc_hqx(records, 0xFFFF)


def slot_body(stack: items.ItemStack | None, list_type: int,
              slot_index: int) -> bytes:
    """One `(0,14)` frame: the 168B a slot's post-move state goes out as.

    An empty slot keeps the `FF FF FF FF` item id and nothing else.  The
    growth field sits far from the rest (`[143:145]`) with the bytes between
    zero in every capture.
    """
    body = bytearray(SLOT_BODY_SIZE)
    body[0] = list_type
    body[1] = 0x01
    struct.pack_into(">H", body, 2, slot_index)
    if stack is None:
        struct.pack_into("<I", body, 5, EMPTY_ITEM_ID)
        return bytes(body)
    struct.pack_into("<I", body, 5, stack.item_id)
    # A stored 0 goes out as 1: the (3,13) creature item is saved with
    # `instance_value` 0 and both of the reference's frames for it say 1.
    struct.pack_into("<I", body, 9, stack.instance_value or 1)
    struct.pack_into("<I", body, 13, stack.reinforcement)
    struct.pack_into("<I", body, 17, stack.enchant_card_id)
    body[22] = stack.amplify_type
    body[23] = stack.amplify_value
    struct.pack_into("<H", body, 143, stack.growth_experience)
    return bytes(body)


def userinfo_body(summary: CharacterSummary,
                  worn: list[items.ItemStack]) -> bytes:
    """The small `(0,2)` push: 216B header, one 31B record per worn row, the
    118B tail, zero-padded to a 16-byte multiple (1296B with 31 worn, 1264B
    with 30 -- the same numbers the reference sent)."""
    body = bytearray(USERINFO_HEADER_SIZE + RECORD_SIZE * len(worn) + len(TAIL))
    body[0:len(HEADER_PREFIX)] = HEADER_PREFIX
    for stack in worn:
        if stack.slot_index == PET_SLOT:
            struct.pack_into("<I", body, 93, display_id(stack))
    name = summary.name.encode()
    body[196] = 0x01
    body[NAME_LENGTH_AT] = len(name)
    body[NAME_AT:NAME_AT + len(name)] = name
    body[CLASS_AT] = summary.class_id
    body[GROW_AT] = (summary.sub_grow_type << 4) | summary.grow_type
    body[LEVEL_AT] = summary.level
    body[COUNT_AT] = len(worn)
    start = USERINFO_HEADER_SIZE
    for i, stack in enumerate(worn):
        body[start + RECORD_SIZE * i:start + RECORD_SIZE * (i + 1)] = record(stack)
    records = bytes(body[start:start + RECORD_SIZE * len(worn)])
    struct.pack_into("<H", body, VERSION_AT, version(records))
    body[start + RECORD_SIZE * len(worn):] = TAIL
    return bytes(body) + bytes(-len(body) % 16)


@dataclass(frozen=True, slots=True)
class Refresh:
    frames: list[tuple[frame.Opcode, bytes]]
    worn: int


def build(conn: sqlite3.Connection, character_id: int, request: MoveRequest,
          summary: CharacterSummary) -> Refresh:
    """The eight frames that follow the ack, in the reference's order."""
    worn = equipment(conn, character_id)
    body = userinfo_body(summary, worn)
    value = struct.unpack_from("<H", body, VERSION_AT)[0]
    src = items.load(conn, character_id, *request.src.address)
    dst = items.load(conn, character_id, *request.dst.address)
    return Refresh(
        frames=[
            (OPCODE_SLOT, slot_body(src, *request.src.address)),
            (OPCODE_SLOT, slot_body(dst, *request.dst.address)),
            (OPCODE_USERINFO, body),
            # the giant carries the same version the small one does
            (OPCODE_USERINFO, giant.body(summary, worn,
                                         giant.creature_levels(conn, character_id),
                                         giant.runes(conn, character_id), value)),
            (OPCODE_VERSION, b"\x01\x00\x00\x00" + struct.pack("<H", value)
                             + bytes(10)),
            (OPCODE_STATE, STATE_BODY),
            (OPCODE_BOARD, BOARD_BODY),
        ],
        worn=body[COUNT_AT],
    )
