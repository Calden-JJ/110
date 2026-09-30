"""The frames a cross-container `(1,19)` move draws -- M2.2 and M2.3.

Measured 2026-09-27 (`Logs-m2oracle/server-20260927.log`, conn=2, character 1)
by replaying the oracle run's own cross-container round frame by frame, pinned
to 101 probe bins, and bracketed 2026-09-28 (`Logs-dungeon/server-20260928.log`,
conn=4, character 3, level 7) where the same round draws a shorter set.  An
*accepted* cross move answers with the ack and then, in this order::

    (0,14)  168B         the source address, post-move
    (0,14)  168B         the destination address, post-move
    (0,2)   header+records+tail   the small USERINFO -- subtype 0
    (0,2)   4.5-4.7KB             the *second* USERINFO -- the giant, `giant.py`
    (0,2265) 16B         the same version u16 the (0,2) header carries
    (0,2432) 208B        the specificity panel -- points byte then zeros
    (0,1361) 96B         captured constant

Three things vary.  A move whose row is a *weapon* (catalogue `type_index` 10)
answers with the small USERINFO alone -- no giant -- and the reference's own
line says so: "refreshed weapon appearance with all worn rows".  Every other
move re-sends "both USERINFO frames with N worn item(s)".  And the
`(0,2432)`/`(0,1361)` pair only goes to characters at or above
`SPECIFICITY_LEVEL`: character 1 has it on every accepted move and on town
entry, character 3 never once in its session, with the panel's points (101)
unmoved by the worn set either way.

The two USERINFO frames are what "both USERINFO frames" means: the small one
built here and the giant subtype-1 built in `giant.py`.  They share a version
u16 -- `[134:136)` and `[24:26)` -- and go out back to back, so `build()`
computes it once from `fame.compute` and hands it to both.  That u16 is the
character's fame: the 09-27 capture's three observed values, 0x88dd with all
31 worn, 0x7eb0 without slot 19's item and 0x858c without slot 13's, are
exactly `fame.py`'s output for those three states, which is what retired the
CRC stand-in this module used to carry.

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

The record layouts and the things this module cannot yet derive are written up
in `references/protocol.md`.
"""
from __future__ import annotations

import sqlite3
import struct
from collections.abc import Sequence
from dataclasses import dataclass

from ...persistence import items
from ...persistence.characters import CharacterSummary
from ...protocol import frame
from ..data import content
from . import fame, giant
from .inventory import MoveRequest

EQUIPMENT_LIST = 3
EMPTY_ITEM_ID = 0xFFFFFFFF

#: One `(0,14)` body is `u8 list | u8 record count | u8 00`, then that many
#: 165B record blocks, zero-padded to a multiple of 8 -- so the one-record
#: form is 168B, the two-record 336B (both measured on the 09-27 buys) and
#: the slotted bag frame with nine records is 1488B.  One block::
#:
#:     [0:2]     u16 le slot index
#:     [2:6]     u32 le item id (`FF FF FF FF` when the slot is empty)
#:     [6:10]    u32 le instance_value or count
#:     [10]      u8 reinforcement, [11] u8 durability
#:     [14:18]   u32 le enchant card id
#:     [19]      u8 amplify type, [20] u8 amplify value
#:     [140:142] u16 le growth experience
#:
#: The far fields are the ones the M2.2 oracle pinned to worn rows; the
#: durability byte and the multi-record frames come from the 09-27 buys
#: (item 29127's fresh row carried 48, its catalogue's own durability).
BLOCK_SIZE = 165
SLOT_BODY_SIZE = 3 + BLOCK_SIZE

RECORD_SIZE = 31
RECORD_FLAG = 0x1B
VERSION_AT = 134
#: The character's own number, a u16: 1 for XRenYing (id 1, slot 0), 3 for
#: XJianHun (id 3, slot 2).  On this save every character's id is its slot
#: plus one, so the two readings cannot be told apart -- recorded in
#: protocol.md, and `character_id` is what `giant.py` writes for the same
#: number.
CHARACTER_AT = 196
NAME_LENGTH_AT = 198
NAME_AT = 202
#: The six bytes *behind* the name -- class, grow, level, two zeros and the
#: worn count -- and the 31B records start right behind *them*, so both move
#: with the name: an eight-character name puts the block at 210 and the
#: records at 216, LRouDao's seven put them at 209 and 215.  Measured on all
#: three characters' town-entry bursts, where the same body is both 1296B
#: (31 worn, eight characters) and 896B (18 worn, seven) -- see `roster_at`.
ROSTER_SIZE = 6
#: Offsets *within* that block.
CLASS_OFFSET = 0
GROW_OFFSET = 1
LEVEL_OFFSET = 2
COUNT_OFFSET = 5
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

#: The `(0,2)` tail, constant except `[22:26]`/`[30]`, which `tail_body`
#: splices: the item worn at slot 26 (`giant`'s own creature slot, `00 00 00 00`
#: when empty) and the level of the creature it is -- the same byte `giant.tail`
#: ends with.  Char 1's 09-27 captures hold 500990783/1 there (its slot-26 item
#: is creature 3), char 3's 09-28 session four zeros with the slot empty, which
#: is what pinned the pair.  `[73]` and `[86]` are unexplained one-byte values
#: -- see protocol.md.
TAIL_SIZE = 118
TAIL_CREATURE_AT = 22
TAIL_LEVEL_AT = 30
TAIL = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000100000000000000000000000200000000000000000000"
    "00000000000000000000000000000000000000000000")

#: `(0,2432)`: `65` then zeros, 208B.  One unique payload over every send --
#: town entry and each accepted cross move alike.  The leading byte is the
#: points value the reference's EQUIPMENT-SPECIFICITY line logs; the zeros are
#: an empty options list (`options=0` in that same line).
STATE_BODY = b"\x65" + bytes(207)
PANEL_POINTS = STATE_BODY[0]

#: The level at which the `(0,2432)`/`(0,1361)` pair starts going out -- a
#: stand-in for a gate this module cannot yet derive.  Character 1 (level 110)
#: carries the pair on every accepted move and on town entry, character 3
#: (level 7) never does anywhere in its session, and the points byte does not
#: move with the worn set, so the gate is character-level rather than
#: equipment-derived.  What selects it -- level, a quest, a counter the save
#: has no column for -- is undecided; the level reading fits both sessions.
#: Probe recipes in `references/protocol.md`.
SPECIFICITY_LEVEL = 100

#: `(0,1361)` has a second, 16B form: `32` then 15 zeros.  It is the last
#: frame of every *write* run in the 09-27 session -- item use, NPC buy, cargo
#: move, cera buy -- where the 96B `BOARD_BODY` below is what a town entry and
#: an equipment cross-move carry.
BOARD_AFTER_WRITE_BODY = b"\x32" + bytes(15)

#: `(0,1361)`: 96B, one unique payload over every send.
BOARD_BODY = bytes.fromhex(
    "1901100103013e000104013f00010c003d00010d002800010e003800010f0037"
    "000110003500011100300001120036000113002f000114002e000115002d0001"
    "16003f0001170040000119003e00011a07010000000000000000000000000000")

#: The moved row is a weapon -- the catalogue's own category for slot 12's
#: contents.  Only a weapon move skips the giant and refreshes the appearance.
WEAPON_TYPE = 10

#: The outcome line's two continuations, for the log -- the reference's wording.
NOTE_BOTH = "re-sent both USERINFO frames with {worn} worn item(s)"
NOTE_WEAPON = "refreshed weapon appearance with all worn rows"


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


def is_weapon(stack: items.ItemStack | None) -> bool:
    """Whether the moved row is a weapon, per the catalogue's `type_index`.

    The one observed small-only refresh is XJianHun's move into equipment slot
    12, and both weapon ids the oracles hold -- 401040095 and `giant`-pinned
    101011250 -- carry the catalogue's weapon category.  A row the catalogue
    does not know reads as not-a-weapon, which re-sends both frames.
    """
    if stack is None:
        return False
    definition = content.definition(stack.item_id)
    return definition is not None and definition.type_index == WEAPON_TYPE


@dataclass(frozen=True, slots=True)
class SlotRecord:
    """One `(0,14)` record block: an address plus the fields it carries.

    `value` is the number the client shows: the instance value when the row
    has one, else the count.  Measured on both ends of the 09-27 cargo move (a
    `count=4, instance_value=0` row went out as 4), on both item-use frames
    (3->2 and 5->4) and on the worn rows of the M2.2 oracle.
    """

    slot_index: int
    item_id: int
    value: int
    reinforcement: int = 0
    durability: int = 0
    enchant_card_id: int = 0
    amplify_type: int = 0
    amplify_value: int = 0
    growth_experience: int = 0

    @classmethod
    def of_stack(cls, stack: items.ItemStack | None,
                 slot_index: int | None = None) -> "SlotRecord":
        if stack is None:
            return cls(slot_index=0 if slot_index is None else slot_index,
                       item_id=EMPTY_ITEM_ID, value=0)
        return cls(
            slot_index=stack.slot_index if slot_index is None else slot_index,
            item_id=stack.item_id, value=stack.instance_value or stack.count,
            reinforcement=stack.reinforcement, durability=stack.durability,
            enchant_card_id=stack.enchant_card_id,
            amplify_type=stack.amplify_type, amplify_value=stack.amplify_value,
            growth_experience=stack.growth_experience)

    def block(self) -> bytes:
        out = bytearray(BLOCK_SIZE)
        struct.pack_into("<H", out, 0, self.slot_index)
        struct.pack_into("<I", out, 2, self.item_id)
        struct.pack_into("<I", out, 6, self.value)
        out[10] = self.reinforcement
        out[11] = self.durability
        struct.pack_into("<I", out, 14, self.enchant_card_id)
        out[19] = self.amplify_type
        out[20] = self.amplify_value
        struct.pack_into("<H", out, 140, self.growth_experience)
        return bytes(out)


def slot_frame(list_type: int, records: Sequence[SlotRecord]) -> bytes:
    """A `(0,14)` body: the header, one block per record, zero-pad to 8."""
    out = bytearray([list_type, len(records), 0])
    for record in records:
        out += record.block()
    return bytes(out) + bytes(-len(out) % 8)


def slot_body(stack: items.ItemStack | None, list_type: int,
              slot_index: int) -> bytes:
    """One `(0,14)` frame: the 168B a slot's post-move state goes out as.

    An empty slot keeps the `FF FF FF FF` item id and nothing else.  The
    growth field sits far from the rest (`[143:145]`) with the bytes between
    zero in every capture.
    """
    return slot_frame(list_type, [SlotRecord.of_stack(stack, slot_index)])


def roster_at(name_length: int) -> int:
    """Where a small USERINFO's six roster bytes start: behind the name."""
    return NAME_AT + name_length


def records_at(name_length: int) -> int:
    """Where its 31B records start: behind the roster block, at 216 for the
    save's eight-character names."""
    return roster_at(name_length) + ROSTER_SIZE


def tail_body(worn: list[items.ItemStack], levels: dict[int, int]) -> bytes:
    """The 118B tail, with the slot-26 pair spliced in where it is worn."""
    out = bytearray(TAIL)
    for stack in worn:
        if stack.slot_index == giant.CREATURE_SLOT:
            struct.pack_into("<I", out, TAIL_CREATURE_AT, stack.item_id)
            out[TAIL_LEVEL_AT] = levels.get(stack.item_id, 0)
    return bytes(out)


def userinfo_body(summary: CharacterSummary, worn: list[items.ItemStack],
                  levels: dict[int, int], version: int) -> bytes:
    """The small `(0,2)` push: the header, one 31B record per worn row, the
    118B tail, zero-padded to a 16-byte multiple (1296B with 31 worn, 896B
    with 18 -- the same numbers the reference sent)."""
    name = summary.name.encode()
    start = records_at(len(name))
    body = bytearray(start + RECORD_SIZE * len(worn) + len(TAIL))
    body[0:len(HEADER_PREFIX)] = HEADER_PREFIX
    for stack in worn:
        if stack.slot_index == PET_SLOT:
            struct.pack_into("<I", body, 93, display_id(stack))
    roster = roster_at(len(name))
    struct.pack_into("<H", body, CHARACTER_AT, summary.character_id)
    body[NAME_LENGTH_AT] = len(name)
    body[NAME_AT:roster] = name
    body[roster + CLASS_OFFSET] = summary.class_id
    body[roster + GROW_OFFSET] = (summary.sub_grow_type << 4) | summary.grow_type
    body[roster + LEVEL_OFFSET] = summary.level
    body[roster + COUNT_OFFSET] = len(worn)
    for i, stack in enumerate(worn):
        body[start + RECORD_SIZE * i:start + RECORD_SIZE * (i + 1)] = record(stack)
    struct.pack_into("<H", body, VERSION_AT, version)
    body[start + RECORD_SIZE * len(worn):] = tail_body(worn, levels)
    return bytes(body) + bytes(-len(body) % 16)


@dataclass(frozen=True, slots=True)
class Refresh:
    frames: list[tuple[frame.Opcode, bytes]]
    worn: int
    #: The outcome line's continuation -- one of the two NOTE_ fragments.
    note: str
    #: Whether the specificity pair went out, and so whether the reference's
    #: EQUIPMENT-SPECIFICITY line should follow the outcome line.
    panel: bool


def build(conn: sqlite3.Connection, character_id: int, request: MoveRequest,
          summary: CharacterSummary) -> Refresh:
    """The frames that follow the ack, in the reference's order."""
    worn = equipment(conn, character_id)
    levels = giant.creature_levels(conn, character_id)
    value = fame.compute(conn, character_id)
    body = userinfo_body(summary, worn, levels, value)
    src = items.load(conn, character_id, *request.src.address)
    dst = items.load(conn, character_id, *request.dst.address)
    moved = src if src is not None else dst
    frames = [
        (OPCODE_SLOT, slot_body(src, *request.src.address)),
        (OPCODE_SLOT, slot_body(dst, *request.dst.address)),
        (OPCODE_USERINFO, body),
    ]
    if is_weapon(moved):
        note = NOTE_WEAPON
    else:
        note = NOTE_BOTH.format(worn=len(worn))
        # the giant carries the same version the small one does
        frames.append(
            (OPCODE_USERINFO, giant.body(summary, worn, levels,
                                         giant.runes(conn, character_id), value)))
    frames.append((OPCODE_VERSION, struct.pack("<I", summary.character_id)
                   + struct.pack("<H", value) + bytes(10)))
    panel = summary.level >= SPECIFICITY_LEVEL
    if panel:
        frames += [(OPCODE_STATE, STATE_BODY), (OPCODE_BOARD, BOARD_BODY)]
    return Refresh(frames=frames, worn=len(worn), note=note, panel=panel)
