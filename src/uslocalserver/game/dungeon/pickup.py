"""`(1,43)` DUNGEON-PICKUP-43 -- the client picking a ground drop up.

The request is 24B and only its first field is read::

    [0:4]   u32le  the ground slot -- the note's `key=`, and the only field
                   the reference reads back
    [4]     u8     0
    [5]     u8     0 in the tutorial dungeon's two sends, 1 in the seven
                   others, 2 in the one 09-25 send that was refused anyway
    [6:20]         four (x, y) u16le pairs -- positions around the pick
    [20:24]        zero

**The answer.**  An item is one 24B `(0,39)`; gold is a 56B one plus a
`(0,14)` 168B refresh of the slot it went into::

    item, 24B:  u32le key | u16le 3 | 8 zero | u16le 3 | u16le cell | 6 zero
    gold, 56B:  u32le key | u16le 3 | u8 1 | u16le amount | 00 00 01
                | zero to 56

`amount` is what this pickup added, not the total -- 32, 39, 17, 21 and 52
in the capture, and the note's `gold=` reads the total after.  The gold
refresh is the row the save now holds, sent the way a buy sends it
(`refresh.slot_frame(0, [SlotRecord.of_stack(gold, 0)])`).  The item form
carries the cell the row landed in at `[16:18]`; the `03 00` before it is
the capture's one unresolved field, `ADDRESS_TAG` below.

**Where the row lands** -- `place`: a stackable merges into a row of its own
item; anything else takes the first free cell at or past its band's base
(`buy.base_for`, bounded by `buy.BAG_CELL_BASE`).  That is `buy.free_slot`'s
rule with the merge narrowed to `kind == 1`, for the reason `place` writes
out.  The row is the ground record's own -- item, count, durability, and for
equipment the instance value -- and nothing is rolled.

**The two refusals**, both from the 09-25 log, both sending nothing and
printing the whole request upper-case::

    key=95 rejected: no active owner or invalid request; plain=...
    key=802 rejected: unknown, consumed or other-room ground object; plain=...

The forms separate cleanly.  key=95 was picked right after its session's
`SETTLEMENT-72` (refusal 117 ms after the 19:11:11.670 pair), and 96/94/93
of the same session went through seconds before it -- *after* the
`DUNGEON-CLEAR-46` at 19:11:07, which is not what refuses.  The 09-28
capture says the same: dungeon 5 clears at 21:12:53 and three pickups land
at 21:12:59.  So `no active owner` is the *run* being gone -- `(1,42)`'s
leave today, and `(1,72)`'s settlement once M3.6 models it -- not the
`(1,46)` flag `run.in_progress` carries.  The three `unknown` refusals are
all room changes: 802 fell in map 550041 and was picked in 550043, and 10
and 35 fell in 100003678 and 100003688 while the run stood in 100003863.
"""
from __future__ import annotations

import sqlite3
import struct
from dataclasses import dataclass, replace

from ...persistence import items
from ...protocol import frame
from ..data import content
from ..item import refresh
from ..shop import buy
from . import drops
from .run import DungeonSession

PICKUP_OPCODE = frame.Opcode(1, 43, frame.OpcodeEncoding.U8_U16LE, True)
REPLY_OPCODE = frame.Opcode(0, 39, frame.OpcodeEncoding.U8_U16LE, True)

#: The request is the 24B body above; the reply, 24B for an item and 56B for
#: gold, then zero-filled.
REQUEST_SIZE = 24
ITEM_BODY_SIZE = 24
GOLD_BODY_SIZE = 56

#: A gold drop's item id in the ground record and in the bag.
GOLD_ITEM = 0

#: The gold form's flag and amount.
GOLD_AT = 6
AMOUNT_AT = 7

#: The item form's `03 00` at `[14:16]`, just before the cell.  The gold form
#: has `00 00` there, so it is not the character the two forms share at
#: `[4:6]`; what it is the capture cannot say, because every sample is
#: character 3 and every destination item kind 0.  The gold form's `00 00 01`
#: at `[9:12]` is a constant of the same standing.
ADDRESS_TAG = 3
GOLD_TAIL = b"\x00\x00\x01"

UNKNOWN = "unknown, consumed or other-room ground object"
NO_OWNER = "no active owner or invalid request"

#: A full bag has no capture behind it: the wording is this rewrite's, and
#: the pickup leaves the object on the ground rather than eating it.
NO_ROOM = "no free bag slot"


def slot_of(plain: bytes) -> int:
    """The ground slot the request names, `key=` in the line."""
    return struct.unpack_from("<I", plain, 0)[0]


def refusal_note(key: int, reason: str, plain: bytes) -> str:
    """The line a refused pickup prints -- the whole request, upper-case."""
    return f"key={key} rejected: {reason}; plain={plain.hex().upper()}"


def item_body(key: int, character: int, cell: int) -> bytes:
    """The 24B `(0,39)` an item pickup answers with."""
    return (struct.pack("<IH", key, character) + bytes(8)
            + struct.pack("<HH", ADDRESS_TAG, cell) + bytes(6))


def gold_body(key: int, character: int, amount: int) -> bytes:
    """The 56B `(0,39)` a gold pickup answers with."""
    out = bytearray(GOLD_BODY_SIZE)
    struct.pack_into("<IH", out, 0, key, character)
    out[GOLD_AT] = 1
    struct.pack_into("<H", out, AMOUNT_AT, amount)
    out[9:12] = GOLD_TAIL
    return bytes(out)


def stackable(item_id: int) -> bool:
    """Whether the catalogue stacks this item -- which is what merges."""
    definition = content.definition(item_id)
    return (definition.kind if definition is not None
            else drops.STACKABLE_KIND) == drops.STACKABLE_KIND


def place(conn: sqlite3.Connection, character_id: int,
          item_id: int) -> tuple[int, items.ItemStack | None] | None:
    """The cell an item lands in, and the row already there when it merges.

    The merge is for stackables only.  conn=17 picks 100070728 into cell 13
    at 15:26:45 and into cell 15 forty-four seconds later, and the only move
    the log records for that item leaves 15 at 15:29:04 -- so the row at 13
    was still standing when the second pickup skipped it, which
    `buy.free_slot`'s same-item merge would not have done.  A stackable's
    evidence runs the other way: 20+ pickups of 10313459 all land on 0:138,
    09-25's three 1047s all on 0:66, and the count they add is the record's.
    """
    rows = conn.execute(
        "select slot_index, item_id from character_items where character_id = ? "
        "and list_type = ? order by slot_index",
        (character_id, buy.GOLD_LIST)).fetchall()
    if stackable(item_id):
        held = next((slot for slot, item in rows
                     if item == item_id and slot != buy.GOLD_SLOT), None)
        if held is not None:
            return held, items.load(conn, character_id, buy.GOLD_LIST, held)
    taken = {slot for slot, _item in rows}
    for slot in range(buy.base_for(item_id), buy.BAG_CELL_BASE):
        if slot not in taken:
            return slot, None
    return None


def picked_row(character_id: int, cell: int, row: drops.Row,
               now: int) -> items.ItemStack:
    """The bag row a picked-up item becomes, straight off the ground record."""
    return replace(
        buy.fresh_row(character_id, cell, row.item, row.count, now),
        durability=row.durability,
        instance_value=(0 if stackable(row.item) else row.value))


@dataclass(frozen=True, slots=True)
class Resolution:
    """One pickup's whole answer: its frames -- none on a refusal -- and the
    line, which carries the reason when it refused."""

    frames: tuple[tuple[frame.Opcode, bytes], ...]
    note: str

    @property
    def committed(self) -> bool:
        return bool(self.frames)


def resolution(conn: sqlite3.Connection, session: DungeonSession, character: int,
               key: int, plain: bytes, now: int) -> Resolution:
    """Everything a `(1,43)` draws: a refusal, or the write and its frames.

    Only a pickup that went through consumes the ground row.  A refused one
    leaves it lying: the 09-25 log's key=10 and key=35 were refused as
    other-room at 18:46:46 and 18:51:45 and committed 18 and 27 seconds
    later, when the run stood in their rooms again -- and the empty bag
    never met its object at all.
    """
    def refused(reason: str) -> Resolution:
        return Resolution(frames=(), note=refusal_note(key, reason, plain))

    if session.run is None:
        return refused(NO_OWNER)
    entry = session.ground.get(key)
    if entry is None or entry[0] != session.run.map_id:
        return refused(UNKNOWN)
    row = entry[1]

    with conn:
        if row.item == GOLD_ITEM:
            gold = items.load(conn, character, buy.GOLD_LIST, buy.GOLD_SLOT)
            if gold is None:
                items.insert(conn, buy.fresh_row(character, buy.GOLD_SLOT,
                                                 GOLD_ITEM, row.value, now))
            else:
                items.set_count(conn, gold, gold.count + row.value, now)
        else:
            placed = place(conn, character, row.item)
            if placed is None:
                return refused(NO_ROOM)
            cell, existing = placed
            if existing is None:
                items.insert(conn, picked_row(character, cell, row, now))
            else:
                items.set_count(conn, existing, existing.count + row.count, now)
    del session.ground[key]

    gold = items.load(conn, character, buy.GOLD_LIST, buy.GOLD_SLOT)
    held = gold.count if gold is not None else 0
    if row.item == GOLD_ITEM:
        frames = ((REPLY_OPCODE, gold_body(key, character, row.value)),
                  (refresh.OPCODE_SLOT,
                   refresh.slot_frame(buy.GOLD_LIST,
                                      [refresh.SlotRecord.of_stack(
                                          gold, buy.GOLD_SLOT)])))
        note = (f"key={key} character={character} item={GOLD_ITEM} "
                f"count={row.value} destination={buy.GOLD_LIST}:{buy.GOLD_SLOT} "
                f"gold={held} committed")
    else:
        frames = ((REPLY_OPCODE, item_body(key, character, cell)),)
        note = (f"key={key} character={character} item={row.item} "
                f"count={row.count} destination={buy.GOLD_LIST}:{cell} "
                f"gold={held} committed")
    return Resolution(frames=frames, note=note)
