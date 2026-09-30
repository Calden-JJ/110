"""The `(1,34)` rows a replay hands in, and the record helpers both chains share.

Two runs move the bag between the oracle's pickups: a quest finish lands its
reward rows (six at 21:11:48, three at 21:12:57) and a card commit its own
reward plus the gold its side paid (`card.py` -- four times, +34/-340 at
21:11:40/45 and +20/-580 at 21:12:54).  The pickups' destinations stand on
them -- slots 10..19 are what the reward rows made taken, and a replay that
skipped the rewards would land dungeon 5's 27602 on cell 10 where the
reference's own note says 18.

**A finish also pays experience.**  The line's `exp +2770 (base=1200,
contract=0, story=1570)` is what the row moves by, over the total the kills
left: the 09-28 character's 2296 -> 5066 -> 5153 -> 7338 -> 12820 walk is the
three finishes' gains, and `die.level_for` over the sum is the level the
frames after them report (3, 5, 5, 5, 7).

**The card frame parses like a refresh.**  A `(0,13)` body is `00 00 00`,
`u16le` count, then the same 165B records a `(0,14)` carries, five bytes in:
slot at `[0:2]`, item, value, durability, and the far fields of
`refresh.SlotRecord`.  Its first record is the gold row, whose value is the
note's `balance=` -- the four frames read 5066/4726/4785/4205, the exact
numbers the note prints.  A reward item is the record the note's `rewards=`
names: the four runs list `406010081x1`, `31002x1`, `416020054x1` and
`22001x1`, landing on cells 12, 13, 10 and 14 -- each the first free cell at
or past the equipment base 9 the moment it was written, which is what makes
the two 09-28 pickups after them land on 18 and 19.

**Telling an instance uid from a count.**  A `(0,14)`/`(0,13)` value is
`instance_value or count`, so it cannot say which field it came from.  For
equipment (`kind 0`) the count is always 1, so a value of 2 or more is a uid
and the capture's rolled uids are all huge; a value of exactly 1 reads as
count 1 with no uid, which is what quest 3146's three rows (20002, 24002,
22002) are in the save -- `instance_value` 0 next to the frame's value 1.  A
stackable's value is its count and never a uid.

The gold delta is the note's `balance=`, the *state* the run left, not the
delta: `goldDelta` and the side's cost are already inside it.
"""
from __future__ import annotations

import sqlite3
import struct
from dataclasses import dataclass, replace

from ...persistence import characters, items
from ..data import content
from ..item import refresh
from ..shop import buy
from . import die, drops

#: Where the 165B records start in each frame: past `u8 list, u8 count, u8 0`
#: in a `(0,14)`, and past `00 00 00, u16le count` in the `(0,13)` list.
REFRESH_HEADER = 3
LIST_HEADER = 5


def refresh_records(body: bytes) -> tuple[refresh.SlotRecord, ...]:
    """The records of a `(0,14)` body."""
    return _records(body, REFRESH_HEADER, body[1])


def list_records(body: bytes) -> tuple[refresh.SlotRecord, ...]:
    """The records of a `(0,13)` body -- the card commit's list frame."""
    return _records(body, LIST_HEADER, struct.unpack_from("<H", body, 3)[0])


def _records(body: bytes, header: int, count: int) -> tuple[refresh.SlotRecord, ...]:
    out = []
    for i in range(count):
        block = body[header + refresh.BLOCK_SIZE * i:
                     header + refresh.BLOCK_SIZE * (i + 1)]
        slot, item, value = struct.unpack_from("<HII", block, 0)
        out.append(refresh.SlotRecord(
            slot_index=slot, item_id=item, value=value,
            reinforcement=block[10], durability=block[11],
            enchant_card_id=struct.unpack_from("<I", block, 14)[0],
            amplify_type=block[19], amplify_value=block[20],
            growth_experience=struct.unpack_from("<H", block, 140)[0]))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class Write:
    """One run's fed rows, and the gold and experience it left when it moved
    any.

    `gold=None` is "this run did not touch the purse" -- a quest finish pays
    experience, a card commit pays both -- and a card commit passes the
    note's `balance=`.  `exp` is the finish line's own gain, added to the
    row's total rather than replacing it: the kills write absolute totals and
    a finish moves from wherever they left off.
    """

    gold: int | None = None
    rows: tuple[refresh.SlotRecord, ...] = ()
    exp: int | None = None


def row(record: refresh.SlotRecord, character_id: int, now: int) -> items.ItemStack:
    """The bag row a record describes -- see the module on value vs count."""
    definition = content.definition(record.item_id)
    stackable = (definition is not None
                 and definition.kind == drops.STACKABLE_KIND)
    return replace(
        buy.fresh_row(character_id, record.slot_index, record.item_id,
                      record.value if stackable else 1, now),
        durability=record.durability,
        instance_value=(0 if stackable else (record.value if record.value > 1
                                             else 0)),
        reinforcement=record.reinforcement,
        enchant_card_id=record.enchant_card_id,
        amplify_type=record.amplify_type, amplify_value=record.amplify_value,
        growth_experience=record.growth_experience)


def set_gold(conn: sqlite3.Connection, character_id: int, total: int,
             now: int) -> None:
    """The purse at `total`, inserting the row when the character has none.

    The card's live commit moves the same row (`card._live_grant`), so the
    write lives here beside `apply`'s own.
    """
    gold = items.load(conn, character_id, buy.GOLD_LIST, buy.GOLD_SLOT)
    if gold is None:
        items.insert(conn, buy.fresh_row(character_id, buy.GOLD_SLOT, 0,
                                         total, now))
    else:
        items.set_count(conn, gold, total, now)


def apply(conn: sqlite3.Connection, character_id: int, write: Write,
          now: int) -> None:
    """Write one fed run's rows, gold and experience, in one transaction."""
    with conn:
        if write.exp is not None:
            summary = characters.by_id(conn, character_id)
            total = (summary.experience if summary is not None else 0) + write.exp
            characters.grant_experience(conn, character_id,
                                        die.level_for(total), total)
        if write.gold is not None:
            set_gold(conn, character_id, write.gold, now)
        for record in write.rows:
            existing = items.load(conn, character_id, buy.GOLD_LIST,
                                  record.slot_index)
            if existing is not None:
                items.delete(conn, character_id, buy.GOLD_LIST,
                             record.slot_index)
            items.insert(conn, row(record, character_id, now))
