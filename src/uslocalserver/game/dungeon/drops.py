"""`(0,38)` -- what a kill left on the ground, and the note's own view.

Every answered `(1,39)` sends one, and its body is::

    u16le seq | u16le count | count x 177B records | 00 00 ff 00 | pad to %4

so it is 8B with no drops, 188B with one and 364B with two -- the padding
lands the body on a multiple of 4.  A record is::

    +0   u32le  ground slot      +14  u8     0
    +4   u16le  ground slot      +15  u8     durability
    +6   u32le  item (0=gold)    +173 u16le  0xffff
    +10  u32le  value            +175 u16le  0x0003

`value` is the drop's own quantity: a gold drop's amount, a stackable's
count (the catalogue's `kind == 1`), and for anything else the instance uid
the row was stamped with.  The ground slot is the counter the session hands
out -- `slot:` in the note, one per row, in the order the frame lists them,
and two slots for two drops of the same item.

This module is the *feed* side of M3.3: a replay is handed the drops the
reference left (`die.Play.drops`).  A live kill rolls its own -- `droppool`
samples the corpus's observed drop sets, table 050's own weighted pools for
the room's boxes, and its gold range for the amounts -- so the frame an
unfed server sends carries the same distributions the reference's did.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ..data import content

#: One `(0,38)` record.
RECORD_SIZE = 177

#: The `seq`/`count` pair before the first record.
HEADER = 4

#: A record's own item id and value.
ITEM_AT = 6
VALUE_AT = 10

#: The four bytes after the last record.
TRAILER = b"\x00\x00\xff\x00"

#: The literal tail every record carries.
RECORD_TAIL = struct.pack("<HH", 0xFFFF, 0x0003)

#: The catalogue `kind` whose `value` is a stack count.
STACKABLE_KIND = 1

GOLD = "gold"


@dataclass(frozen=True, slots=True)
class Fact:
    """One drop a kill left: what a roll or a replay hands in.

    `kind` is the note's own word -- `monster`, `type2`, or `gold`, which is
    the pool table 050 picked it from, not anything the frame carries.
    """

    item: int
    value: int
    kind: str


@dataclass(frozen=True, slots=True)
class Row:
    """A `Fact` with the ground slot it landed in and the catalogue's own
    numbers filled in -- the record is built from these."""

    slot: int
    item: int
    value: int
    kind: str
    durability: int
    count: int


def rows(facts: tuple[Fact, ...], first_slot: int) -> tuple[Row, ...]:
    """Place `facts` on consecutive ground slots from `first_slot`."""
    out = []
    for index, fact in enumerate(facts):
        definition = content.definition(fact.item) if fact.item else None
        if fact.kind == GOLD:
            count = 0
        elif definition is not None and definition.kind == STACKABLE_KIND:
            count = fact.value
        else:
            count = 1
        out.append(Row(slot=first_slot + index, item=fact.item, value=fact.value,
                       kind=fact.kind,
                       durability=definition.durability if definition else 0,
                       count=count))
    return tuple(out)


def _record(row: Row) -> bytes:
    out = bytearray(RECORD_SIZE)
    struct.pack_into("<I", out, 0, row.slot)
    struct.pack_into("<H", out, 4, row.slot)
    struct.pack_into("<I", out, ITEM_AT, row.item)
    struct.pack_into("<I", out, VALUE_AT, row.value)
    out[15] = row.durability & 0xFF
    out[173:177] = RECORD_TAIL
    return bytes(out)


def body(seq: int, rows: tuple[Row, ...]) -> bytes:
    """`(0,38)`: the dying monster's id, then its rows."""
    out = struct.pack("<HH", seq, len(rows))
    out += b"".join(_record(row) for row in rows)
    out += TRAILER
    return out + bytes(-len(out) % 4)


def records(body: bytes) -> tuple[tuple[int, int], ...]:
    """The `(item, value)` pairs a `(0,38)` body carries, in frame order.

    What a replay reads the reference's answer with: the slots and the pools
    are the note's, the item and value the record's.
    """
    count = struct.unpack_from("<H", body, 2)[0]
    return tuple(
        (struct.unpack_from("<I", body, HEADER + ITEM_AT + RECORD_SIZE * i)[0],
         struct.unpack_from("<I", body, HEADER + VALUE_AT + RECORD_SIZE * i)[0])
        for i in range(count))


def note(rows: tuple[Row, ...]) -> str:
    """`drops=[...]` as the reference spells it.

    An item row is `slot:id x count / pool`; a gold row swaps the id pair for
    `0x` and the amount's *decimal spelling* -- 32 reads `0x32`, not `0x20`.
    """
    parts = []
    for row in rows:
        if row.kind == GOLD:
            parts.append(f"{row.slot}:0x{row.value}/{GOLD}")
        else:
            parts.append(f"{row.slot}:{row.item}x{row.count}/{row.kind}")
    return "[" + ",".join(parts) + "]"
