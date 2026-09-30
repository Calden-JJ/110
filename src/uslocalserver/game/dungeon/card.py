"""`(1,69)`/`(1,70)` CARD-STAGE and `(1,71)` DUNGEON-CARD-71 -- the flip chain.

`(1,46)`'s five frames hand the client a card -- `(0,35)`, 257 + 29k bytes --
and the client plays it back over three requests; `settle.py` keeps the
fourth.  The two stages are bare 13B headers; the commit is eight bytes of
side index::

    (1,69)  ->  one 8B `01` + zeros
    (1,70)  ->  the 24B flag body, then the state frame
    (1,71)  ->  the state frame, then the (0,13) bag list

**The stages.**  Both print the same line, `key=K opcode=69|70 free=F paid=P`,
and both booleans are the session's card result's flags at that moment: the
09-28 session's second pair -- asked at 21:12:56, after both flips -- reads
`free=True paid=True`, its first pair before any flip reads `False False`, and
a session whose flip lands a second later (09-26 10:00:32) reads False False
too.  Only `(1,70)` carries the state frame.

**The state frame** is the card's eight cells as the client is to draw them,
40B, or 48B once the paid side has landed::

    40B  `01 00 ff 00` + `00 ff ff 00` x 7 + 8 zeros
    48B  `01 00 00 01` + u32le(item) + `01 00 00 00` + `00 ff ff 00` x 7 + 8 zeros

`item` is the paid flip's own granted reward -- 31002 on the capture's
dungeon 3 and 22001 on dungeon 5, the two ids their side-1 lines grant.  The
card does not carry it, and the client learns what it bought from the
commit's own answer, so the frame stays 40B until a side-1 commit has gone
through.

**The commit** carries the side index at `[0]` and nothing else; 0 is the
free flip, 1 the paid one, and each answers with the state frame and then
`(0,13)`, the bag list *after* the grant: `00 00 00`, `u16le` count, the
character's list-0 rows in slot order as 165B `refresh` records -- the gold
row first, its value the purse -- zero-padded to 8.  The capture's three
sizes, 2976/3144/3312, are 18/19/20 rows.

The note reads `key=3 dungeon=3 run=<uuid> side=0 cost=0 goldDelta=34
balance=5066 rewards=0x34,406010081x1 committed`:

* `run` is the result's own 16 random bytes, one set per clear and shared by
  every commit of it (`b67cba62...` on both of dungeon 3's);
* `cost` is 0 on side 0 and the card's own `cost=` on side 1 -- 340 for
  dungeon 3, 580 for dungeon 5, the numbers the clear's `free= paid= cost=`
  prints;
* `goldDelta` is the card's gold field on side 0 (+34/+20, the deltas the
  09-28 purse history walks: 5032 + 34 = 5066, 5066 - 340 = 4726) and
  `-cost` on side 1;
* `rewards` is `0x` + the *decimal* delta when it is positive -- the prefix
  is a marker, `0x34` on a +34 -- then each granted item as `idxcount`, a
  stackable at its record's value and anything else `x1`, in the bag list's
  own order;
* `balance` is the purse the write left, which is also the `(0,13)` gold row.

**Fed and unfed.**  The rows, the balance and the uuid come from the
reference's own line and frames (`diff_dungeon.commit_feed`); a run with
nothing fed still sends both frames and grants what its own card holds: the
free side moves the purse by the card's gold and lands the clear's rolled
items, and the paid side rolls its own -- paying back `cardpool.paid_gold`
against the cost and landing its dungeon's paid item only six times in ten
-- since the request is eight bytes of side index and names no reward, so
both sides are the server's own roll (`cardpool`).  Each lands the way a
picked-up item does.  A live uuid is drawn per result, so an unfed server's
note cannot match a capture's, and is not meant to.
"""
from __future__ import annotations

import os
import sqlite3
import struct
from dataclasses import dataclass, field

from ...persistence import characters, items, materials
from ...protocol import frame
from ..item import refresh
from ..shop import buy
from . import cardpool, clear, pickup, reward
from .run import DungeonSession

COMMIT_OPCODE = frame.Opcode(1, 71, frame.OpcodeEncoding.U8_U16LE, True)
LIST_OPCODE = frame.Opcode(0, 13, frame.OpcodeEncoding.U8_U16LE, True)

#: The two stage requests are the opcodes `(1,46)` answers with, so the
#: client's echo of them comes back as a request.
STAGE_OPCODE = clear.STAGE_OPCODE
STAGE_FLAGS_OPCODE = clear.STAGE_FLAGS_OPCODE

#: The commit's body is the side index and seven zero bytes.
COMMIT_BODY_SIZE = 8

#: Where the card's own gold sits -- `clear.FREE_AT` is the count one byte
#: before it, and `clear.card_purse` reads the two paid fields.
GOLD_AT = 136

#: The state frame's two heads, before the item.
FREE_HEAD = b"\x01\x00\xff\x00"
PAID_HEAD = b"\x01\x00\x00\x01"
PAID_MID = b"\x01\x00\x00\x00"
CELL = b"\x00\xff\xff\x00"
CELL_TAIL = bytes(8)


def side_of(plain: bytes) -> int:
    """The side the commit names: `[0]`, the only field it reads."""
    return plain[0] if plain else 0


def state_body(paid_item: int | None) -> bytes:
    """The `(1,71)` state frame -- 40B, or 48B once the paid item is known."""
    if paid_item is None:
        return FREE_HEAD + CELL * 7 + CELL_TAIL
    return (PAID_HEAD + struct.pack("<I", paid_item) + PAID_MID + CELL * 7
            + CELL_TAIL)


def list_body(conn: sqlite3.Connection, character_id: int) -> bytes:
    """`(0,13)`: the character's list-0 bag, in slot order, padded to 8.

    The account-material band closes the frame the way the town entry's
    inventory does (363..374, `buy.BAG_ITEMS`): the capture's commit frames
    are 18/19/20 rows against the character's own six, and the band is the
    twelve that close the gap -- the M3.6 reading that the card path carried
    no band was the diff fixture's own rows standing in for it.
    """
    rows = conn.execute(
        f'select {", ".join(items.COLUMNS)} from character_items '
        "where character_id = ? and list_type = ? order by slot_index",
        (character_id, buy.GOLD_LIST)).fetchall()
    records = [refresh.SlotRecord.of_stack(items.ItemStack.from_row(r))
               for r in rows]
    summary = characters.by_id(conn, character_id)
    counts = {m.item_id: m.count
              for m in materials.items(conn, summary.account_id)}
    band = [(cell, item_id, counts.get(item_id, 0))
            for cell, item_id in enumerate(buy.BAG_ITEMS, buy.BAG_CELL_BASE)]
    out = bytearray(b"\x00\x00\x00" + struct.pack("<H", len(records) + len(band)))
    for record in records:
        out += record.block()
    for cell, item_id, count in band:
        out += refresh.SlotRecord(slot_index=cell, item_id=item_id,
                                  value=count).block()
    return bytes(out) + bytes(-len(out) % 8)


@dataclass(slots=True)
class Result:
    """One clear's card context: what the flips and the settlement read.

    Created by `(1,46)` and read by everything after it -- the stages print
    its two flags, a commit learns the paid item from its own grant, and the
    settlement counts attempts on it.  It outlives the run it came with:
    `(1,72)` leaves the run but a replay of the settlement still reads
    `retried` here.
    """

    dungeon: int
    gold: int = 0
    cost: int = 0
    grant_items: tuple[tuple[int, int], ...] = ()
    run_id: bytes = field(default_factory=lambda: os.urandom(16))
    free: bool = False
    paid: bool = False
    paid_item: int | None = None
    attempt: int = 0
    retried: bool = False

    @classmethod
    def of(cls, card: bytes, dungeon: int,
           items: tuple[tuple[int, int], ...] = ()) -> "Result":
        """The result a clear's card opens: its cost, free gold and grants.

        `items` is the live roll's own list -- what the free commit lands;
        a fed clear passes none and takes the grant from the fed write.
        """
        if len(card) < GOLD_AT + 4:
            return cls(dungeon=dungeon, grant_items=items)
        _, _, cost = clear.card_purse(card)
        return cls(dungeon=dungeon, cost=cost, grant_items=items,
                   gold=struct.unpack_from("<I", card, GOLD_AT)[0])


@dataclass(frozen=True, slots=True)
class Grant:
    """A fed `(1,71)`: the reference's own uuid and the write it left.

    Keyed by the request like every other feed -- and the commit's request is
    eight bytes of side index, so a session's two side-0 commits are
    byte-identical and the run's identity lives here, not in the request.
    """

    run_id: bytes
    write: reward.Write


@dataclass(frozen=True, slots=True)
class Granted:
    """A live commit's own grant, in the note's `rewards=` shape.

    Carries the same `item_id`/`value` pair a fed `refresh.SlotRecord`
    offers, so `rewards_text` reads either.
    """

    item_id: int
    value: int


@dataclass(frozen=True, slots=True)
class Resolution:
    """One commit's frames and its line."""

    frames: tuple[tuple[frame.Opcode, bytes], ...]
    note: str


def stage_note(key: int, opcode: int, result: Result | None) -> str:
    """The `DUNGEON-CARD-STAGE` prose after the bare `conn=N `."""
    free = result.free if result is not None else False
    paid = result.paid if result is not None else False
    return f"key={key} opcode={opcode} free={free} paid={paid}"


def rewards_text(gold_delta: int, rows) -> str:
    """The note's `rewards=`: the gold marker, then the granted items.

    The list is the bag frame's own order, which is why the gold -- list-0
    slot 0 -- always leads.  The `0x` prefix is a marker, not a base: the
    reference prints the decimal delta behind it (`0x34` on +34, `0x1076` on
    +1076).
    """
    parts = [f"0x{gold_delta}"] if gold_delta > 0 else []
    parts += [f"{r.item_id}x{r.value if pickup.stackable(r.item_id) else 1}"
              for r in rows]
    return ",".join(parts)


def commit_note(key: int, result: Result, side: int, cost: int, gold_delta: int,
                balance: int | None, rows) -> str:
    """The `DUNGEON-CARD-71` prose after the bare `conn=N `."""
    return (f"key={key} dungeon={result.dungeon} run={result.run_id.hex()} "
            f"side={side} cost={cost} goldDelta={gold_delta} "
            f"balance={balance} rewards={rewards_text(gold_delta, rows)} "
            f"committed")


def resolution(conn: sqlite3.Connection, session: DungeonSession,
               character_id: int, side: int, grant: Grant | None,
               now: int) -> Resolution:
    """Everything a `(1,71)` draws: the write, the two frames, the line.

    A fed commit writes exactly what the reference wrote -- rows and purse --
    and adopts its uuid so the line matches; an unfed one grants its own
    card's roll (`_live_grant`).  The list frame is built after, so it
    carries the state the client is about to see.
    """
    result = session.result
    if result is None:
        result = session.result = Result(
            dungeon=session.run.dungeon if session.run is not None else 0)
    cost = result.cost if side else 0
    if grant is not None:
        result.run_id = grant.run_id
        reward.apply(conn, character_id, grant.write, now)
        rows: tuple = grant.write.rows
        gold_delta = -cost if side else result.gold
    else:
        rows, gold_delta = _live_grant(conn, character_id, result, side, cost,
                                       now)
    if side:
        result.paid = True
        if rows:
            result.paid_item = rows[0].item_id
    else:
        result.free = True
    frames = ((COMMIT_OPCODE,
               clear.padded(COMMIT_OPCODE, state_body(result.paid_item))),
              (LIST_OPCODE,
               clear.padded(LIST_OPCODE, list_body(conn, character_id))))
    note = commit_note(session.key, result, side, cost, gold_delta,
                       purse(conn, character_id), rows)
    return Resolution(frames=frames, note=note)


def _live_grant(conn: sqlite3.Connection, character_id: int, result: Result,
                side: int, cost: int, now: int) -> tuple[tuple[Granted, ...], int]:
    """A commit with nothing fed: the purse, and whatever its side grants.

    The free side lands the clear's own roll (`Result.grant_items`, what the
    card showed) and moves the purse by the card's own gold; the paid side
    rolls its own now -- the request names nothing but the side -- paying
    back `cardpool.paid_gold` against the cost and landing its dungeon's
    paid item only `PAID_ITEM_CHANCE` of the time.  A side 1 against a card
    with no paid flip for sale (cost 0, the `disabled` specials) pays back
    nothing and grants nothing.  `balance` is written as the total, not the
    delta, the way `reward.set_gold` reads a fed write.  The rows come back
    for the note's `rewards=`, which lists only what landed.
    """
    rows: list[Granted] = []
    if side:
        gold_delta = cardpool.paid_gold(cost) - cost
        item = cardpool.paid_item(result.dungeon) if cost else None
        grants = () if item is None else ((item, 1),)
    else:
        gold_delta = result.gold
        grants = result.grant_items
    with conn:
        if gold_delta:
            held = purse(conn, character_id)
            reward.set_gold(conn, character_id, (held or 0) + gold_delta, now)
        for item_id, count in grants:
            if _land(conn, character_id, item_id, count, now):
                rows.append(Granted(item_id=item_id, value=count))
    return tuple(rows), gold_delta


def _land(conn: sqlite3.Connection, character_id: int, item_id: int,
          count: int, now: int) -> bool:
    """Put one granted item in the bag the way a pickup does; False on a
    full bag, which leaves it unlanded rather than overwriting a row."""
    placed = pickup.place(conn, character_id, item_id)
    if placed is None:
        return False
    cell, existing = placed
    if existing is None:
        items.insert(conn, buy.fresh_row(character_id, cell, item_id,
                                         count, now))
    else:
        items.set_count(conn, existing, existing.count + count, now)
    return True


def purse(conn: sqlite3.Connection, character_id: int) -> int | None:
    """The gold row's count -- `balance=` in the line, None when there is no
    row to read."""
    gold = items.load(conn, character_id, buy.GOLD_LIST, buy.GOLD_SLOT)
    return gold.count if gold is not None else None
