"""The town-entry burst, addressed by opcode instead of by index.

`(1,143)`/`(1,666)` sent from `CharacterSelected` draw the entering
character's *own* frame list, and the lists differ: XRenYing's run is 33
frames, LRouDao's 31 and XJianHun's 30 (the shapes are in
`data/game/town_bursts.json`, one burst per character key).  The frames the
server rebuilds sit at different indices in each -- the quickslots are frame
15 of XRenYing's run and 14 of the other two, the quest trio 17/18/19 against
16/17/18 -- so nothing can be addressed by index.  Opcodes can, once the two
that repeat within a run are split:

* `(0,2)` appears twice and leads with its subtype byte: 0 is the small
  USERINFO (`refresh.py`), 1 the giant (`giant.py`).
* `(0,13)` appears seven times and leads with its kind byte: 0 is the main
  inventory, and the rest are the character's avatar, cargo, worn, pet and
  rune bags.

`locate` returns those positions and nothing else; `_town_entry` regenerates
what it finds there.

**The two entry opcodes draw the same list.**  XJianHun entered through both
-- `(1,666)` on 09-28, `(1,143)` on 09-29 -- and the `(1,666)` run is the
`(1,143)` run behind one extra leading 8B `(1,666)` ack: the opcode sequence
matches element for element, and the 16B `(1,143)` frame that follows the ack
is *byte*-identical to the `(1,143)` run's own first frame.  So the frame list
belongs to the character and only the leading ack belongs to the request --
which is why a character captured through one opcode can still enter through
the other, with every rebuilt index shifted by one.

**What is rebuilt and what is replayed.**  Everything the capture cannot
carry for the selected character is built from the save at entry: the eight
row-built frames `_town_entry` always rebuilt, plus the three the corpus's
`replies.json` burst could never hold correctly -- the two USERINFO frames,
which name the character and list its worn set, and the main inventory.  The
latter is the one frame *both* new captures cut: the log's hex dumps stop at
4096 bytes (4080 of body) and the frame is 7265B for LRouDao and 4130B for
XJianHun, so a replayed copy would be half a frame.

The remaining `(0,13)` bag frames are replayed as captured -- they are the
captured character's own, and for all three keys they still agree with the
live save down to the row count and the capacity params (`character_avatar`,
`character_cargo_capacity`, `character_inventory_expansion`), but nothing
rebuilds them yet, so a bag that changes after its capture goes stale until
the next one.  Their record layouts are *not* `refresh.SlotRecord`: a worn
row's block is that record with its leading slot u16 dropped, 163 bytes, and
rows below slot 12 carry 44 more (`(0,13)` kind 3).  Written up in
`references/protocol.md`.
"""
from __future__ import annotations

import sqlite3
import struct
from collections.abc import Sequence
from dataclasses import dataclass

from ...persistence import capacity, characters, items, materials
from ...protocol import frame
from ..item import refresh
from ..shop import buy, cera
from . import charsettings, movement, queststate

#: The opcode `(0,13)` carries whichever bag a frame is about.
LIST_OPCODE = frame.Opcode(0, 13, frame.OpcodeEncoding.U8_U16LE, True)

#: The frames `_town_entry` regenerates, by name.  The two whose opcode
#: repeats inside a run -- `(0,2)` and `(0,13)` -- are split separately, by
#: their leading byte.
OPCODES: dict[str, frame.Opcode] = {
    "quickslots": charsettings.PUSH_OPCODE,
    "finished": queststate.FINISHED_OPCODE,
    "in_progress": queststate.IN_PROGRESS_OPCODE,
    "available": queststate.AVAILABLE_OPCODE,
    "pair0": movement.AREA_ACK_OPCODE,
    "pair1": movement.AREA_ACK_2_OPCODE,
    "spawn": movement.SPAWN_OPCODE,
    "cera": cera.BALANCE_OPCODE,
}

#: `(0,2)`'s two faces, by the subtype byte that leads the body.
SELF_SUBTYPE = 0
GIANT_SUBTYPE = 1

#: `(0,13)`'s main inventory, by the kind byte that leads the body.
INVENTORY_KIND = 0

#: The entry opcode `town_bursts.json` stores its captures under, and the other
#: one a client may enter through instead.  A `(1,666)` run is a `(1,143)` run
#: behind one extra leading 8B ack, so a character captured on either can be
#: answered on both -- which matters because answering one with the corpus run
#: sends another character's bags.
CAPTURED_ENTRY = (1, 143)
OTHER_ENTRY = (1, 666)
#: That other opcode's own ack, pinned on the corpus `(1,666)` run.
OTHER_ENTRY_ACK = bytes(8)

#: Every burst carries these; a run missing one is a data error, not a shape.
REQUIRED = ("quickslots", "finished", "in_progress", "available", "pair0",
            "pair1", "spawn", "cera", "userinfo", "giant", "inventory")

#: The main inventory's `(0,13)` header: kind, `u16` expansion, `u16` row
#: count, then one 165B `refresh` record per row and a zero pad to 8.  The
#: unpadded length is what the reference's `TOWN-ITEMS` line prints -- 12545B
#: for XRenYing's 76 rows, 7265B for LRouDao's 44, 4130B for XJianHun's 25.
HEADER_SIZE = 5
BLOCK_SIZE = refresh.BLOCK_SIZE


def locate(replies: Sequence[object]) -> dict[str, int]:
    """Where each regenerated frame sits in a burst.

    Raises `ValueError` on a burst that carries a frame twice or lacks one
    outright: the file is generated (`tools/extract_town_bursts.py` checks the
    same invariants), so either means the data is wrong, not the shape.
    """
    by_opcode = {op.key(): name for name, op in OPCODES.items()}
    subtyped = {bytes([SELF_SUBTYPE]): "userinfo",
                bytes([GIANT_SUBTYPE]): "giant"}
    inventory = bytes([INVENTORY_KIND])
    found: dict[str, int] = {}
    for i, reply in enumerate(replies):
        op = (reply.main, reply.sub)
        if reply.plain is None:
            raise ValueError(f"frame {i} ({op[0]},{op[1]}) is generated, "
                             f"not a captured body")
        head = reply.plain[0:1]
        if op == refresh.OPCODE_USERINFO.key():
            name = subtyped.get(head)
            if name is None:
                raise ValueError(f"frame {i} (0,2) leads with {head.hex()}, "
                                 f"neither subtype {SELF_SUBTYPE} nor "
                                 f"{GIANT_SUBTYPE}")
        elif op == LIST_OPCODE.key():
            if head != inventory:
                continue
            name = "inventory"
        else:
            name = by_opcode.get(op)
            if name is None:
                continue
        if name in found:
            raise ValueError(f"frames {found[name]} and {i} are both the "
                             f"{name} frame")
        found[name] = i
    missing = [name for name in REQUIRED if name not in found]
    if missing:
        raise ValueError(f"the burst has no {', '.join(missing)} frame")
    return found


def self_character(plain: bytes | None) -> int | None:
    """The character id a small USERINFO names -- what says whose burst this
    is, against the row that was selected."""
    if plain is None or len(plain) < refresh.CHARACTER_AT + 2:
        return None
    return struct.unpack_from("<H", plain, refresh.CHARACTER_AT)[0]


@dataclass(frozen=True, slots=True)
class Inventory:
    """The main-inventory `(0,13)` frame as the save has it at entry.

    Two parts.  First the character's own list-0 rows, `expansion` being
    `character_inventory_expansion`'s value -- the +8/+16 rows a ticket
    grants, 0 when the character has no row -- and the frame's `param` field.
    Then the account-material band: the twelve fixed cells 363..374
    (`buy.BAG_ITEMS`), each carrying its `account_materials` count.  The
    reference emits the whole band whether or not the account owns the item
    -- its 09-19 line is all twelve at count 0, and every one of the 44
    `TOWN-ITEMS` lines across the seven logs carries exactly these twelve
    cells -- which is what makes the bag's souls and cube fragments visible
    to the client.  A dungeon card's commit (`dungeon.card.list_body`) draws
    the same bag one `param` value apart: its 0 to this frame's expansion,
    the band included.
    """

    expansion: int
    rows: tuple[items.ItemStack, ...]
    #: `(item_id, count)` per cell, in `buy.BAG_ITEMS` order, absent rows 0.
    band: tuple[tuple[int, int], ...]

    @classmethod
    def of(cls, conn: sqlite3.Connection, character_id: int) -> "Inventory":
        rows = conn.execute(
            f'select {", ".join(items.COLUMNS)} from "{items.TABLE}" '
            "where character_id = ? and list_type = ? order by slot_index",
            (character_id, buy.GOLD_LIST)).fetchall()
        summary = characters.by_id(conn, character_id)
        counts = {m.item_id: m.count
                  for m in materials.items(conn, summary.account_id)}
        return cls(expansion=capacity.expansion(conn, character_id) or 0,
                   rows=tuple(items.ItemStack.from_row(r) for r in rows),
                   band=tuple((item_id, counts.get(item_id, 0))
                              for item_id in buy.BAG_ITEMS))

    @property
    def size(self) -> int:
        """The body's length before padding, which the note prints."""
        return HEADER_SIZE + BLOCK_SIZE * (len(self.rows) + len(self.band))

    def body(self) -> bytes:
        out = bytearray([INVENTORY_KIND])
        out += struct.pack("<HH", self.expansion,
                           len(self.rows) + len(self.band))
        for row in self.rows:
            out += refresh.SlotRecord.of_stack(row).block()
        for cell, (item_id, count) in enumerate(self.band, buy.BAG_CELL_BASE):
            out += refresh.SlotRecord(slot_index=cell, item_id=item_id,
                                      value=count).block()
        return bytes(out) + bytes(-len(out) % 8)

    def note(self) -> str:
        """The reference's `TOWN-ITEMS` prose: the count, the unpadded length
        and every row, `seed=` for a row that carries an instance value (the
        rows the client rolls options for) and `count=` otherwise."""
        fields = [
            f"slot={row.slot_index} id={row.item_id} "
            + (f"seed={row.instance_value}" if row.instance_value
               else f"count={row.count}")
            + f" dur={row.durability}"
            for row in self.rows]
        fields += [f"slot={cell} id={item_id} count={count} dur=0"
                   for cell, (item_id, count)
                   in enumerate(self.band, buy.BAG_CELL_BASE)]
        return (f"main inventory {len(self.rows) + len(self.band)} row(s), "
                f"(0,13) body={self.size}B: " + ", ".join(fields))
