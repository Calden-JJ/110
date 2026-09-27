"""Reading characters off a save.

The one hand-written typed interface M0 has, covering the only query that was
verified end to end against the real save: pick an account, list its
characters in slot order.  Everything else goes through `schema.Repository`,
which does not need a class per table -- see `schema.py` for why.

`slot_index` is the client's character-select order, so the list comes back in
it.  `favorite_position` is that screen's separate "favourite" pin (0 = not
pinned); `uq_characters_favorite` keeps one account from pinning two
characters to the same position.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, fields

TABLE = "characters"

#: slot_index first: it is the ordering the client shows, and the field a
#: caller is most likely to reach for.
COLUMNS = (
    "character_id", "account_id", "slot_index", "name", "class_id", "level",
    "town_id", "area_id", "position_x", "position_y", "town_state",
    "created_at", "updated_at", "experience", "grow_type", "sub_grow_type",
    "ex_equip_slot_flags", "bonus_sp", "bonus_tp", "favorite_position",
    "pending_tutorial_dungeon_id",
)


@dataclass(frozen=True, slots=True)
class CharacterSummary:
    character_id: int
    account_id: int
    slot_index: int
    name: str
    class_id: int
    level: int
    town_id: int
    area_id: int
    position_x: int
    position_y: int
    town_state: int
    created_at: int
    updated_at: int
    experience: int
    grow_type: int
    sub_grow_type: int
    ex_equip_slot_flags: int
    bonus_sp: int
    bonus_tp: int
    favorite_position: int
    pending_tutorial_dungeon_id: int

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "CharacterSummary":
        return cls(**{f.name: row[f.name] for f in fields(cls)})

    @property
    def location(self) -> tuple[int, int, int]:
        return (self.town_id, self.area_id, self.town_state)

    @property
    def pinned(self) -> bool:
        return self.favorite_position > 0

    def __str__(self) -> str:
        return (f"{self.name} Lv{self.level} class={self.class_id} "
                f"town={self.town_id}/{self.area_id} slot={self.slot_index}")


def list_characters(conn: sqlite3.Connection, account_id: int) -> list[CharacterSummary]:
    """An account's characters, in the order the client shows them."""
    rows = conn.execute(
        f'select {", ".join(COLUMNS)} from "{TABLE}" '
        f'where account_id = ? order by slot_index', (account_id,)).fetchall()
    return [CharacterSummary.from_row(r) for r in rows]


def find(conn: sqlite3.Connection, account_id: int, name: str) -> CharacterSummary | None:
    row = conn.execute(
        f'select {", ".join(COLUMNS)} from "{TABLE}" '
        f'where account_id = ? and name = ?', (account_id, name)).fetchone()
    return CharacterSummary.from_row(row) if row else None


def at_slot(conn: sqlite3.Connection, account_id: int,
            slot_index: int) -> CharacterSummary | None:
    """`(1,4)`'s request names a character-selection slot, not an id.

    Its 16B body is all zeros in the capture, and the reference read that as
    `slot=0 key=1 name='XRenYing'` -- the key is looked up, not sent.
    """
    row = conn.execute(
        f'select {", ".join(COLUMNS)} from "{TABLE}" '
        f'where account_id = ? and slot_index = ?', (account_id, slot_index)).fetchone()
    return CharacterSummary.from_row(row) if row else None


def by_id(conn: sqlite3.Connection, character_id: int) -> CharacterSummary | None:
    """For the handlers that were handed an id and need the rest of the row
    (`(1,19)`'s refresh: name, class, level, grow types)."""
    row = conn.execute(
        f'select {", ".join(COLUMNS)} from "{TABLE}" '
        f'where character_id = ?', (character_id,)).fetchone()
    return CharacterSummary.from_row(row) if row else None
