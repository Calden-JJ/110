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
#:
#: The four `expert_job_*` columns are 0.4.4's (the 副职业 / expert job system)
#: and sit *between* `ex_equip_slot_flags` and `bonus_sp` in the live table.
#: 0.3.6 has neither them nor anything in that gap, so this list is the 0.4.4
#: declaration order -- the order `pragma table_info` returns, which
#: `test_schema` pins.
COLUMNS = (
    "character_id", "account_id", "slot_index", "name", "class_id", "level",
    "town_id", "area_id", "position_x", "position_y", "town_state",
    "created_at", "updated_at", "experience", "grow_type", "sub_grow_type",
    "ex_equip_slot_flags", "expert_job_type", "expert_job_experience",
    "expert_job_grade", "expert_job_endurance", "bonus_sp", "bonus_tp",
    "favorite_position", "pending_tutorial_dungeon_id",
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
    expert_job_type: int
    expert_job_experience: int
    expert_job_grade: int
    expert_job_endurance: int
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


def clear_pending_tutorial(conn: sqlite3.Connection, character_id: int) -> None:
    """The tutorial entry's write: the pending dungeon is consumed.

    A character is born holding one (`pending_tutorial_dungeon_id`), and the
    reference's `tutorial entry committed; pending cleared=True` is the row
    read back after this.  Nothing else is touched: the capture gives no
    evidence about `updated_at` and none of its frames read it.
    """
    with conn:
        conn.execute(f'update "{TABLE}" set pending_tutorial_dungeon_id = 0 '
                     f'where character_id = ?', (character_id,))


def grant_experience(conn: sqlite3.Connection, character_id: int, level: int,
                     experience: int) -> None:
    """A kill's write-back: the row's level and cumulative experience.

    The row is what the next `(1,16)` prints -- the capture's four entries
    read level 1, 3, 5, 7, which is exactly `die.level_for` over the kills
    the runs had answered by then -- and what `(1,4)`'s selection shows.
    """
    with conn:
        conn.execute(f'update "{TABLE}" set level = ?, experience = ? '
                     f'where character_id = ?', (level, experience, character_id))


def story_level(conn: sqlite3.Connection, character_id: int) -> int:
    """`character_story_digest.last_level`, 0 when the character has no row.

    The row is what `(1,4)`'s STORY-DIGEST line reads, and it is the only
    per-character difference this project has found behind that body's
    tutorial-flag block -- see `game.character.roleselection`.
    """
    row = conn.execute(
        'select last_level from character_story_digest where character_id = ?',
        (character_id,)).fetchone()
    return 0 if row is None else row[0]


def tutorial_flag_count(conn: sqlite3.Connection, character_id: int) -> int:
    """How many tutorial flags the client has reported for a character.

    The `reported N` in the reference's TUTORIAL-FLAGS line: 4 for both
    characters that have played, 0 for a fresh one.
    """
    return conn.execute(
        'select count(*) from character_tutorial_flags where character_id = ?',
        (character_id,)).fetchone()[0]
