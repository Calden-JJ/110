"""Reading and writing `character_items`.

A row *is* the definition of "this slot holds something": empty slots have no
row at all, which is why a move's two ends are loaded with a `None` check and
not with a sentinel item id.  `(character_id, list_type, slot_index)` is the
primary key, so an item's address is what a move changes and the address is
also what the save's triggers key their bookkeeping on.

Which write shape a move uses is measured, not guessed.  Against the 09-27
oracle run's pre-move backup, `gm_inventory_revisions` moved by exactly one per
address for a plain move but by *two* for a swap -- so a plain move is an
address `UPDATE` (the `gm_inventory_update` trigger has a branch for exactly
that) and a swap is a delete plus an insert, not two updates.  `updated_at` is
unix seconds and is rewritten on every row the reference touches: the saved
rows carried the wall-clock second of the move that last touched them.

`schema.Repository` is read-only, so the write path lives here.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, fields, replace

TABLE = "character_items"

COLUMNS = (
    "character_id", "list_type", "slot_index", "item_id", "count",
    "durability", "instance_value", "random_options", "avatar_sockets",
    "clone_appearance_id", "reinforcement", "refinement", "fusion_item",
    "bakal_state", "transferred_option_mask", "enchant_card_id",
    "enchant_upgrade", "mist_imbued", "updated_at", "expires_at",
    "custom_option_ids", "growth_experience", "amplify_type", "amplify_value",
)

_SELECT = f'select {", ".join(COLUMNS)} from "{TABLE}"'


@dataclass(frozen=True, slots=True)
class ItemStack:
    """One `character_items` row, whole.  A move copies it verbatim."""

    character_id: int
    list_type: int
    slot_index: int
    item_id: int
    count: int
    durability: int
    instance_value: int
    random_options: bytes
    avatar_sockets: bytes
    clone_appearance_id: int
    reinforcement: int
    refinement: int
    fusion_item: str
    bakal_state: str
    transferred_option_mask: int
    enchant_card_id: int
    enchant_upgrade: int
    mist_imbued: int
    updated_at: int
    expires_at: int
    custom_option_ids: int
    growth_experience: int
    amplify_type: int
    amplify_value: int

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "ItemStack":
        return cls(**{f.name: row[f.name] for f in fields(cls)})

    @property
    def address(self) -> tuple[int, int]:
        return (self.list_type, self.slot_index)

    def at(self, list_type: int, slot_index: int, updated_at: int) -> "ItemStack":
        return replace(self, list_type=list_type, slot_index=slot_index,
                       updated_at=updated_at)


def load(conn: sqlite3.Connection, character_id: int,
         list_type: int, slot_index: int) -> ItemStack | None:
    row = conn.execute(f"{_SELECT} where character_id = ? and list_type = ? and slot_index = ?",
                       (character_id, list_type, slot_index)).fetchone()
    return ItemStack.from_row(row) if row else None


def relocate(conn: sqlite3.Connection, stack: ItemStack,
             list_type: int, slot_index: int, updated_at: int) -> None:
    """Move an existing row to another address, in place."""
    conn.execute(f'update "{TABLE}" set list_type = ?, slot_index = ?, updated_at = ? '
                 f"where character_id = ? and list_type = ? and slot_index = ?",
                 (list_type, slot_index, updated_at, stack.character_id,
                  stack.list_type, stack.slot_index))


def set_count(conn: sqlite3.Connection, stack: ItemStack, count: int,
              updated_at: int) -> None:
    conn.execute(f'update "{TABLE}" set count = ?, updated_at = ? '
                 f"where character_id = ? and list_type = ? and slot_index = ?",
                 (count, updated_at, stack.character_id, stack.list_type,
                  stack.slot_index))


def insert(conn: sqlite3.Connection, stack: ItemStack) -> None:
    conn.execute(f'insert into "{TABLE}" ({", ".join(COLUMNS)}) '
                 f'values ({", ".join("?" * len(COLUMNS))})',
                 tuple(getattr(stack, name) for name in COLUMNS))


def delete(conn: sqlite3.Connection, character_id: int,
           list_type: int, slot_index: int) -> None:
    conn.execute(f'delete from "{TABLE}" where character_id = ? '
                 f"and list_type = ? and slot_index = ?",
                 (character_id, list_type, slot_index))
