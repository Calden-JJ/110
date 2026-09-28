"""Reading and writing `account_materials` -- the account-scope material bag.

Four columns, no slot: `(account_id, item_id)` is the primary key and the
count is the whole state, so an item's *address* is its item id and the bag
cell the client shows it in is derived, never stored (see
`game.shop.buy.bag_cell`).  The table has no triggers either, so nothing
rides along with a write the way `character_items`' GM revision counters do.

An item row is created by a `(1,21)` buy or by whatever the reference's own
loot paths do; a rewrite session reads and writes it through here.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

TABLE = "account_materials"

COLUMNS = ("account_id", "item_id", "count", "updated_at")


@dataclass(frozen=True, slots=True)
class Material:
    """One `account_materials` row."""

    item_id: int
    count: int
    updated_at: int

    @classmethod
    def from_row(cls, row: sqlite3.Row | tuple) -> "Material":
        return cls(item_id=row[1], count=row[2], updated_at=row[3])


def load(conn: sqlite3.Connection, account_id: int,
         item_id: int) -> Material | None:
    row = conn.execute(
        f'select {", ".join(COLUMNS)} from "{TABLE}" where account_id = ? '
        f"and item_id = ?", (account_id, item_id)).fetchone()
    return Material.from_row(row) if row else None


def items(conn: sqlite3.Connection, account_id: int) -> list[Material]:
    """Every row of the account's bag, ascending by item id -- the order the
    bag cells number in."""
    rows = conn.execute(
        f'select {", ".join(COLUMNS)} from "{TABLE}" where account_id = ? '
        f"order by item_id", (account_id,)).fetchall()
    return [Material.from_row(r) for r in rows]


def insert(conn: sqlite3.Connection, account_id: int, item_id: int, count: int,
           updated_at: int) -> None:
    conn.execute(f'insert into "{TABLE}" ({", ".join(COLUMNS)}) '
                 f'values (?, ?, ?, ?)', (account_id, item_id, count, updated_at))


def set_count(conn: sqlite3.Connection, account_id: int, item_id: int,
              count: int, updated_at: int) -> None:
    conn.execute(f'update "{TABLE}" set count = ?, updated_at = ? '
                 f"where account_id = ? and item_id = ?",
                 (count, updated_at, account_id, item_id))
