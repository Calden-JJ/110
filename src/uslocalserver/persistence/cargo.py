"""Reading and writing `account_cargo_items` -- the account-scope warehouse.

A `(1,19)` move reaches two tables: rows whose `list_type` is 2 (the
character's own warehouse) live in `character_items` like every other
character list, while `list_type` 12 (the account warehouse the whole account
shares) lives here, keyed by `account_id`.  The mapping is the save's own --
`account_cargo_items` has `CHECK(list_type=12)` -- and the 09-27 probe's
`2/63->12/2`-shaped moves agree.

The columns are `character_items`' minus `character_id` plus `account_id`, so
the same `items.ItemStack` carries a row here; its `character_id` field holds
the account id.  `character_items`' triggers (the GM revision counters) have
no counterpart on this table, so no bookkeeping rides along.
"""
from __future__ import annotations

import sqlite3

from . import items

TABLE = "account_cargo_items"
LIST_TYPE = 12

COLUMNS = ("account_id",) + items.COLUMNS[1:]

#: The account column is aliased to the stack's own name so one
#: `items.ItemStack` can carry a row from either table.
_SELECT = (f'select account_id as character_id, '
           f'{", ".join(items.COLUMNS[1:])} from "{TABLE}"')


def load(conn: sqlite3.Connection, account_id: int, list_type: int,
         slot_index: int) -> items.ItemStack | None:
    row = conn.execute(f"{_SELECT} where account_id = ? and list_type = ? "
                       f"and slot_index = ?",
                       (account_id, list_type, slot_index)).fetchone()
    return items.ItemStack.from_row(row) if row else None


def insert(conn: sqlite3.Connection, stack: items.ItemStack) -> None:
    # `account_id` comes off the stack's `character_id` -- see the module
    # docstring.
    values = (stack.character_id,) + tuple(getattr(stack, name)
                                           for name in COLUMNS[1:])
    conn.execute(f'insert into "{TABLE}" ({", ".join(COLUMNS)}) '
                 f'values ({", ".join("?" * len(COLUMNS))})', values)


def delete(conn: sqlite3.Connection, account_id: int, list_type: int,
           slot_index: int) -> None:
    conn.execute(f'delete from "{TABLE}" where account_id = ? '
                 f"and list_type = ? and slot_index = ?",
                 (account_id, list_type, slot_index))


def set_count(conn: sqlite3.Connection, stack: items.ItemStack, count: int,
              updated_at: int) -> None:
    conn.execute(f'update "{TABLE}" set count = ?, updated_at = ? '
                 f"where account_id = ? and list_type = ? and slot_index = ?",
                 (count, updated_at, stack.character_id, stack.list_type,
                  stack.slot_index))


def relocate(conn: sqlite3.Connection, stack: items.ItemStack,
             list_type: int, slot_index: int, updated_at: int) -> None:
    conn.execute(f'update "{TABLE}" set list_type = ?, slot_index = ?, '
                 f"updated_at = ? where account_id = ? and list_type = ? "
                 f"and slot_index = ?",
                 (list_type, slot_index, updated_at, stack.character_id,
                  stack.list_type, stack.slot_index))
