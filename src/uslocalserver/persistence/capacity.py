"""The three one-row capacity tables a purchase can raise.

`character_inventory_expansion` (+8/+16 main-inventory rows) and the two
warehouse states -- `character_cargo_state` for the character's own cargo
(list 2) and `character_second_cargo_state` for the account/second warehouse
-- are one row per character, keyed by `character_id`, with a single NOT NULL
value and no `updated_at`.  None of them has a trigger, so nothing rides along
with a write the way `character_items`' GM revision counters do.

`character_inventory_expansion`'s CHECK allows 0, 8 and 16 only and the 09-27
screen-read of the reference's own line shows it as a plain assignment (`0->8`
then `8->16` for the two upgrade kits, `16->16` for every item that leaves it
alone); the warehouse's is `8..264`.  Both are the values a cera-shop purchase
writes -- see `game.shop.cera`.
"""
from __future__ import annotations

import sqlite3

EXPANSION_TABLE = "character_inventory_expansion"
CARGO_TABLE = "character_cargo_state"
SECOND_CARGO_TABLE = "character_second_cargo_state"


def expansion(conn: sqlite3.Connection, character_id: int) -> int | None:
    """The character's extra main-inventory rows, or None when the save has
    no row for them -- the reference's own line prints 0 for that case."""
    row = conn.execute(
        f'select expansion from "{EXPANSION_TABLE}" where character_id = ?',
        (character_id,)).fetchone()
    return None if row is None else row[0]


def set_expansion(conn: sqlite3.Connection, character_id: int,
                  value: int) -> None:
    """Write the row, creating it if the character has none."""
    conn.execute(
        f'insert into "{EXPANSION_TABLE}" (character_id, expansion) '
        f"values (?, ?) on conflict (character_id) do update set "
        f"expansion = excluded.expansion", (character_id, value))


def cargo_capacity(conn: sqlite3.Connection, character_id: int, *,
                   second: bool = False) -> int | None:
    """The character's warehouse capacity; `second` reads the account-scope
    warehouse's state instead."""
    table = SECOND_CARGO_TABLE if second else CARGO_TABLE
    row = conn.execute(
        f'select capacity from "{table}" where character_id = ?',
        (character_id,)).fetchone()
    return None if row is None else row[0]


def set_cargo_capacity(conn: sqlite3.Connection, character_id: int,
                       capacity: int, *, second: bool = False) -> None:
    table = SECOND_CARGO_TABLE if second else CARGO_TABLE
    conn.execute(
        f'insert into "{table}" (character_id, capacity) values (?, ?) '
        f"on conflict (character_id) do update set "
        f"capacity = excluded.capacity", (character_id, capacity))
