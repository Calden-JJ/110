"""Item definitions from the reference's own catalogue.

The 69 embedded tables carry shops, drops and quests, but not the items
themselves: those live in the launcher's 500k-row `item_content_110us.db`
(`paths.ITEM_CONTENT_DB`).  Two measured readers need it -- `(1,21)` creates
a bought row with the durability the catalogue holds (item 29127's fresh row
went into its `(0,14)` frame as 48, the catalogue's own value), and a
stackable's catalogue durability is 0, so the one rule covers both; and
`(1,19)`'s refresh asks the catalogue's `type_index` whether the moved row is
a weapon.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from uslocalserver import paths


@dataclass(frozen=True, slots=True)
class ItemDefinition:
    """The catalogue columns a purchase, a sale or a refresh reads.

    `type_index` is the equipment category: 10 is the weapon slot's own
    category (`(1,19)`'s small-only refresh keys off it), and it is the same
    number for the two weapon ids the oracles exercise, 401040095 and
    101011250, while nothing worn elsewhere carries it.
    """

    item_id: int
    kind: int
    type_index: int
    durability: int
    value: int


def definition(item_id: int) -> ItemDefinition | None:
    """The catalogue row for `item_id`, or None when it is not there.

    The catalogue is opened per call -- a purchase or a move is rare and the
    file is the launcher's, not the save's, so nothing is cached or held open.
    """
    if not paths.ITEM_CONTENT_DB.exists():
        return None
    conn = sqlite3.connect(paths.ITEM_CONTENT_DB)
    try:
        row = conn.execute(
            "select item_id, kind, type_index, durability, value from items "
            "where item_id = ?", (item_id,)).fetchone()
    finally:
        conn.close()
    return None if row is None else ItemDefinition(
        item_id=row[0], kind=row[1], type_index=row[2], durability=row[3],
        value=row[4])
