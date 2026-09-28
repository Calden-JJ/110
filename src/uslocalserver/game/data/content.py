"""Item definitions from the reference's own catalogue.

The 69 embedded tables carry shops, drops and quests, but not the items
themselves: those live in the launcher's 500k-row `item_content_110us.db`
(`paths.ITEM_CONTENT_DB`).  One measured reader needs it -- `(1,21)` creates
a bought row with the durability the catalogue holds (item 29127's fresh row
went into its `(0,14)` frame as 48, the catalogue's own value), and a
stackable's catalogue durability is 0, so the one rule covers both.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from uslocalserver import paths


@dataclass(frozen=True, slots=True)
class ItemDefinition:
    """The catalogue columns a purchase reads."""

    item_id: int
    kind: int
    durability: int


def definition(item_id: int) -> ItemDefinition | None:
    """The catalogue row for `item_id`, or None when it is not there.

    The catalogue is opened per call -- a purchase is rare and the file is
    the launcher's, not the save's, so nothing is cached or held open.
    """
    if not paths.ITEM_CONTENT_DB.exists():
        return None
    conn = sqlite3.connect(paths.ITEM_CONTENT_DB)
    try:
        row = conn.execute(
            "select item_id, kind, durability from items where item_id = ?",
            (item_id,)).fetchone()
    finally:
        conn.close()
    return None if row is None else ItemDefinition(item_id=row[0], kind=row[1],
                                                   durability=row[2])
