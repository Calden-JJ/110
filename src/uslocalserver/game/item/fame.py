"""The character's fame -- the u16 `(0,2)` and `(0,2265)` all carry.

Byte-exact against both save characters (1 `XRenYing`: 35037; 2 `LRouDao`:
811) and against every fame probe bin in `_m23/probe`.  The sum walks
`character_items` and adds five parts per counted row:

    item       the row's `fame_content.items` value
    enchant    the enchant card's value from the same table
    socket     each 6-byte `avatar_sockets` entry's id (`[off+2:off+6]`) from
               the same table
    growth     `option_growth`: the normal experience ladder, or the divine
               one for a divine weapon or a level-110 item, capped at the
               divine limit (`divineWeaponLimit` for weapons, `divineLimit`
               otherwise)
    reinforce  the per-level table below -- probe-derived -- with the column
               picked by `amplify_type` and the item's `fame_content.upgrades`
               weapon flag, growing linearly past level 15

Counted rows are every list-3 (equipment) row except slots 11 and 32 -- three
insert probes at 11 (plain, weapon, epic) and two at 32 all leave the u16
untouched -- plus the list-43 rune window, slots 320..328, which counts only
while a talisman sits in equipment slot 33.

The window is the talisman system's: its rows are the runes stored in the
equipped talisman, and the reference counts them only while the first special
slot is occupied by a talisman (table 040's `rune`-flag column).  Probe bins:
a talisman at 33 with one window row gives 185 + 46, the same talisman moved
to 34 or 35 or a *rune* at 33 leaves the window at 0, and dropping char 1's
slot-33..35 talismans with the window rows gives 34068 = 35037 - 555 - 414.
Everything else about the character -- level, quest 21019, `ex_equip_slot_flags`
-- was probed and does not gate it.
"""
from __future__ import annotations

import functools
import sqlite3
import struct
from dataclasses import dataclass

from ...persistence import items
from ..data import load

EQUIPMENT_LIST = 3
WINDOW_LIST = 43

#: Equipment slots the item sum walks past, probe-pinned: rows inserted at 11
#: and 32 never moved the u16.
SKIPPED_SLOTS = (11, 32)

#: The rune window (list 43) and the talisman slot that arms it.  `--slot 1`
#: bins with a talisman at 33 counted the window; at 34, at 35, or with a rune
#: at 33 it stayed dark.
TALISMAN_SLOT = 33
WINDOW_SLOTS = range(320, 329)

#: Reinforcement / amplification fame, level 1..15, probe-derived: `(0,2)` was
#: read after stepping a row's `reinforcement`/`amplify_type` through the
#: levels, one item per column.  Past 15 it grows by the slope -- +16/+17/+20
#: probes on both a weapon and an armor pinned the four numbers.
REINFORCED: dict[str, tuple[int, ...]] = {
    "weapon": (0, 12, 23, 35, 46, 57, 69, 80, 137, 154, 216, 425, 682, 738,
               795, 852),
    "other": (0, 4, 8, 11, 15, 19, 22, 26, 44, 50, 70, 137, 219, 237, 255,
              274),
    "amp_weapon": (0, 13, 26, 38, 51, 64, 76, 89, 152, 171, 240, 472, 757,
                   820, 883, 947),
    "amp_other": (0, 5, 9, 13, 17, 21, 25, 29, 49, 55, 77, 152, 243, 263,
                  284, 304),
}
SLOPE = {"weapon": 57, "other": 18, "amp_weapon": 63, "amp_other": 20}


@dataclass(frozen=True, slots=True)
class _Catalogue:
    """The three content tables, held as read: `fame_content` keys stay str."""

    fame: dict[str, int]
    upgrades: dict[str, list[int]]
    equipment: dict[str, int]
    divine_weapons: frozenset[int]
    levels: tuple[tuple[int, int], ...]
    growth_fame: tuple[tuple[int, int], ...]
    divine_levels: tuple[tuple[int, int], ...]
    divine_fame: tuple[tuple[int, int], ...]
    divine_limit: int
    divine_weapon_limit: int
    talismans: frozenset[int]


@functools.lru_cache(maxsize=1)
def _catalogue() -> _Catalogue:
    content = load("fame_content")
    growth = load("option_growth")
    talisman = load("talisman_content")
    return _Catalogue(
        fame=content["items"],
        upgrades=content["upgrades"],
        equipment=growth["equipment"],
        divine_weapons=frozenset(growth["divineWeapons"]),
        levels=tuple(map(tuple, growth["levels"])),
        growth_fame=tuple(map(tuple, growth["fame"])),
        divine_levels=tuple(map(tuple, growth["divineLevels"])),
        divine_fame=tuple(map(tuple, growth["divineFame"])),
        divine_limit=int(growth["divineLimit"]),
        divine_weapon_limit=int(growth["divineWeaponLimit"]),
        talismans=frozenset(int(item_id) for item_id, row in
                            talisman["items"].items() if row[0] == 0))


def _weapon(item_id: int, catalogue: _Catalogue) -> bool:
    upgrade = catalogue.upgrades.get(str(item_id))
    return bool(upgrade) and upgrade[2] == 1


def _level_for(ladder: tuple[tuple[int, int], ...], value: int) -> int:
    """The highest level whose threshold `value` reaches, or 0 for none."""
    level = 0
    for entry_level, threshold in ladder:
        if value >= threshold:
            level = entry_level
        else:
            break
    return level


def _fame_for(ladder: tuple[tuple[int, int], ...], level: int) -> int:
    for entry_level, fame in ladder:
        if entry_level == level:
            return fame
    return 0


def _growth_fame(item_id: int, growth: int, catalogue: _Catalogue) -> int:
    if not growth or str(item_id) not in catalogue.equipment:
        return 0
    if item_id in catalogue.divine_weapons or catalogue.equipment[str(item_id)] == 110:
        level = _level_for(catalogue.divine_levels, growth)
        if not level:
            return 0
        limit = (catalogue.divine_weapon_limit if _weapon(item_id, catalogue)
                 else catalogue.divine_limit)
        capped = _level_for(catalogue.divine_levels, limit)
        return _fame_for(catalogue.divine_fame, min(level, capped))
    return _fame_for(catalogue.growth_fame,
                     _level_for(catalogue.levels, growth))


def _socket_fame(blob: bytes | None, catalogue: _Catalogue) -> int:
    if not blob:
        return 0
    return sum(catalogue.fame.get(
        str(struct.unpack_from("<I", blob, off + 2)[0]), 0)
        for off in range(0, len(blob) - 5, 6))


def _reinforcement_fame(row: items.ItemStack, catalogue: _Catalogue) -> int:
    if not row.reinforcement or str(row.item_id) not in catalogue.upgrades:
        return 0
    column = ("amp_" if row.amplify_type else "") + \
        ("weapon" if _weapon(row.item_id, catalogue) else "other")
    table = REINFORCED[column]
    if row.reinforcement <= 15:
        return table[row.reinforcement]
    return table[15] + (row.reinforcement - 15) * SLOPE[column]


def compute(conn: sqlite3.Connection, character_id: int) -> int:
    """The character's fame, as the reference stamps it."""
    catalogue = _catalogue()
    rows = [items.ItemStack.from_row(row) for row in conn.execute(
        f'select {", ".join(items.COLUMNS)} from character_items '
        "where character_id = ? and list_type in (?, ?) "
        "order by list_type, slot_index",
        (character_id, EQUIPMENT_LIST, WINDOW_LIST)).fetchall()]
    window_open = any(row.list_type == EQUIPMENT_LIST
                      and row.slot_index == TALISMAN_SLOT
                      and row.item_id in catalogue.talismans for row in rows)
    total = 0
    for row in rows:
        if row.list_type == EQUIPMENT_LIST:
            if row.slot_index in SKIPPED_SLOTS:
                continue
        elif not (window_open and row.slot_index in WINDOW_SLOTS):
            continue
        total += catalogue.fame.get(str(row.item_id), 0)
        if row.enchant_card_id:
            total += catalogue.fame.get(str(row.enchant_card_id), 0)
        total += _socket_fame(row.avatar_sockets, catalogue)
        total += _growth_fame(row.item_id, row.growth_experience or 0, catalogue)
        total += _reinforcement_fame(row, catalogue)
    return total
