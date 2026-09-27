"""The subtype-1 `(0,2)` USERINFO -- the giant *second* frame of a refresh.

Fitted 2026-09-27 against 101 probe bins (the rig in `tools/probe_m23_giant.py`
plus `_m23/giant_model.py`): header, character block, per-item blocks, tail and
padding reproduce 97 byte-exact.  The 4 that differ are reference-side
artifacts of out-of-band DB edits, not layout unknowns:

  * `equip_add_slot11` / `lv110_item_dur` -- the reference re-registers a row
    whose `durability` column moved under it, stamping a *fresh random*
    31-bit `instance_value` and `updated_at` on the next town entry; nothing
    on disk predicts it.  The block's `[5:9)` is a plain read of
    `instance_value or count`.
  * `creature_del_all` / `pet_all_gone` -- the +5 creature pad survives
    emptying `character_creatures`, so the reference holds that set in memory
    for its process lifetime; this module reads the table live, which is the
    behaviour a rewrite wants.

Body layout::

    0    8B   `01 01 00 01 0a 00 00 00`
    8-24 zeros
    24   u16  the same version the small USERINFO carries (see `refresh`)
    26-240 zeros
    240  105B character block
    345  ...  one block per worn row, slot order
    ...  tail
    ...  zeros up to ceil16(content_end + 12); the frame adds its 16B header

The character block is a stat fit over table 013: the wire value of a field is
`base + (lv-1)*row1` up to lv15 and `base + 14*row1 + (lv-15)*row(grow)` past
it, with `row` keyed by `grow_type % 6 + 1` (job 1 has five rows and the
modulo lands on "6", absent -> row "1").  `[2:10)` is `experience` floored at
the level's own `expTable` entry -- a level forced past the exp row shows the
floor, not the row's value.  The tail mirrors the rune container: a presence
flag, the list-43 item ids at slots 320..328 (`FF FF FF FF` for a gap), then
`FF 00 00 <lvl> 00` where `<lvl>` is the level of the creature whose item is
worn at slot 26 exactly (0 otherwise).

The record layout of the *small* USERINFO and the four things this module
cannot derive (the version function) are written up in `references/protocol.md`.
"""
from __future__ import annotations

import sqlite3
import struct

from ...persistence import items
from ...persistence.characters import CharacterSummary
from ..data import load

RUNE_LIST = 43
CREATURE_TABLE = "character_creatures"

PREFIX = bytes.fromhex("010100010a000000")
VERSION_AT = 24
CHAR_AT = 240
ITEMS_AT = 345
CHAR_SIZE = 105
HEAD_SIZE = 41
AVATAR_SIZE = 146
T_SIZE = 62
GROWTH_SIZE = 54
CREATURE_PAD = 5
GROW_SLOT = 12
RUNE_SLOTS = tuple(range(320, 329))
RUNE_TRIGGER = (33, 34, 35)
CREATURE_SLOT = 26
RUNE_EMPTY = 0xFFFFFFFF

#: field -> (body offset, width, signed) inside the 105B character block.
LAYOUT = (
    ("hp_max", 254, 4, False), ("mp_max", 258, 4, False),
    ("phys_atk", 262, 2, False), ("phys_def", 264, 2, False),
    ("mag_atk", 266, 2, False), ("mag_def", 268, 2, False),
    ("fire_res", 270, 2, True), ("water_res", 272, 2, True),
    ("dark_res", 274, 2, True), ("light_res", 276, 2, True),
    ("inventory_limit", 314, 4, False),
    ("mp_regen", 320, 2, False), ("move_speed", 322, 2, False),
    ("attack_speed", 326, 2, False), ("cast_speed", 328, 2, False),
    ("hit_recovery", 330, 2, False), ("jump_power", 332, 2, False),
    ("weight", 334, 4, False),
)
FORMAT = {(2, True): "<h", (2, False): "<H", (4, True): "<i", (4, False): "<I"}
#: The 62B section's constants once the block is grown (slot 12 or growth>0).
T_GROWTH = {10: 4, 18: 8, 31: 5, 40: 1, 45: 1, 50: 1, 59: 4}
#: The extra 54B section's constants; growth experience is a u32 at +32.
G_GROWTH = {5: 5, 15: 0x15, 41: 1, 46: 3}


def stat_wire(job_id: str, field: str, level: int, grow_type: int) -> int:
    job = load("character_stats")["jobs"][job_id]
    rows = job["growtype"]
    row1 = rows["1"][field]
    if level <= 15:
        return job["base"][field] + (level - 1) * row1
    row = rows.get(str(grow_type % 6 + 1), rows["1"])[field]
    return job["base"][field] + 14 * row1 + (level - 15) * row


def char_block(summary: CharacterSummary) -> bytes:
    """The 105B block at 240: id, exp, the table-013 stats, flags, worn count."""
    stats = load("character_stats")
    exp_table = stats["expTable"]
    floor = exp_table[summary.level - 2] if summary.level >= 2 else 0
    out = bytearray(CHAR_SIZE)
    struct.pack_into("<H", out, 0, summary.character_id)
    struct.pack_into("<Q", out, 2, max(summary.experience, floor))
    out[10] = 89
    job_id = str(summary.class_id)
    for field, off, width, signed in LAYOUT:
        struct.pack_into(FORMAT[(width, signed)], out, off - CHAR_AT,
                         stat_wire(job_id, field, summary.level,
                                   summary.grow_type))
    struct.pack_into("<I", out, 98, 100)
    out[103] = summary.ex_equip_slot_flags
    return bytes(out)


def random_option_chunks(blob: bytes | None) -> list[bytes]:
    """The stored random options as the 3B wire chunks, up to a zero chunk."""
    out = []
    for i in range(0, len(blob or b"") - 2, 3):
        chunk = blob[i:i + 3]
        if chunk == b"\0\0\0":
            break
        out.append(chunk)
    return out


def item_block(stack: items.ItemStack, creatures: frozenset[int]) -> bytes:
    """One worn row's block: 41B head, options, 62B section, growth, pad.

    An avatar item takes the 146B flat form instead -- its sockets at [40:70)
    and only the head's first 40 bytes before that.
    """
    head = bytearray(HEAD_SIZE)
    head[0] = stack.slot_index
    struct.pack_into("<I", head, 1, stack.item_id)
    head[9] = stack.reinforcement or 0
    head[10] = stack.durability or 0
    struct.pack_into("<I", head, 24, stack.clone_appearance_id or 0)
    struct.pack_into("<I", head, 28, stack.enchant_card_id or 0)
    head[32] = stack.enchant_upgrade or 0
    head[33] = stack.amplify_type or 0
    struct.pack_into("<H", head, 34, stack.amplify_value or 0)
    if stack.avatar_sockets:
        struct.pack_into("<I", head, 36, 30)
        out = bytes(head[:40]) + stack.avatar_sockets[:30] + struct.pack("<I", 4)
        return out + bytes(AVATAR_SIZE - len(out))
    struct.pack_into("<I", head, 5, stack.instance_value or stack.count or 0)
    chunks = random_option_chunks(stack.random_options)
    out = bytes(head) + bytes([len(chunks)])
    if chunks:
        out += b"".join(chunks) + b"\x00\xff"
    grown = stack.slot_index == GROW_SLOT or (stack.growth_experience or 0) > 0
    section = bytearray(T_SIZE)
    if grown:
        for off, value in T_GROWTH.items():
            section[off] = value
    out += bytes(section)
    if grown:
        growth = bytearray(GROWTH_SIZE)
        for off, value in G_GROWTH.items():
            growth[off] = value
        struct.pack_into("<I", growth, 32, stack.growth_experience or 0)
        out += bytes(growth)
    if stack.item_id in creatures:
        out += bytes(CREATURE_PAD)
    return out


def creature_levels(conn: sqlite3.Connection, character_id: int) -> dict[int, int]:
    """The character's creatures by their item id -- the pad's membership test
    and the tail's level byte both read this."""
    return {r["item_id"]: r["level"] or 0 for r in conn.execute(
        f"select item_id, level from {CREATURE_TABLE} where character_id = ?",
        (character_id,))}


def runes(conn: sqlite3.Connection, character_id: int) -> dict[int, int]:
    """The character's list-43 rows as item ids by slot -- the rune container
    plus wherever else it is parked; `tail` picks the array's own slots."""
    return {r["slot_index"]: r["item_id"] for r in conn.execute(
        f'select slot_index, item_id from "{items.TABLE}" '
        "where character_id = ? and list_type = ?", (character_id, RUNE_LIST))}


def tail(worn: list[items.ItemStack], levels: dict[int, int],
         rune_ids: dict[int, int]) -> bytes:
    """The rune array, when the character has one, then the creature byte.

    The array is present iff a rune row sits at one of its own nine slots *or*
    the worn set reaches into 33..35 -- the inventory slots the rune container
    overlaps -- and absent it is the same 29 bytes with a zero count.
    """
    rune_ids = {slot: item for slot, item in rune_ids.items() if slot in RUNE_SLOTS}
    triggered = bool(rune_ids) or any(
        stack.slot_index in RUNE_TRIGGER for stack in worn)
    out = struct.pack("<IB", 0, 9 if triggered else 0)
    if triggered:
        out += b"".join(struct.pack("<I", rune_ids.get(slot, RUNE_EMPTY))
                        for slot in RUNE_SLOTS)
    level = 0
    for stack in worn:
        if stack.slot_index == CREATURE_SLOT:
            level = levels.get(stack.item_id, 0)
    return out + bytes(19) + b"\xff\x00\x00" + bytes([level]) + b"\x00"


def body(summary: CharacterSummary, worn: list[items.ItemStack],
         levels: dict[int, int], rune_ids: dict[int, int],
         version: int) -> bytes:
    """The whole subtype-1 body; `version` is the small USERINFO's own value."""
    creatures = frozenset(levels)
    blocks = b"".join(item_block(stack, creatures) for stack in worn)
    rest = tail(worn, levels, rune_ids)
    content_end = ITEMS_AT + len(blocks) + len(rest)
    out = bytearray((content_end + 12 + 15) // 16 * 16)
    out[0:len(PREFIX)] = PREFIX
    struct.pack_into("<H", out, VERSION_AT, version)
    out[CHAR_AT:CHAR_AT + CHAR_SIZE] = char_block(summary)
    out[CHAR_AT + CHAR_SIZE - 1] = len(worn)
    out[ITEMS_AT:content_end] = blocks + rest
    return bytes(out)
