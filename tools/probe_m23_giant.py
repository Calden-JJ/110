#!/usr/bin/env python3
"""Perturb the save, replay one town entry at the reference, diff its giant.

M2.3's subtype-1 `(0,2)` is 4.5KB, and most of it is derived state: the header
carries a 105B character block (`[240:345)`) full of values that appear in no
save column, and the record tail lists nine `list_type=43` items.  Rather than
guess what feeds them, this tool changes *one* thing in the save per round,
has the reference rebuild the giant, and reports which bytes moved -- a
column-to-offset map with no decoding involved.

The reference is expected to be already running with its per-user `server.json`
pointing `diagnostics.logDirectory` at a fresh file (and `packetHexMaxBytes`
>= 8192, or the giant arrives truncated).  Each round:

    apply SQL -> replay the corpus session -> read the newest subtype-1 `(0,2)`
    off the log -> undo the SQL

Undo is SQL, never a file copy: the reference holds the save open in WAL mode,
so its `-wal`/`-shm` files cannot be replaced underneath it.  Restore the
`uslocalserver.db` set *before* the reference starts (M2.0 hygiene) instead.

The corpus is the 09-26 capture, whose session drives character slot 0 through
the town entry; that is where the giant is sent, so no move needs injecting.

    python tools/probe_m23_giant.py --baseline-only
    python tools/probe_m23_giant.py --only level_plus1 --only exp_plus1
    python tools/probe_m23_giant.py                 # every round
"""
from __future__ import annotations

import argparse
import asyncio
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_m2_item_move import capture_frames, exchange  # noqa: E402

CORPUS = paths.LOGS_DIR / "server-20260926.log"
OUT_DIR = paths.REPO_ROOT / "_m23" / "probe"
CHAR = 1

#: The columns `--set` is allowed to move, with the values the restored save
#: holds; the undo writes these back, so a round never has to remember them.
BASELINE_COLUMNS = {"level": 110, "grow_type": 5, "sub_grow_type": 3,
                    "class_id": 11, "favorite_position": 1, "town_state": 5,
                    "bonus_sp": 0, "bonus_tp": 0, "slot_index": 0, "account_id": 0,
                    "town_id": 38, "area_id": 1, "position_x": 450, "position_y": 210,
                    "pending_tutorial_dungeon_id": 0}


#: The pet bag's nine rows (rowid, slot, item, updated_at) -- `bag_del_all`
#: has to be able to put the save back exactly.
_BAG_ROWS = ((878, 320, 10617119, 1790327366), (873, 321, 10617135, 1790327350),
             (875, 322, 10617127, 1790327355), (879, 323, 10617119, 1790327367),
             (876, 324, 10617127, 1790327357), (872, 325, 10617135, 1790327348),
             (871, 326, 10617135, 1790327346), (874, 327, 10617127, 1790327353),
             (877, 328, 10617119, 1790327364))

_BAG_RESTORE = tuple(
    f"insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
    f"durability,instance_value,updated_at) values ({rid},1,43,{slot},{iid},1,0,0,{ts})"
    for rid, slot, iid, ts in _BAG_ROWS)

#: char1's other eleven list-43 rows (rowid, slot, item, updated_at): slots
#: 1..8 and 80..82, the ones the bag array never shows.
_OTHER_L43 = ((847, 1, 400400022), (848, 2, 400400022), (849, 3, 400400022),
              (850, 4, 400400022), (851, 5, 400400022), (852, 6, 400400022),
              (853, 7, 400400022), (854, 8, 400400022), (859, 80, 10617131),
              (860, 81, 10617131), (861, 82, 10617131))

_L43_RESTORE = tuple(
    f"insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
    f"durability,instance_value,updated_at) values ({rid},1,43,{slot},{iid},1,0,0,1790327181)"
    for rid, slot, iid in _OTHER_L43)

#: char1's three list-7 rows (rowid, slot, item): two creatures and one pet
#: item at the far slot 143.
_L7_ROWS = ((543, 0, 500990882), (807, 1, 500990902), (571, 143, 500950023))

_L7_RESTORE = tuple(
    f"insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
    f"durability,instance_value,updated_at) values ({rid},1,7,{slot},{iid},1,0,0,1790327181)"
    for rid, slot, iid in _L7_ROWS)

#: The row the reference itself installed for char2 at (43, 80) during the
#: `c2_petitem_in_inv` session; rounds that wipe char2's list 43 put it back.
_C2_SEED_RESTORE = (
    "insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
    "durability,instance_value,updated_at) values (1221,2,43,80,10617119,1,0,0,1790503228)",)

#: The eleven list-3 rows carrying reinforcement 13 + amplify 3/7 (char1's
#: "mythic" set): slots and their per-row extras, for exact undos.
_MYTHIC = (12, 15, 16, 17, 18, 19, 20, 21, 22, 23, 25)
_MYTHIC_ENCH = {12: 10349087, 15: 10349108, 16: 10349073, 17: 10349071,
                18: 10349105, 19: 10349042, 20: 10349054, 21: 10349110,
                22: 10349080, 23: 10349078, 25: 10349062}
_MYTHIC_GROWTH = {12: 2808799, 15: 228534, 16: 29269, 17: 69194, 18: 1222000,
                  19: 9769, 20: 3767, 21: 17305, 23: 407, 25: 528}

#: (slot, avatar_sockets hex) for the eleven socketed rows; the undo restores
#: the exact 35-byte blob.
_MYTHIC_SOCKS = (
    (0, "01005F94352301005F94352300000000000000000000000000000000000000000000"),
    (1, "01005F94352301005F94352300000000000000000000000000000000000000000000"),
    (2, "02006794352302006794352300000000000000000000000000000000000000000000"),
    (3, "10008193352304006994352304006994352300000000000000000000000000000000"),
    (4, "10008193352304006994352304006994352300000000000000000000000000000000"),
    (5, "08006F94352308006F94352300000000000000000000000000000000000000000000"),
    (6, "02006794352302006794352300000000000000000000000000000000000000000000"),
    (7, "08006F94352308006F94352300000000000000000000000000000000000000000000"),
    (8, "EFFFCD923523EFFFCD92352300000000000000000000000000000000000000000000"),
    (9, "100081933523EFFF5F943523EFFF6994352300000000000000000000000000000000"),
    (10, "EFFF67943523EFFF6794352300000000000000000000000000000000000000000000"),
)

_CREATURES = ((1, 500990888), (2, 500990882), (3, 500990783), (4, 500990902))

_CREATURE_RESTORE = tuple(
    f"insert into character_creatures (rowid,creature_id,character_id,item_id,satiety,"
    f"level,experience,name) values ({cid},{cid},1,{iid},100,1,0,'')"
    for cid, iid in _CREATURES)


@dataclass(frozen=True)
class Round:
    name: str
    sql: tuple[str, ...]
    #: SQL that puts the save back.  Rows re-created after a delete carry their
    #: original `rowid` explicitly, so the revert is byte-exact for the columns
    #: that matter (`updated_at` is left alone; the reference rewrites it).
    undo: tuple[str, ...] = ()
    note: str = ""


#: One thing at a time.  The character block is the target; the list-43 rows
#: probe the record tail's selection rule; the rest are controls (name, town,
#: position) that a header-only structure should ignore.
ROUNDS: tuple[Round, ...] = (
    Round("level_minus1", (f"update characters set level = level - 1 where character_id={CHAR}",),
          (f"update characters set level = level + 1 where character_id={CHAR}",),
          "does the stat-ish block follow level? (110 is the CHECK ceiling)"),
    Round("exp_plus1", (f"update characters set experience = experience + 12345 where character_id={CHAR}",),
          (f"update characters set experience = experience - 12345 where character_id={CHAR}",),
          "known: exp u64 at [242]"),
    Round("class_plus1", (f"update characters set class_id = class_id + 1 where character_id={CHAR}",),
          (f"update characters set class_id = class_id - 1 where character_id={CHAR}",),
          "known: class u32 at [316]; do stats follow the job?"),
    Round("ex_equip_plus1", (f"update characters set ex_equip_slot_flags = ex_equip_slot_flags + 1 where character_id={CHAR}",),
          (f"update characters set ex_equip_slot_flags = ex_equip_slot_flags - 1 where character_id={CHAR}",),
          "known: byte at [343]"),
    Round("grow_swap", (f"update characters set grow_type = 6, sub_grow_type = 4 where character_id={CHAR}",),
          (f"update characters set grow_type = 5, sub_grow_type = 3 where character_id={CHAR}",),
          "1st/2nd awakening -- stat multipliers?"),
    Round("bonus_sp_tp", (f"update characters set bonus_sp = 5, bonus_tp = 7 where character_id={CHAR}",),
          (f"update characters set bonus_sp = 0, bonus_tp = 0 where character_id={CHAR}",),
          "spare columns, in case anything reads them"),
    Round("name", (f"update characters set name = 'ZRenYing' where character_id={CHAR}",),
          (f"update characters set name = 'XRenYing' where character_id={CHAR}",),
          "control: the giant has no name (`XRenYing` is absent)"),
    Round("town_plus1", (f"update characters set town_id = town_id + 1 where character_id={CHAR}",),
          (f"update characters set town_id = town_id - 1 where character_id={CHAR}",),
          "control: header should ignore location"),
    Round("pos_plus1", (f"update characters set position_x = position_x + 1 where character_id={CHAR}",),
          (f"update characters set position_x = position_x - 1 where character_id={CHAR}",),
          "control"),
    Round("lv110_item_dur", (f"update character_items set durability = 123 where character_id={CHAR} and list_type=3 and slot_index=19",),
          (f"update character_items set durability = 0 where character_id={CHAR} and list_type=3 and slot_index=19",),
          "record field check: dur at record[10]"),
    Round("lv110_item_iv", (f"update character_items set instance_value = 4242 where character_id={CHAR} and list_type=3 and slot_index=19",),
          (f"update character_items set instance_value = 2111652581 where character_id={CHAR} and list_type=3 and slot_index=19",),
          "record field check: iv u32 at record[5]"),
    Round("list43_del328",
          (f"delete from character_items where character_id={CHAR} and list_type=43 and slot_index=328",),
          (f"insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
           f"durability,instance_value,updated_at) values (877,{CHAR},43,328,10617119,1,0,0,"
           f"(select updated_at from characters where character_id={CHAR}))",),
          "tail count 9 -> 8?"),
    Round("list43_move320", (f"update character_items set slot_index = 330 where character_id={CHAR} and list_type=43 and slot_index=320",),
          (f"update character_items set slot_index = 320 where character_id={CHAR} and list_type=43 and slot_index=330",),
          "is the tail a slot range (320..) or something else?"),
    Round("list43_move80", (f"update character_items set slot_index = 331 where character_id={CHAR} and list_type=43 and slot_index=80",),
          (f"update character_items set slot_index = 80 where character_id={CHAR} and list_type=43 and slot_index=331",),
          "does a sub-320 slot promote into the tail when moved up?"),
    Round("list43_item_swap", (f"update character_items set item_id = 10617135 where character_id={CHAR} and list_type=43 and slot_index=320",),
          (f"update character_items set item_id = 10617119 where character_id={CHAR} and list_type=43 and slot_index=320",),
          "tail carries item ids, not slots"),
    Round("wit_plus1", (f"update character_items set instance_value = 9 where character_id={CHAR} and list_type=43 and slot_index=321",),
          (f"update character_items set instance_value = 0 where character_id={CHAR} and list_type=43 and slot_index=321",),
          "does the tail carry anything but the id?"),
    Round("equip_add_slot11",
          (f"insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           f"instance_value,updated_at) values ({CHAR},3,11,100301594,1,7,555,0)",),
          (f"delete from character_items where character_id={CHAR} and list_type=3 and slot_index=11",),
          "an emptied equipment slot: record family + position"),
    Round("ro_on_s13",
          (f"update character_items set random_options = X'0f0c55000000000000' where character_id={CHAR} "
           f"and list_type=3 and slot_index=13",),
          (f"update character_items set random_options = X'' where character_id={CHAR} "
           f"and list_type=3 and slot_index=13",),
          "9B random_options on a 104 block: does the 5-byte field appear?"),
    Round("growth_on_s13",
          (f"update character_items set growth_experience = 12345 where character_id={CHAR} "
           f"and list_type=3 and slot_index=13",),
          (f"update character_items set growth_experience = 0 where character_id={CHAR} "
           f"and list_type=3 and slot_index=13",),
          "growth>0 on a 104 block: does the 54-byte section appear?"),
    Round("ro_growth_s13",
          (f"update character_items set random_options = X'0f0c55000000000000', growth_experience = 12345 "
           f"where character_id={CHAR} and list_type=3 and slot_index=13",),
          (f"update character_items set random_options = X'', growth_experience = 0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=13",),
          "both: 104 -> 109+54?"),
    #: char2 rounds (run with --slot 1): the only items with the 5-byte field and
    #: growth=0 live there.
    Round("ro_clear_c2s15",
          ("update character_items set random_options = X'' where character_id=2 "
           "and list_type=3 and slot_index=15",),
          ("update character_items set random_options = X'500107000000000000' where character_id=2 "
           "and list_type=3 and slot_index=15",),
          "clear ro on char2 s15 (109 block): does the 5-byte field disappear?"),
    Round("growth_on_c2s15",
          ("update character_items set growth_experience = 12345 where character_id=2 "
           "and list_type=3 and slot_index=15",),
          ("update character_items set growth_experience = 0 where character_id=2 "
           "and list_type=3 and slot_index=15",),
          "growth>0 on a char2 109 block: 163?"),
    Round("ro_variant_s13",
          (f"update character_items set random_options = X'aabbccdd1122334455' where character_id={CHAR} "
           f"and list_type=3 and slot_index=13",),
          (f"update character_items set random_options = X'' where character_id={CHAR} "
           f"and list_type=3 and slot_index=13",),
          "which ro bytes reach the wire (9B blob: u32 + 5)?"),
    Round("ro_variant_growth_s13",
          (f"update character_items set random_options = X'aabbccdd1122334455', growth_experience = 12345 "
           f"where character_id={CHAR} and list_type=3 and slot_index=13",),
          (f"update character_items set random_options = X'', growth_experience = 0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=13",),
          "does the 04 marker move with the variant ro?"),
    Round("zero_growth_c1s12",
          (f"update character_items set growth_experience = 0 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          (f"update character_items set growth_experience = 2808799 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          "type-10 weapon with growth 0: does the 54B section stay?"),
    Round("insert_weapon_s11",
          (f"insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           f"instance_value,updated_at) values ({CHAR},3,11,102040184,1,48,573753456,0)",),
          (f"delete from character_items where character_id={CHAR} and list_type=3 and slot_index=11",),
          "type-10 weapon, growth 0: section forced by the item?"),
    Round("insert_t27_s11",
          (f"insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           f"instance_value,updated_at) values ({CHAR},3,11,100313283,1,0,1588635579,0)",),
          (f"delete from character_items where character_id={CHAR} and list_type=3 and slot_index=11",),
          "type-27 epic, growth 0: section absent?"),
    Round("ro_hole_s13",
          (f"update character_items set random_options = X'aabbcc000000112233' where character_id={CHAR} "
           f"and list_type=3 and slot_index=13",),
          (f"update character_items set random_options = X'' where character_id={CHAR} "
           f"and list_type=3 and slot_index=13",),
          "zero 3-byte chunk in the middle: prefix rule or all non-zero?"),
    Round("ins_weapon_nogroup_ro_s14",
          (f"insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           f"instance_value,random_options,updated_at) values ({CHAR},3,14,101011250,1,45,175501053,"
           f"X'0f0c55000000000000',0)",),
          (f"delete from character_items where character_id={CHAR} and list_type=3 and slot_index=14",),
          "type-10 weapon NOT in 033, ro set, slot 14: section by type or by slot?"),
    Round("ins_weapon_033_ro_s14",
          (f"insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           f"instance_value,random_options,updated_at) values ({CHAR},3,14,102040184,1,48,573753456,"
           f"X'0f0c55000000000000',0)",),
          (f"delete from character_items where character_id={CHAR} and list_type=3 and slot_index=14",),
          "033 group-1000 weapon, ro set, slot 14: section needs slot 12?"),
    Round("bare_c1s12",
          (f"update character_items set growth_experience=0, enchant_card_id=0, amplify_type=0, "
           f"amplify_value=0, reinforcement=0 where character_id={CHAR} and list_type=3 and slot_index=12",),
          (f"update character_items set growth_experience=2808799, enchant_card_id=10349087, "
           f"amplify_type=3, amplify_value=7, reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          "slot 12, no state at all: section still there?"),
    Round("t24_on_s12",
          (f"update character_items set item_id=100345719, growth_experience=0 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          (f"update character_items set item_id=101011250, growth_experience=2808799 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          "slot 12 with a non-weapon: still sectioned?"),
    #: The version u16 equals char2's/char3's plain `sum(fame(item))` over the
    #: counted rows but char1 sits 16.5k above its own sum -- these rounds take
    #: each per-row extra away from every mythic row at once and read the delta.
    Round("zero_rein_all",
          (f"update character_items set reinforcement=0 where character_id={CHAR} "
           f"and list_type=3",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index in {_MYTHIC}",),
          "fame: every row's reinforcement contribution"),
    Round("zero_amp_all",
          (f"update character_items set amplify_type=0, amplify_value=0 "
           f"where character_id={CHAR} and list_type=3",),
          (f"update character_items set amplify_type=3, amplify_value=7 "
           f"where character_id={CHAR} and list_type=3 and slot_index in {_MYTHIC}",),
          "fame: every row's amplify contribution"),
    Round("zero_rein_s12",
          (f"update character_items set reinforcement=0 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          "fame: slot 12's reinforcement alone (the level-110 row)"),
    Round("zero_amp_s12",
          (f"update character_items set amplify_type=0, amplify_value=0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=12",),
          (f"update character_items set amplify_type=3, amplify_value=7 "
           f"where character_id={CHAR} and list_type=3 and slot_index=12",),
          "fame: slot 12's amplify alone"),
    Round("zero_ench_all",
          (f"update character_items set enchant_card_id=0 where character_id={CHAR} "
           f"and list_type=3",),
          tuple(f"update character_items set enchant_card_id={v} where "
                f"character_id={CHAR} and list_type=3 and slot_index={k}"
                for k, v in sorted(_MYTHIC_ENCH.items())),
          "fame: enchant-card fame, all rows"),
    Round("zero_growth_all",
          (f"update character_items set growth_experience=0 where character_id={CHAR} "
           f"and list_type=3",),
          tuple(f"update character_items set growth_experience={v} where "
                f"character_id={CHAR} and list_type=3 and slot_index={k}"
                for k, v in sorted(_MYTHIC_GROWTH.items())),
          "fame: growth/divine, thresholds only or fractional?"),
    Round("zero_sock_all",
          (f"update character_items set avatar_sockets=X'' where character_id={CHAR} "
           f"and list_type=3",),
          tuple(f"update character_items set avatar_sockets=X'{h}' where "
                f"character_id={CHAR} and list_type=3 and slot_index={s}"
                for s, h in _MYTHIC_SOCKS),
          "fame: avatar-socket emblems, 35B blobs"),
    Round("zero_ench_s12",
          (f"update character_items set enchant_card_id=0 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          (f"update character_items set enchant_card_id=10349087 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          "fame: slot 12's enchant alone (10349087)"),
    Round("zero_pair_s15",
          (f"update character_items set reinforcement=0, amplify_type=0, amplify_value=0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=15",),
          (f"update character_items set reinforcement=13, amplify_type=3, amplify_value=7 "
           f"where character_id={CHAR} and list_type=3 and slot_index=15",),
          "fame: one 105 row's rein+amp pair: additive 289 or 345?"),
    Round("zero_rein_s15",
          (f"update character_items set reinforcement=0 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          "fame: one 105 row's reinforcement alone"),
    Round("zero_amp_s15",
          (f"update character_items set amplify_type=0, amplify_value=0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=15",),
          (f"update character_items set amplify_type=3, amplify_value=7 "
           f"where character_id={CHAR} and list_type=3 and slot_index=15",),
          "fame: one 105 row's amplify alone"),
    Round("rein12_s12",
          (f"update character_items set reinforcement=12 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          "fame: +12 on the 110 weapon: 682 (shared table) or other?"),
    Round("rein12_s15",
          (f"update character_items set reinforcement=12 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          "fame: +12 on the 105 armor: expect 219 (amp on)"),
    Round("rein8_s15",
          (f"update character_items set reinforcement=8 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          "fame: +8 on the 105 armor: expect 49 (amp on)"),
    Round("rein8_s12_ampoff",
          (f"update character_items set reinforcement=8, amplify_type=0, amplify_value=0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=12",),
          (f"update character_items set reinforcement=13, amplify_type=3, amplify_value=7 "
           f"where character_id={CHAR} and list_type=3 and slot_index=12",),
          "fame: +8 no-amp on the 110 weapon: expect 137 (rein force table)"),
    Round("rein10_s12_ampoff",
          (f"update character_items set reinforcement=10, amplify_type=0, amplify_value=0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=12",),
          (f"update character_items set reinforcement=13, amplify_type=3, amplify_value=7 "
           f"where character_id={CHAR} and list_type=3 and slot_index=12",),
          "fame: +10 no-amp weapon: expect 216"),
    Round("rein11_s15",
          (f"update character_items set reinforcement=11 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          "fame: +11 amp armor: expect 152 (jump row)"),
    Round("rein16_s15",
          (f"update character_items set reinforcement=16 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          "fame: >15 clamp behavior (table has no +16 row)"),
    Round("rein17_s15",
          (f"update character_items set reinforcement=17 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=15",),
          "fame: +17 armor amp: slope past 15"),
    Round("rein20_s12",
          (f"update character_items set reinforcement=20 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          (f"update character_items set reinforcement=13 where character_id={CHAR} "
           f"and list_type=3 and slot_index=12",),
          "fame: +20 weapon amp: weapon slope past 15"),
    Round("rein16_s15_ampoff",
          (f"update character_items set reinforcement=16, amplify_type=0, amplify_value=0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=15",),
          (f"update character_items set reinforcement=13, amplify_type=3, amplify_value=7 "
           f"where character_id={CHAR} and list_type=3 and slot_index=15",),
          "fame: +16 armor no-amp: slope past 15"),
    Round("rein16_s12_ampoff",
          (f"update character_items set reinforcement=16, amplify_type=0, amplify_value=0 "
           f"where character_id={CHAR} and list_type=3 and slot_index=12",),
          (f"update character_items set reinforcement=13, amplify_type=3, amplify_value=7 "
           f"where character_id={CHAR} and list_type=3 and slot_index=12",),
          "fame: +16 weapon no-amp: slope past 15"),
    Round("swap_s32_item",
          (f"update character_items set item_id=400400019 where character_id={CHAR} "
           f"and list_type=3 and slot_index=32",),
          (f"update character_items set item_id=500990888 where character_id={CHAR} "
           f"and list_type=3 and slot_index=32",),
          "fame: is the 315-fame row at s32 counted (expect -130) or not (expect 0)?"),
    Round("creature_state_s26",
          (f"update character_creatures set satiety=33, level=7, experience=999 where creature_id=3",),
          (f"update character_creatures set satiety=100, level=1, experience=0 where creature_id=3",),
          "pet block +5 bytes: which creature fields land there?"),
    Round("creature_lv_pair",
          (f"update character_creatures set level=5 where creature_id=1",),
          (f"update character_creatures set level=1 where creature_id=1",),
          "tail ff 00 00 lvl 00: is 5 (creature_id 1) or 7 (creature_id 3) next?"),
    Round("bag_del_all",
          (f"delete from character_items where character_id={CHAR} and list_type=43 "
           f"and slot_index between 320 and 328",),
          _BAG_RESTORE,
          "empty bag: does the tail count 9 -> 0, and what do the nine ids read?"),
    Round("bag_ins329",
          (f"insert into character_items (character_id,list_type,slot_index,item_id,count,"
           f"durability,instance_value,updated_at) values ({CHAR},43,329,10617119,1,0,0,0)",),
          (f"delete from character_items where character_id={CHAR} and list_type=43 "
           f"and slot_index=329",),
          "a 10th bag slot: count 9 -> 10, or is 320..328 the whole array?"),
    Round("bag_ins330",
          (f"insert into character_items (character_id,list_type,slot_index,item_id,count,"
           f"durability,instance_value,updated_at) values ({CHAR},43,330,10617119,1,0,0,0)",),
          (f"delete from character_items where character_id={CHAR} and list_type=43 "
           f"and slot_index=330",),
          "a bag slot past 329: does the array extend?"),
    Round("bag_del_l43_all",
          (f"delete from character_items where character_id={CHAR} and list_type=43",),
          _BAG_RESTORE + _L43_RESTORE,
          "no list-43 rows at all: is the 9-slot array tied to their existence?"),
    Round("bag_c2_ins320",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,43,320,10617119,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=43 and slot_index=320",),
          "char2's first list-43 row: does its tail count 0 -> 9? (run with --slot 1)"),
    Round("c2_norev_probe",
          ("select 1",),
          (),
          "char2 unchanged, but the save now holds a stray (43,320) revision row "
          "from the bag_c2_ins320 session: does the array appear? (run with --slot 1)"),
    Round("bag_c2_rev_only",
          ("insert into gm_inventory_revisions (character_id,list_type,slot_index,revision) "
           "values (2,43,320,1)",),
          ("delete from gm_inventory_revisions where character_id=2 and list_type=43",),
          "char2, a revision row but no item: is the 9-slot array's existence "
          "recorded there? (run with --slot 1)"),
    Round("c2_plain_in_43",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,43,320,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=43 and slot_index=320",),
          "char2, a NON-pet item in list 43: list-based or item-type based? (--slot 1)"),
    Round("c2_petitem_in_inv",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,0,5,10617119,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=0 and slot_index=5",),
          "char2, a type-91 pet item in the plain inventory: does the array appear? (--slot 1)"),
    Round("pet_all_gone",
          (f"delete from character_items where character_id={CHAR} and list_type=43",
           f"delete from character_creatures where character_id={CHAR}"),
          _BAG_RESTORE + _L43_RESTORE + _CREATURE_RESTORE,
          "every pet row gone: is the 9-slot array a live read at all?"),
    Round("creature_s26_move30",
          (f"update character_items set slot_index=30 where character_id={CHAR} "
           f"and list_type=3 and slot_index=26",),
          (f"update character_items set slot_index=26 where character_id={CHAR} "
           f"and list_type=3 and slot_index=30",),
          "the worn creature moves off slot 26: does the tail's level follow the slot?"),
    Round("creature_del_all",
          (f"delete from character_creatures where character_id={CHAR}",),
          _CREATURE_RESTORE,
          "no creatures: tail count, the ff0000 lvl byte, and the worn +5"),
    Round("c1_del_l7_l43",
          (f"delete from character_items where character_id={CHAR} and list_type in (7,43)",),
          _L7_RESTORE + _BAG_RESTORE + _L43_RESTORE,
          "char1 with no list-7 and no list-43 rows at all: does the count 9 "
          "finally drop to 0, or is something outside character_items holding it up?"),
    Round("c2_del_seed",
          ("delete from character_items where character_id=2 and list_type=43",),
          _C2_SEED_RESTORE,
          "char2 with the reference-seeded (43,80) row removed: count 9 -> 0? (--slot 1)"),
    Round("c2_row_l4",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,4,0,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=4 and slot_index=0",),
          "char2, one row in list 4: does ANY non-inventory list flip the count? (--slot 1)"),
    Round("c2_row_l6",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,6,0,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=6 and slot_index=0",),
          "char2, one row in list 6: second sample for the list-type question (--slot 1)"),
    Round("c2_row_l2",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,2,0,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=2 and slot_index=0",),
          "char2, one row in list 2 (char1 has ten of these): gate or not? (--slot 1)"),
    Round("c2_row_l7",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,7,0,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=7 and slot_index=0",),
          "char2, one row in list 7: the char1-side candidate list (--slot 1)"),
    #: The rune array is present for char1 in every probed state and absent
    #: for char2 unless a list-43 row sits in 320..328.  char1 differs from
    #: char2 in level (110/55), ex_equip_slot_flags (59/0), awakening
    #: (5,3 / 4,1) and finished quest 21019 -- exactly the things the exe's
    #: `rejected: requires owned level110, finished quest21019 and fame34308`
    #: names.  One axis per round, then the conjunction.
    Round("c2_lv110",
          ("update characters set level = 110 where character_id=2",),
          ("update characters set level = 55 where character_id=2",),
          "char2 level 55 -> 110: does the rune array materialize? (--slot 1)"),
    Round("c2_flag59",
          ("update characters set ex_equip_slot_flags = 59 where character_id=2",),
          ("update characters set ex_equip_slot_flags = 0 where character_id=2",),
          "char2's ex-equip flags 0 -> char1's 59 (--slot 1)"),
    Round("c2_grow53",
          ("update characters set grow_type = 5, sub_grow_type = 3 where character_id=2",),
          ("update characters set grow_type = 4, sub_grow_type = 1 where character_id=2",),
          "char2 set to 2nd-awakening grow values (--slot 1)"),
    Round("c2_q21019",
          ("insert into character_finished_quests (character_id, quest_id, finished_at) "
           "values (2, 21019, 0)",),
          ("delete from character_finished_quests where character_id=2 and quest_id=21019",),
          "char2 finishes quest 21019 (--slot 1)"),
    Round("c2_lv110_q21019",
          ("update characters set level = 110 where character_id=2",
           "insert into character_finished_quests (character_id, quest_id, finished_at) "
           "values (2, 21019, 0)",),
          ("update characters set level = 55 where character_id=2",
           "delete from character_finished_quests where character_id=2 and quest_id=21019",),
          "level110 AND quest21019 (--slot 1)"),
    Round("c2_all",
          ("update characters set level = 110, ex_equip_slot_flags = 59, "
           "grow_type = 5, sub_grow_type = 3 where character_id=2",
           "insert into character_finished_quests (character_id, quest_id, finished_at) "
           "values (2, 21019, 0)",),
          ("update characters set level = 55, ex_equip_slot_flags = 0, "
           "grow_type = 4, sub_grow_type = 1 where character_id=2",
           "delete from character_finished_quests where character_id=2 and quest_id=21019",),
          "everything char1 has, given to char2 (--slot 1)"),
    Round("c1_lv55",
          (f"delete from character_items where character_id={CHAR} and list_type=43",
           f"update characters set level = 55 where character_id={CHAR}",),
          _BAG_RESTORE + _L43_RESTORE
          + (f"update characters set level = 110 where character_id={CHAR}",),
          "char1: zero list-43 rows and level 55 -- does the array vanish?"),
    Round("c1_flag0",
          (f"delete from character_items where character_id={CHAR} and list_type=43",
           f"update characters set ex_equip_slot_flags = 0 where character_id={CHAR}",),
          _BAG_RESTORE + _L43_RESTORE
          + (f"update characters set ex_equip_slot_flags = 59 where character_id={CHAR}",),
          "char1: zero rows and flags 0 -- does the array vanish?"),
    #: char1's worn trio at equipment slots 33/34/35 (400400019/400400022/
    #: 400400023) -- the only equipment char2 lacks entirely, and the exe has
    #: `IsTalismanSlot`/`TalismanEquipmentHandler`/`TalismanCatalog`.  If the
    #: rune array is the equipped talisman's slot table, dropping the item
    #: should drop the array.
    Round("c1_no34_only",
          (f"delete from character_items where character_id={CHAR} and list_type=43",
           f"delete from character_items where character_id={CHAR} and list_type=3 and slot_index=34",),
          _BAG_RESTORE + _L43_RESTORE + (
              "insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
              "durability,instance_value,updated_at) values (855,1,3,34,400400022,1,0,0,1790327186)",),
          "char1: no list-43 rows, equipment slot 34 emptied -- array vanishes?"),
    Round("c1_no_talismans",
          (f"delete from character_items where character_id={CHAR} and list_type=43",
           f"delete from character_items where character_id={CHAR} and list_type=3 "
           f"and slot_index in (33,34,35)",),
          _BAG_RESTORE + _L43_RESTORE + (
              "insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
              "durability,instance_value,updated_at) values (857,1,3,33,400400019,1,0,0,1790327234)",
              "insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
              "durability,instance_value,updated_at) values (855,1,3,34,400400022,1,0,0,1790327186)",
              "insert into character_items (rowid,character_id,list_type,slot_index,item_id,count,"
              "durability,instance_value,updated_at) values (858,1,3,35,400400023,1,0,0,1790327248)",),
          "char1: no rows and the whole 33/34/35 trio gone"),
    Round("c2_equip34",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,34,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=3 and slot_index=34",),
          "char2 equips the slot-34 item: array materializes? (--slot 1)"),
    Round("c2_equip_trio",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,33,400400019,1,0,0,0)",
           "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,34,400400022,1,0,0,0)",
           "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,35,400400023,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=3 and slot_index in (33,34,35)",),
          "char2 equips the whole trio (--slot 1)"),
    #: Disambiguate the trio: slot-based (worn row at 33/34/35) or
    #: item-based (a catalogue talisman item worn anywhere)?
    Round("c2_plain_at_34",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,34,100313283,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=3 and slot_index=34",),
          "char2, an epic weapon at slot 34: slot-based or item-based? (--slot 1)"),
    Round("c2_talisman_at_22",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,22,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=3 and slot_index=22",),
          "char2, the slot-34 item worn at normal slot 22 (--slot 1)"),
    Round("c2_talisman_at_33",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,33,400400019,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=3 and slot_index=33",),
          "char2, the 400400019 item at slot 33 (--slot 1)"),
    Round("c2_talisman_at_35",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,35,400400023,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=3 and slot_index=35",),
          "char2, the 400400023 item at slot 35 (--slot 1)"),
    Round("c2_at_32",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,32,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=3 and slot_index=32",),
          "char2, item one slot below the trio (slot 32) (--slot 1)"),
    Round("c2_at_36",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,36,400400022,1,0,0,0)",),
          ("delete from character_items where character_id=2 and list_type=3 and slot_index=36",),
          "char2, item one slot above the trio (slot 36): {33,34,35} or >=33? (--slot 1)"),
    Round("swap_s26_item",
          (f"update character_items set item_id=500950023 where character_id={CHAR} and list_type=3 "
           f"and slot_index=26",),
          (f"update character_items set item_id=500990783 where character_id={CHAR} and list_type=3 "
           f"and slot_index=26",),
          "non-creature item at slot 26: does the +5 vanish?"),
    #: char2's list-43 inserts (updated_at=0) never add fame while char1's live
    #: rows (real timestamps) do; these two rounds tell the column from a gate.
    Round("zero_ts_window",
          (f"update character_items set updated_at=0 where character_id={CHAR} "
           f"and list_type=43 and slot_index=328",),
          (f"update character_items set updated_at=1790327364 where character_id={CHAR} "
           f"and list_type=43 and slot_index=328",),
          "fame: window row with updated_at=0 (expect -46 if the fame read gates on it)"),
    Round("c2_row_ts",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,43,320,10617119,1,0,0,1790327366)",),
          ("delete from character_items where character_id=2 and list_type=43 and slot_index=320",),
          "fame: char2 window row with a REAL timestamp (expect +46 if ts was the blocker) (--slot 1)"),
    Round("c2_gate_row",
          ("update characters set level=110, ex_equip_slot_flags=59, grow_type=5, sub_grow_type=3 "
           "where character_id=2",
           "insert into character_finished_quests (character_id, quest_id, finished_at) "
           "values (2, 21019, 0)",
           "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,43,320,10617119,1,0,0,1790327366)",),
          ("update characters set level=55, ex_equip_slot_flags=0, grow_type=4, sub_grow_type=1 "
           "where character_id=2",
           "delete from character_finished_quests where character_id=2 and quest_id=21019",
           "delete from character_items where character_id=2 and list_type=43 and slot_index=320",),
          "fame: char2 given everything char1 has + the row (expect +46 if a state gate) (--slot 1)"),
    Round("swap_win_185",
          (f"update character_items set item_id=400400022 where character_id={CHAR} "
           f"and list_type=43 and slot_index=328",),
          (f"update character_items set item_id=10617119 where character_id={CHAR} "
           f"and list_type=43 and slot_index=328",),
          "fame: window row item 46 -> 185 (delta +139 = per-item, 0 = fixed, -46 = class-gated)"),
    Round("c2_ins321",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,43,321,10617119,1,0,0,1790327366)",),
          ("delete from character_items where character_id=2 and list_type=43 and slot_index=321",),
          "fame: is slot 320 alone dead, or the whole char2 window? (--slot 1)"),
    Round("c2_ins_two",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,43,320,10617119,1,0,0,1790327366)",
           "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,43,321,10617127,1,0,0,1790327367)",),
          ("delete from character_items where character_id=2 and list_type=43 and slot_index in (320,321)",),
          "fame: two char2 window rows: 0, +46 or +92? (--slot 1)"),
    Round("c2_copy_all_l43",
          ("insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,random_options,avatar_sockets,clone_appearance_id,reinforcement,refinement,"
           "fusion_item,bakal_state,transferred_option_mask,enchant_card_id,enchant_upgrade,mist_imbued,"
           "updated_at,expires_at,custom_option_ids,growth_experience,amplify_type,amplify_value) "
           "select 2,list_type,slot_index,item_id,count,durability,instance_value,random_options,"
           "avatar_sockets,clone_appearance_id,reinforcement,refinement,fusion_item,bakal_state,"
           "transferred_option_mask,enchant_card_id,enchant_upgrade,mist_imbued,updated_at,expires_at,"
           "custom_option_ids,growth_experience,amplify_type,amplify_value "
           "from character_items where character_id=1 and list_type=43",),
          ("delete from character_items where character_id=2 and list_type=43",),
          "fame: char2 with char1's whole list-43 set verbatim (811 = char gate, 1225 = row-structure) "
          "(--slot 1)"),
    Round("c1_del_q21019",
          (f"delete from character_finished_quests where character_id={CHAR} and quest_id=21019",),
          (f"insert into character_finished_quests (character_id,quest_id,finished_at) "
           f"values ({CHAR},21019,1790309158)",),
          "fame: does removing quest 21019 un-latch char1's rune-window fame?"),
)

_C2_L3_RESTORE = tuple(
    ln for ln in (Path(__file__).resolve().parents[1] / "_m23" / "c2_l3_restore.sql")
    .read_text(encoding="utf-8").splitlines() if ln.strip())

ROUNDS += (
    Round("c2_promote",
          ("update characters set level=110 where character_id=2",
           "insert into character_finished_quests (character_id,quest_id,finished_at) "
           "values (2,21019,1790309158)",
           "delete from character_items where character_id=2 and list_type=3",
           "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,random_options,avatar_sockets,clone_appearance_id,reinforcement,refinement,"
           "fusion_item,bakal_state,transferred_option_mask,enchant_card_id,enchant_upgrade,mist_imbued,"
           "updated_at,expires_at,custom_option_ids,growth_experience,amplify_type,amplify_value) "
           "select 2,list_type,slot_index,item_id,count,durability,instance_value,random_options,"
           "avatar_sockets,clone_appearance_id,reinforcement,refinement,fusion_item,bakal_state,"
           "transferred_option_mask,enchant_card_id,enchant_upgrade,mist_imbued,updated_at,expires_at,"
           "custom_option_ids,growth_experience,amplify_type,amplify_value "
           "from character_items where character_id=1 and list_type=3 "
           "and slot_index <= 35 and slot_index <> 26",
           "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) select 2,43,slot_index,item_id,1,0,0,updated_at "
           "from character_items where character_id=1 and list_type=43 and slot_index between 320 and 328"),
          ("delete from character_items where character_id=2 and list_type=3",
           "update characters set level=55 where character_id=2",
           "delete from character_finished_quests where character_id=2 and quest_id=21019",
           "delete from character_items where character_id=2 and list_type=43") + _C2_L3_RESTORE,
          "fame: char2 promoted to the exe-string triple (level110 + quest21019 + char1 gear) with "
          "all 9 window rows: latent rune fame should appear (+414) (--slot 1)"),
)

_PROMOTE_SETUP = (
    "update characters set level=110 where character_id=2",
    "insert into character_finished_quests (character_id,quest_id,finished_at) "
    "values (2,21019,1790309158)",
    "delete from character_items where character_id=2 and list_type=3",
    "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
    "instance_value,random_options,avatar_sockets,clone_appearance_id,reinforcement,refinement,"
    "fusion_item,bakal_state,transferred_option_mask,enchant_card_id,enchant_upgrade,mist_imbued,"
    "updated_at,expires_at,custom_option_ids,growth_experience,amplify_type,amplify_value) "
    "select 2,list_type,slot_index,item_id,count,durability,instance_value,random_options,"
    "avatar_sockets,clone_appearance_id,reinforcement,refinement,fusion_item,bakal_state,"
    "transferred_option_mask,enchant_card_id,enchant_upgrade,mist_imbued,updated_at,expires_at,"
    "custom_option_ids,growth_experience,amplify_type,amplify_value "
    "from character_items where character_id=1 and list_type=3 "
    "and slot_index <= 35 and slot_index <> 26")

_PROMOTE_UNDO = (
    "delete from character_items where character_id=2 and list_type=3",
    "update characters set level=55 where character_id=2",
    "delete from character_finished_quests where character_id=2 and quest_id=21019",
    "delete from character_items where character_id=2 and list_type=43") + _C2_L3_RESTORE

_INS_ONE_WINDOW = (
    "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
    "instance_value,updated_at) values (2,43,320,10617119,1,0,0,1790327366)",)

ROUNDS += (
    Round("c2_promote_norow", _PROMOTE_SETUP, _PROMOTE_UNDO,
          "fame: promoted char2, zero window rows -> expect 33632 (control) (--slot 1)"),
    Round("c2_promote_one", _PROMOTE_SETUP + _INS_ONE_WINDOW, _PROMOTE_UNDO,
          "fame: promoted char2, one window row -> 33678 if fame-gated, 33632 if row-count-gated "
          "(--slot 1)"),
)


def _promote_setup(*filters: str) -> tuple[str, ...]:
    base = list(_PROMOTE_SETUP)
    copy = base.pop()
    where = " and ".join(filters)
    base.append(copy.replace("and slot_index <= 35 and slot_index <> 26", f"and {where}"))
    return tuple(base)


ROUNDS += (
    Round("c2_only_s12", _promote_setup("slot_index = 12") + _INS_ONE_WINDOW, _PROMOTE_UNDO,
          "fame: char2 with ONLY the minLvl-110 item + 1 window row: 3867 if 'owns level110', "
          "3821 if fame-gated (--slot 1)"),
    Round("c2_fam5677", _promote_setup("slot_index in (15,16)") + _INS_ONE_WINDOW, _PROMOTE_UNDO,
          "fame: char2 gear fame 5677 + 1 window row: 5723 if window counts (--slot 1)"),
    Round("c2_fam14142", _promote_setup("slot_index between 15 and 19") + _INS_ONE_WINDOW,
          _PROMOTE_UNDO,
          "fame: char2 gear fame 14142 + 1 window row: 14188 if window counts (--slot 1)"),
    Round("c2_manyrows", _promote_setup("slot_index in (0,1,2,3,4,5,6,7,8,9,10,12,13,27,28,29,33,34,35)")
          + _INS_ONE_WINDOW, _PROMOTE_UNDO,
          "fame: 19 low-fame rows (8621) + 1 window row: 8667 if row-count-gated, 8621 if "
          "fame>=T with T>14142 (--slot 1)"),
    Round("c2_fam25011", _promote_setup("slot_index between 15 and 25") + _INS_ONE_WINDOW,
          _PROMOTE_UNDO,
          "fame: 10 x 105-bracket rows (25011) + 1 window row: 25057 if fame-gated "
          "(T<=25011) (--slot 1)"),
    Round("c2_talismans_only", _promote_setup("slot_index in (33,34,35)") + _INS_ONE_WINDOW,
          _PROMOTE_UNDO,
          "fame: only the three slot-33..35 talismans (555) + 1 window row: 601 if the gate needs "
          "talismans, 555 if it needs >=19 rows (--slot 1)"),
    Round("c2_t33", _promote_setup("slot_index = 33") + _INS_ONE_WINDOW, _PROMOTE_UNDO,
          "fame: only slot 33 (185) + 1 window row: 231 if one talisman suffices (--slot 1)"),
    Round("c2_t35", _promote_setup("slot_index = 35") + _INS_ONE_WINDOW, _PROMOTE_UNDO,
          "fame: only slot 35 (185) + 1 window row: 231 if any single talisman suffices (--slot 1)"),
    Round("c2_t23at33",
          ("update characters set level=110 where character_id=2",
           "delete from character_items where character_id=2 and list_type=3",
           "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,33,400400023,1,0,0,1790327366)") + _INS_ONE_WINDOW,
          _PROMOTE_UNDO,
          "fame: 400400023 (dead at slot 35) moved to slot 33 + 1 window row: 231 = slot-based, "
          "185 = item-based (--slot 1)"),
    Round("c2_t34", _promote_setup("slot_index = 34") + _INS_ONE_WINDOW, _PROMOTE_UNDO,
          "fame: only slot 34 (400400022) + 1 window row: 231 if slot 34 also qualifies (--slot 1)"),
    Round("c2_rune33",
          ("update characters set level=110 where character_id=2",
           "delete from character_items where character_id=2 and list_type=3",
           "insert into character_items (character_id,list_type,slot_index,item_id,count,durability,"
           "instance_value,updated_at) values (2,3,33,10617119,1,0,0,1790327366)") + _INS_ONE_WINDOW,
          _PROMOTE_UNDO,
          "fame: a rune (10617119) instead of a talisman at slot 33 (46) + 1 window row: "
          "92 if the gate needs a talisman-class item, 46 if any item (--slot 1)"),
)


#: Per-row growth credit: zeroing one row's growth removes just that row's
#: section, so the per-row fame contribution can be read off one at a time.
ROUNDS += tuple(
    Round(f"growth_row_{slot}",
          (f"update character_items set growth_experience=0 where character_id={CHAR} "
           f"and list_type=3 and slot_index={slot}",),
          (f"update character_items set growth_experience={val} where character_id={CHAR} "
           f"and list_type=3 and slot_index={slot}",),
          f"fame: growth {val} on row {slot} alone")
    for slot, val in sorted(_MYTHIC_GROWTH.items()) if slot != 12)


def run_sql(save: Path, statements: tuple[str, ...]) -> None:
    db = sqlite3.connect(save)
    try:
        with db:
            for s in statements:
                db.execute(s)
    finally:
        db.close()


def newest_giant(log: Path, since: int) -> tuple[bytes | None, int]:
    """The last subtype-1 `(0,2)` the reference logged past `since`.

    Returns (plaintext body, last line number seen) so the caller can resume.
    """
    plain = None
    last = since
    for p in logs.iter_packets(log):
        if p.line_no <= since:
            continue
        last = max(last, p.line_no)
        if p.link != "game" or p.direction != "S->C" or p.hex is None:
            continue
        try:
            # S->C lines carry no opcode column (`raw=N sent hex=`), so the
            # frame itself has to be parsed before the filter can run.
            f = frame.parse(frame.Link.GAME_S2C, p.frame_bytes, strict=False,
                            expect_size=p.hex.full_size)
        except frame.ProtocolError:
            continue
        if (f.opcode.main, f.opcode.sub) != (0, 2):
            continue
        body = tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)
        if body and body[0] == 0x01:
            plain = body
    return plain, last


def first_diffs(a: bytes, b: bytes, limit: int = 12) -> list[str]:
    out = []
    if len(a) != len(b):
        out.append(f"length {len(a)} vs {len(b)}")
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            out.append(f"[{i}] {x:#04x}->{y:#04x}")
            if len(out) >= limit:
                out.append("...")
                break
    return out


def reselect(payloads: list[bytes], slot: int) -> list[bytes]:
    """The corpus's `(1,4)` with another selection slot in front (`plain[0]`)."""
    out = []
    for raw in payloads:
        f = frame.parse(frame.Link.GAME_C2S, raw)
        if (f.opcode.main, f.opcode.sub) == (1, 4):
            body = tiles.encrypt_body(tiles.algo_id(4), bytes([slot]) + bytes(15))
            raw = frame.build(frame.Link.GAME_C2S, f.opcode, body, seq=f.seq)
        out.append(raw)
    return out


async def session(host: str, port: int, corpus: Path, idle: float, gap: float,
                  slot: int = 0) -> int:
    payloads = capture_frames(corpus)
    if slot:
        payloads = reselect(payloads, slot)
    got = await exchange(host, port, payloads, idle, gap)
    return len(got)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="192.168.1.6")
    ap.add_argument("--port", type=int, default=10013)
    ap.add_argument("--corpus", type=Path, default=CORPUS)
    ap.add_argument("--save", type=Path, default=paths.SAVE_DB)
    ap.add_argument("--log", type=Path, required=True,
                    help="the reference's log file (logDirectory target)")
    ap.add_argument("--only", action="append", default=[], help="round name(s)")
    ap.add_argument("--set", action="append", default=[], metavar="K=V,...",
                    help="extra round setting character columns; the undo restores "
                         "the baseline value of each column named")
    ap.add_argument("--levels", default="",
                    help="extra rounds setting level to N, comma-separated "
                         "(the character block's stats are level-driven and "
                         "the curve is what the formula needs)")
    ap.add_argument("--slot", type=int, default=0,
                    help="character slot the corpus's (1,4) selects; 1 = the "
                         "second character (a second data point for otherwise "
                         "unexplained constants)")
    ap.add_argument("--idle", type=float, default=6.0)
    ap.add_argument("--send-gap", type=float, default=0.002)
    ap.add_argument("--baseline-only", action="store_true",
                    help="one unperturbed session, saved as _baseline.bin")
    args = ap.parse_args(argv)

    cands = sorted((paths.REPO_ROOT / "_backups").glob("uslocalserver-m23probe-*.db"))
    print(f"save {args.save}"
          + (f"\n(restored from {cands[-1].name}; the reference holds it open, so rounds"
             f"\n only ever undo with SQL)" if cands else ""))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rounds = [r for r in ROUNDS if not args.only or r.name in args.only]
    for n in (int(x) for x in args.levels.replace(" ", "").split(",") if x):
        rounds.append(Round(f"level{n}",
                            (f"update characters set level = {n} where character_id={CHAR}",),
                            (f"update characters set level = 110 where character_id={CHAR}",),
                            f"level {n}: the stat curve"))
    for spec in args.set:
        kv = dict(x.split("=") for x in spec.replace(" ", "").split(",") if x)
        name = "set_" + "_".join(f"{k}{v}" for k, v in kv.items())
        rounds.append(Round(
            name,
            (f"update characters set " + ", ".join(f"{k} = {int(v)}" for k, v in kv.items())
             + f" where character_id={CHAR}",),
            (f"update characters set " + ", ".join(f"{k} = {BASELINE_COLUMNS[k]}" for k in kv)
             + f" where character_id={CHAR}",),
            spec))

    scan = 0
    ok = 0
    for rnd in ([Round("baseline", (), (), "unperturbed")] if args.baseline_only else rounds):
        if rnd.sql:
            run_sql(args.save, rnd.sql)
        print(f"\n== {rnd.name}: {rnd.note}")
        try:
            n = asyncio.run(session(args.host, args.port, args.corpus, args.idle,
                                    args.send_gap, args.slot))
        finally:
            if rnd.undo:
                run_sql(args.save, rnd.undo)
        plain, scan = newest_giant(args.log, scan)
        if plain is None:
            print(f"   !! no subtype-1 (0,2) in the log past line {scan} ({n}B back)")
            continue
        out = OUT_DIR / f"{rnd.name}.bin"
        out.write_bytes(plain)
        ref = OUT_DIR / "_baseline.bin"
        if rnd.name == "baseline" or not ref.exists():
            ref.write_bytes(plain)
            print(f"   {len(plain)}B -> {out.name} (kept as baseline)")
            ok += 1
            continue
        base_plain = ref.read_bytes()
        diffs = first_diffs(base_plain, plain)
        if diffs:
            print(f"   {len(plain)}B -> {out.name}: " + "; ".join(diffs))
        else:
            print(f"   {len(plain)}B -> {out.name}: identical")
        ok += 1
    print(f"\n{ok}/{len(rounds) + (1 if args.baseline_only else 0)} round(s) captured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
