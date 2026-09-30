"""What is actually in the 0.4.4 save?

The 0.3.6-era test fixtures were pinned to a played-in save (four characters,
235 item rows, 938 finished quests).  0.4.4 ships a nearly fresh one, so this
prints what a fixture rebuilt from it could rely on -- and what it could not.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from uslocalserver import paths                                     # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

layout = paths.for_version("0.4.4")
conn = sqlite3.connect(f"file:{layout.save_db.as_posix()}?mode=ro", uri=True)
conn.row_factory = sqlite3.Row

print(f"save {layout.save_db}")
print(f"  {layout.save_db.stat().st_size / 1e6:.1f} MB\n")

print("--- accounts ---")
for r in conn.execute("select * from accounts"):
    print(f"  {dict(r)}")

print("\n--- characters ---")
cols = [d[0] for d in conn.execute("select * from characters limit 1").description]
interesting = [c for c in cols if c in (
    "character_id", "account_id", "slot_index", "name", "class_id", "level",
    "grow_type", "town_id", "area_id", "town_state", "experience",
    "favorite_position", "created_at", "updated_at")]
for r in conn.execute("select * from characters"):
    d = {c: r[c] for c in interesting}
    print(f"  {d}")

print("\n--- per-character row counts ---")
for cid, in conn.execute("select character_id from characters"):
    print(f"  character {cid}:")
    for table in ("character_items", "character_skills", "character_quests",
                  "character_finished_quests", "character_quest_progress",
                  "character_tutorial_flags", "character_creatures",
                  "character_quickslots", "character_story_digest",
                  "character_inventory_expansion"):
        try:
            n = conn.execute(f"select count(*) from {table} where character_id=?",
                             (cid,)).fetchone()[0]
        except sqlite3.Error:
            continue
        if n:
            print(f"    {table:<34} {n}")

print("\n--- account material / settings ---")
for table in ("account_materials", "account_client_settings", "account_cargo_state",
              "account_hotkeys", "account_premium_contracts", "channels"):
    try:
        n = conn.execute(f"select count(*) from {table}").fetchone()[0]
        print(f"  {table:<34} {n}")
    except sqlite3.Error as exc:
        print(f"  {table:<34} ERR {exc}")

print("\n--- the items that exist ---")
for r in conn.execute("select character_id, list_type, slot_index, item_id, count "
                      "from character_items order by character_id, list_type, slot_index"):
    print(f"  c{r['character_id']} list={r['list_type']:<3} slot={r['slot_index']:<4} "
          f"item={r['item_id']:<12} n={r['count']}")
conn.close()
