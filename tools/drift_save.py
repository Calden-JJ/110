"""Drift a copy of the live save, then run the suite against it.

The test suite reads the real save (`paths.SAVE_DB`) through `_save_copy()`,
so every assertion that pins a live value -- a row count, a level, a roster,
a fame total -- goes red the first time the user plays.  This tool makes that
class of coupling visible *before* a play-through does, by applying a
representative drift to a sandbox copy and running the suite off it:

    python tools/drift_save.py --sandbox _saveaudit
    DFO_SERVER_DIR=<repo>/_saveaudit/srv DFO_LOGS_DIR=<real Logs> \\
        python -m unittest discover -s tests     # run from tests/

Anything that fails is either a pinned expectation (fix it to derive from the
save) or a generator that does not survive drift (fix the generator).  The
audit on 2026-09-28 -- three rounds, ~30 tables, a 4th character -- found four
such tests; all four now derive.

`--sandbox` refuses to touch the live save; mutations are only ever applied to
the copy it makes.  Each round's mutations are independent and best-effort:
a table that has grown a column since this tool was written is skipped with a
`FAIL` line rather than aborting the round.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import paths  # noqa: E402

TS = 1_790_700_000


def _report(name: str, fn) -> None:
    try:
        fn()
    except Exception as e:                  # schema drift makes this expected
        print(f"  skip {name}: {type(e).__name__}: {e}")
    else:
        print(f"  ok   {name}")


def _columns(conn, table: str) -> list[str]:
    return [d[0] for d in conn.execute(f"SELECT * FROM {table} LIMIT 0").description]


def _clone_row(conn, table: str, where: str, **overrides):
    """Copy one row of `table` with `overrides`, then insert it."""
    cols = _columns(conn, table)
    row = conn.execute(f"SELECT * FROM {table} WHERE {where} LIMIT 1").fetchone()
    if row is None:
        raise LookupError(f"no row: {table} where {where}")
    vals = dict(zip(cols, row))
    vals.update(overrides)
    conn.execute(f"INSERT INTO {table} ({','.join(vals)}) "
                 f"VALUES ({','.join('?' * len(vals))})", list(vals.values()))


def play_round(conn: sqlite3.Connection) -> None:
    """What one dungeon session leaves behind: xp, flags, quests, loot."""
    def level_up():
        conn.execute("UPDATE characters SET level=8, experience=50000, "
                     "updated_at=? WHERE character_id=3", (TS,))

    def flags():
        conn.execute("INSERT INTO character_tutorial_flags VALUES (3, 36, ?)", (TS,))
        conn.execute("INSERT INTO character_tutorial_flags VALUES (1, 60, ?)", (TS,))

    def quests():
        conn.execute("INSERT INTO character_quests VALUES (3, 9999, ?)", (TS,))
        conn.execute("INSERT INTO character_finished_quests VALUES (3, 9999, ?)", (TS,))

    def cera():
        conn.execute("UPDATE accounts SET cera=cera-5575, updated_at=?", (TS,))

    def loot():
        _clone_row(conn, "character_items",
                   "character_id=1 AND list_type=0 AND slot_index=46",
                   character_id=3, slot_index=20, item_id=500330437, count=1,
                   updated_at=TS)

    def count_drift():
        conn.execute("UPDATE character_items SET count=count-1, updated_at=? "
                     "WHERE character_id=1 AND list_type=0 AND slot_index=1", (TS,))

    def equip():                          # reinforcement feeds the fame total
        conn.execute("UPDATE character_items SET reinforcement=14, updated_at=? "
                     "WHERE character_id=1 AND list_type=3 AND slot_index=12", (TS,))

    def revision():
        conn.execute("UPDATE gm_inventory_revisions SET revision=revision+1 "
                     "WHERE character_id=1 AND list_type=0 AND slot_index=0")

    def skill():
        conn.execute("INSERT INTO character_skills VALUES (3, 0, 1, 5, 0, ?)", (TS,))

    for name, fn in (("level_up", level_up), ("flags", flags), ("quests", quests),
                     ("cera", cera), ("loot", loot), ("count_drift", count_drift),
                     ("equip", equip), ("revision", revision), ("skill", skill)):
        _report(name, fn)


def surface_round(conn: sqlite3.Connection) -> None:
    """The rest of the play surface: travel, mail, cargo, settings, blobs."""
    def travel():
        conn.execute("UPDATE characters SET town_id=1, area_id=2, position_x=100, "
                     "position_y=200, updated_at=? WHERE character_id=2", (TS,))

    def story_digest():
        conn.execute("INSERT INTO character_story_digest VALUES (3, 8, ?)", (TS,))
        conn.execute("UPDATE character_story_digest SET last_level=56, updated_at=? "
                     "WHERE character_id=2", (TS,))

    def dungeon_admission():
        conn.execute("INSERT INTO character_dungeon_admissions "
                     "VALUES (3, 1234, '2026-W40', 'abcdef01')")

    def card_claim():
        conn.execute("INSERT INTO dungeon_card_claims VALUES (3, 'ffffffffffffffff')")

    def materials():
        conn.execute("UPDATE account_materials SET count=count+7, updated_at=? "
                     "WHERE rowid=(SELECT MIN(rowid) FROM account_materials)", (TS,))

    def previous_village():
        conn.execute("INSERT INTO character_previous_village "
                     "VALUES (3, 38, 1, 561, 234, 0)")

    def quest_progress():
        conn.execute("INSERT INTO character_quest_progress VALUES (3, 9999, 3, -1, 0)")

    def mail():
        nxt = conn.execute("SELECT MAX(mail_id)+1 FROM system_mail").fetchone()[0]
        _clone_row(conn, "system_mail", "character_id=1", mail_id=nxt, character_id=3,
                   request_key='k2', claimed=0, created_at=TS)

    def premium():
        conn.execute("UPDATE account_premium_contracts SET expires_at=expires_at+86400, "
                     "updated_at=? WHERE account_id=0", (TS,))

    def cargo():
        conn.execute("UPDATE account_cargo_state SET capacity=capacity+8")
        conn.execute("UPDATE character_cargo_state SET capacity=capacity+8 "
                     "WHERE character_id=3")
        conn.execute("UPDATE character_second_cargo_state SET capacity=capacity+8 "
                     "WHERE character_id=1")

    def expansions():
        conn.execute("INSERT INTO character_inventory_expansion VALUES (3, 8)")
        conn.execute("INSERT INTO account_character_capacity VALUES (0, 40, ?)", (TS,))

    def collectibles():
        conn.execute("INSERT INTO character_read_synopses VALUES (3, 5)")
        conn.execute("INSERT INTO character_wish_items VALUES (3, 0, 0, 500330437)")
        conn.execute("INSERT INTO character_buff_swap VALUES (3, 1)")
        conn.execute("INSERT INTO buff_swap_registrations VALUES (3, 0, 0, 0)")
        conn.execute("INSERT INTO character_cube_contract VALUES (3, 1)")
        conn.execute("INSERT INTO character_neo_rentals VALUES (3, 500330437, 100000, ?)",
                     (TS,))
        conn.execute("INSERT INTO character_bakal_admissions VALUES (3, ?, ?)",
                     ("a" * 32, TS))

    def creatures():
        conn.execute("UPDATE character_creatures SET satiety=50 WHERE character_id=1")

    def settings_blobs():
        # one byte past any header, so a blob's own length field stays honest
        q = conn.execute("SELECT payload FROM character_quickslots "
                         "WHERE character_id=1").fetchone()[0]
        conn.execute("UPDATE character_quickslots SET payload=?, updated_at=? "
                     "WHERE character_id=1",
                     (q[:100] + bytes([q[100] ^ 1]) + q[101:], TS))
        o = conn.execute("SELECT options FROM account_client_settings").fetchone()[0]
        conn.execute("UPDATE account_client_settings SET options=?",
                     (o[:4] + bytes([o[4] ^ 1]) + o[5:],))
        h = conn.execute("SELECT bindings FROM account_hotkeys").fetchone()[0]
        conn.execute("UPDATE account_hotkeys SET bindings=?",
                     (h[:2] + bytes([h[2] ^ 1]) + h[3:],))

    def dialogue():
        conn.execute("UPDATE account_dungeon_life_dialogue "
                     "SET progress=progress+1, updated_at=?", (TS,))

    def gm_log():
        conn.execute("INSERT INTO gm_operations VALUES ('r1', 'p', 'b', 'r', ?)", (TS,))

    for name, fn in (("travel", travel), ("story_digest", story_digest),
                     ("dungeon_admission", dungeon_admission),
                     ("card_claim", card_claim), ("materials", materials),
                     ("previous_village", previous_village),
                     ("quest_progress", quest_progress), ("mail", mail),
                     ("premium", premium), ("cargo", cargo),
                     ("expansions", expansions), ("collectibles", collectibles),
                     ("creatures", creatures), ("settings_blobs", settings_blobs),
                     ("dialogue", dialogue), ("gm_log", gm_log)):
        _report(name, fn)


def roster_round(conn: sqlite3.Connection) -> None:
    """A fourth character rolled on the select screen."""
    def new_character():
        slot = conn.execute("SELECT MAX(slot_index)+1 FROM characters "
                            "WHERE account_id=0").fetchone()[0]
        cid = conn.execute("SELECT next_character_id FROM character_id_allocator"
                           ).fetchone()[0]
        _clone_row(conn, "characters", "character_id=1", character_id=cid,
                   slot_index=slot, name='YNewChar', level=1, experience=0,
                   grow_type=0, sub_grow_type=0, created_at=TS, updated_at=TS,
                   favorite_position=slot + 1, pending_tutorial_dungeon_id=0)
        conn.execute("UPDATE character_id_allocator SET next_character_id=?",
                     (cid + 1,))
        conn.execute("INSERT INTO account_character_selection_slots "
                     "VALUES (0, ?, 0, 0, ?)", (slot, TS))

    _report("new_character", new_character)


ROUNDS = {"play": play_round, "surface": surface_round, "roster": roster_round}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sandbox", type=Path, default=Path("_saveaudit"),
                    help="directory to build (default: _saveaudit)")
    ap.add_argument("--round", choices=sorted(ROUNDS), action="append",
                    help="repeatable; default all three")
    args = ap.parse_args()

    srv = args.sandbox / "srv"
    srv.mkdir(parents=True, exist_ok=True)
    save = srv / paths.SAVE_DB.name
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(save) + suffix))
    exe = srv / paths.EXE.name
    if not exe.exists():
        os.link(paths.EXE, exe)             # 107 MB: link, never copy
    if save.resolve() == paths.SAVE_DB.resolve():
        raise SystemExit("refusing to drift the live save")

    conn = sqlite3.connect(save)
    conn.execute("PRAGMA foreign_keys=ON")
    for name in args.round or list(ROUNDS):
        print(f"{name}:")
        ROUNDS[name](conn)
    conn.commit()
    conn.close()
    print(f"\nnow run, from tests/:\n"
          f"  DFO_SERVER_DIR={srv.resolve()} DFO_LOGS_DIR={paths.LOGS_DIR.resolve()} "
          f"python -m unittest discover -s .")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
