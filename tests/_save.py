"""Shared save fixture: the live reference save, copied, with enough characters.

Most gameplay tests do not care which character they exercise -- they seed the
rows they need and then assert on what the handler did.  What they *do* need is
for the `character_id` they name to exist, because `character_items`,
`character_quests` and a dozen other tables carry a foreign key to
`characters`.

That worked by accident on the 0.3.6 save, which had been played into and held
four characters with ids 1..4.  The 0.4.4 save ships with exactly one (`NGRY`,
id 1), so tests pinned to character 2 or 3 now fail before they start with
`FOREIGN KEY constraint failed` -- a fixture gap that looks like a code defect.

`fixture()` closes the gap without inventing data: it copies the save and, only
if the wanted ids are missing, clones the reference character's own rows under
the new id.  A clone is legitimate here because every one of these tests
overwrites the rows it reads; a test that genuinely depends on *which*
character it got should name `saves.character_id()` instead of hard-coding.
"""
from __future__ import annotations

import functools
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

import _bootstrap  # noqa: F401  (sys.path)

from uslocalserver import paths

#: Tables with a `character_id` column, discovered rather than listed, so a
#: release that adds one clones it too.  `characters` is handled separately.
_SKIP_TABLES = {"characters"}


#: Tables that carry a `character_id` but must NOT be cloned along with the
#: character.  These are per-*account* aggregates the server keeps in sync with
#: `characters` through triggers, so they are keyed on the account and a second
#: copy collides: `account_explorer_clears` is unique on
#: `(account_id, event_key)`, and the explorer tables are maintained by
#: `explorer_character_created` anyway.
_ACCOUNT_SCOPED = {
    "account_explorer",
    "account_explorer_capsules",
    "account_explorer_clears",
    "account_explorer_contributions",
    "account_explorer_earnings",
    "account_explorer_groups",
    "account_explorer_items",
    "account_explorer_login_rewards",
    "account_explorer_medal",
    "account_explorer_purchases",
    "account_explorer_wallet",
    "account_grief",
    "account_ruby_curse",
    "account_skins",
    "character_monster_collections",
    "character_monster_pieces",
    "character_watcher",
    "character_watcher_gauge",
    "recent_party_members",
}


def _character_owned_tables(conn: sqlite3.Connection) -> list[str]:
    """Tables whose rows belong to one character, per their own foreign keys.

    Discovered, not listed: a table qualifies when it declares a foreign key
    onto `characters`.  That is exactly the set SQLite will refuse an insert
    into for a character that does not exist, which is the set the fixture has
    to populate.
    """
    out = []
    for (name,) in conn.execute(
            "select name from sqlite_master where type='table' "
            "and name not like 'sqlite_%' order by name"):
        if name in _SKIP_TABLES or name in _ACCOUNT_SCOPED:
            continue
        fks = conn.execute(f'pragma foreign_key_list("{name}")').fetchall()
        if any(fk[2] == "characters" for fk in fks):
            out.append(name)
    return out


def reference_character(conn: sqlite3.Connection) -> int:
    """The character every other one is cloned from: the most-populated row."""
    row = conn.execute(
        "select c.character_id, count(i.character_id) as n "
        "from characters c left join character_items i "
        "  on i.character_id = c.character_id "
        "group by c.character_id order by n desc, c.character_id limit 1"
    ).fetchone()
    if row is None:
        raise RuntimeError(f"{paths.SAVE_DB} has no characters to clone from")
    return row[0]


def character_id(conn: sqlite3.Connection, *, slot: int | None = None) -> int:
    """A real character id from the save.

    With `slot`, the character the client would show at that select-screen
    slot; without it, the reference character.
    """
    if slot is None:
        return reference_character(conn)
    row = conn.execute(
        "select character_id from characters where slot_index = ? "
        "order by account_id limit 1", (slot,)).fetchone()
    if row is None:
        raise LookupError(f"no character at slot {slot} in {paths.SAVE_DB}")
    return row[0]


def _owner_column(conn: sqlite3.Connection, table: str) -> str | None:
    """The column in `table` that points at `characters.character_id`.

    Not always called `character_id`: `character_friends` names both ends
    (`character_id_a` / `character_id_b`) and has no plain one, and the
    creature/quest tables are inconsistent across releases.  The foreign key
    metadata already knows, so read it instead of guessing.
    """
    for fk in conn.execute(f'pragma foreign_key_list("{table}")'):
        if fk[2] == "characters" and fk[4] == "character_id":
            return fk[3]
    cols = {r[1] for r in conn.execute(f'pragma table_info("{table}")')}
    return "character_id" if "character_id" in cols else None


def clone_character(conn: sqlite3.Connection, source: int, target: int) -> None:
    """Duplicate `source`'s rows under `target`, inserting the parent last."""
    conn.execute("pragma foreign_keys=off")
    try:
        for table in _character_owned_tables(conn):
            owner = _owner_column(conn, table)
            if owner is None:
                continue                      # nothing to key the copy on
            cols = [r[1] for r in conn.execute(f'pragma table_info("{table}")')]
            others = [c for c in cols if c != owner]
            targets = ", ".join(f'"{c}"' for c in others)
            # A table with no columns beyond the owner is not worth copying.
            if not others:
                continue
            conn.execute(
                f'insert into "{table}" ("{owner}", {targets}) '
                f'select ?, {targets} from "{table}" where "{owner}" = ?',
                (target, source))
        # `characters` last: the children only need their parent once
        # enforcement comes back on, but a parent clone must not collide first.
        src = conn.execute("select * from characters where character_id = ?",
                           (source,)).fetchone()
        keys = [d[0] for d in conn.execute("select * from characters limit 1").description]
        values = dict(zip(keys, src))
        values["character_id"] = target
        if "slot_index" in values:
            values["slot_index"] = conn.execute(
                "select coalesce(max(slot_index), -1) + 1 from characters "
                "where account_id = ?", (values["account_id"],)).fetchone()[0]
        if "name" in values:
            base = str(values["name"])[:12]
            values["name"] = f"{base}{target}"[:20]
        if "favorite_position" in values:
            values["favorite_position"] = 0
        cols = ", ".join(f'"{k}"' for k in values)
        conn.execute(
            f'insert into characters ({cols}) '
            f'values ({", ".join("?" * len(values))})', tuple(values.values()))
    finally:
        conn.execute("pragma foreign_keys=on")


def _seed_capacity(conn: sqlite3.Connection) -> None:
    """Give every character the one-row capacity tables the handlers read.

    The 0.4.4 save ships none of them, and `capacity.expansion()` returns None
    for a missing row -- so a purchase that assigns `0 -> 8` reads as `0 -> 0`
    and the assertion looks like a logic bug rather than a missing fixture row.
    The reference creates these rows as a character is played; seeding them is
    reproducing that, not inventing state.

    Values are the ones the 0.3.6 capture shows for a played-in character:
    main inventory expanded once (16), both warehouses at their base 8.
    """
    for (table, column, value, key) in (
        ("character_inventory_expansion", "expansion", 16, "character_id"),
        ("character_cargo_state", "capacity", 8, "character_id"),
        ("character_second_cargo_state", "capacity", 8, "character_id"),
    ):
        exists = {r[0] for r in conn.execute(f'select "{key}" from "{table}"')}
        for (cid,) in conn.execute("select character_id from characters"):
            if cid in exists:
                continue
            conn.execute(
                f'insert into "{table}" ("{key}", "{column}") values (?, ?)',
                (cid, value))
    # `account_cargo_state` is per account, not per character.
    exists = {r[0] for r in conn.execute("select account_id from account_cargo_state")}
    for (aid,) in conn.execute("select distinct account_id from characters"):
        if aid in exists:
            continue
        conn.execute("insert into account_cargo_state (account_id, capacity) "
                     "values (?, 8)", (aid,))


@functools.lru_cache(maxsize=16)
def fixture(*character_ids: int) -> Path:
    """A writable copy of the reference save holding at least `character_ids`.

    Cached per id set -- the copy is a few hundred KB and the clone is a handful
    of inserts, so rebuilding it per test would dominate the suite.  Callers
    that mutate must copy again themselves; the cached path is the template.
    """
    tmp = Path(tempfile.mkdtemp(prefix="dfo-fixture-"))
    dst = tmp / paths.SAVE_DB.name
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))

    conn = sqlite3.connect(str(dst), isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        source = reference_character(conn)
        for wanted in character_ids:
            if conn.execute("select 1 from characters where character_id = ?",
                            (wanted,)).fetchone():
                continue
            clone_character(conn, source, wanted)
        _seed_capacity(conn)
    finally:
        conn.close()
    return dst


def fresh(*character_ids: int) -> Path:
    """A private copy of `fixture(...)`, safe to mutate and to delete."""
    template = fixture(*character_ids)
    tmp = Path(tempfile.mkdtemp(prefix="dfo-save-"))
    dst = tmp / template.name
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(template) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


def cleanup(path: Path) -> None:
    shutil.rmtree(path.parent, ignore_errors=True)
