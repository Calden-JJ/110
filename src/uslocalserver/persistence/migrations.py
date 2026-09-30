"""The upgrade layer the server runs after `BootstrapSchema.sql`.

`BootstrapSchema.sql` creates most of the save -- and then the server keeps
going, adding columns and triggers of its own.  Because the script uses
`CREATE TABLE IF NOT EXISTS` the gap never raises: an un-migrated database is
valid SQLite that quietly returns NULL for every field the game actually stores
there.

The exe does contain `ALTER TABLE ` and ` ADD COLUMN ` as string fragments,
but only as concatenation pieces; there is no readable list of finished
statements.  These were therefore read back off the real save: snapshot both
schemas with `schema.Schema.from_connection`, diff them, and take each added
column's definition verbatim out of the live `CREATE TABLE` text.

Two releases, two gaps (both measured; `tools/check_migrate044.py` re-measures):

    ==================  ======  =====
    release             tables  adds
    ==================  ======  =====
    0.3.6 (oracle)         54   17 columns, 1 index, 0 triggers
    0.4.4 (target)         94    6 columns, 0 indexes, 2 triggers
    ==================  ======  =====

0.4.4's script is *much* closer to its save than 0.3.6's was -- it already
carries `talisman_rune_types`, `lock_until`, `saint_selection` and the four
`expert_job_*` columns -- so the newer release needs less patching, not more.
Both gaps share the same five tables and the same column suffixes, so `LEGACY`
is `CURRENT[0.4.4]` plus the four columns 0.4.4 stopped adding.

Which set applies is decided by the bootstrap script the save is built from,
because that is the only thing that actually determines what is missing:
`for_script(path)` scans for the newest table a set introduces.  `save_is_new`
keeps the older test that only has a live connection.

The acceptance test is the reconstruction itself: build a database from the
bootstrap script plus this module and `schema.diff(expected=real, actual=built)`
must come back clean -- same columns in the same order, same types, defaults and
CHECK clauses, same indexes and triggers.

Note the ordering constraint this relies on: SQLite's `ADD COLUMN` appends to
the end of the column list, which is exactly where the real save has them.  A
column added in the middle of a later release's table cannot be reproduced this
way and must move into the bundled script instead.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from .schema import apply_ddl

ADD_COLUMN = "alter table {table} add column {definition}"

#: Same five columns land on both item tables; kept in one place so the two
#: cannot drift apart in a later edit.  Order matters: the live save's column
#: list is what `schema.diff` compares against.
ITEM_COLUMNS_LEGACY: tuple[str, ...] = (
    "expires_at INTEGER NOT NULL DEFAULT 0 CHECK(expires_at >= 0)",
    "custom_option_ids INTEGER NOT NULL DEFAULT 0",
    "growth_experience INTEGER NOT NULL DEFAULT 0 CHECK(growth_experience >= 0)",
    "amplify_type INTEGER NOT NULL DEFAULT 0 CHECK(amplify_type BETWEEN 0 AND 4)",
    "amplify_value INTEGER NOT NULL DEFAULT 0 CHECK(amplify_value BETWEEN 0 AND 65535)",
)

#: `account_cargo_items` does **not** order its tail the same way.  In the live
#: save it is `shop_exchange | sort_locked | custom_option_ids | ...`, the
#: reverse of `character_items`; the two tables stopped being clones when 0.4.4
#: migrated them separately.  Sharing one tuple here produces a subtly wrong
#: column order, which `schema.diff` reports as a `~` table difference rather
#: than as an error -- so the two are written out separately on purpose.
CARGO_COLUMNS_CURRENT: tuple[str, ...] = (
    "expires_at INTEGER NOT NULL DEFAULT 0 CHECK(expires_at >= 0)",
    "shop_exchange INTEGER NOT NULL DEFAULT 0 CHECK(shop_exchange BETWEEN 0 AND 63)",
    "sort_locked INTEGER NOT NULL DEFAULT 0 CHECK(sort_locked IN (0,1))",
    "custom_option_ids INTEGER NOT NULL DEFAULT 0",
    "growth_experience INTEGER NOT NULL DEFAULT 0 CHECK(growth_experience >= 0)",
    "amplify_type INTEGER NOT NULL DEFAULT 0 CHECK(amplify_type BETWEEN 0 AND 4)",
    "amplify_value INTEGER NOT NULL DEFAULT 0 CHECK(amplify_value BETWEEN 0 AND 65535)",
)

#: 0.4.4 keeps the legacy five but inserts `shop_exchange`/`sort_locked` after
#: `custom_option_ids`, so this is not a suffix of the legacy tuple.  The order
#: is what the live save has, measured with `tools/check_migrate044.py`:
#
#:     ... expires_at | custom_option_ids | shop_exchange | sort_locked
#:         | growth_experience | amplify_type | amplify_value
#:
#: `ADD COLUMN` can only append, so the bootstrap script supplies `expires_at`
#: and the rest follow in this order.
ITEM_COLUMNS_CURRENT: tuple[str, ...] = (
    "expires_at INTEGER NOT NULL DEFAULT 0 CHECK(expires_at >= 0)",
    "custom_option_ids INTEGER NOT NULL DEFAULT 0",
    "shop_exchange INTEGER NOT NULL DEFAULT 0 CHECK(shop_exchange BETWEEN 0 AND 63)",
    "sort_locked INTEGER NOT NULL DEFAULT 0 CHECK(sort_locked IN (0,1))",
    "growth_experience INTEGER NOT NULL DEFAULT 0 CHECK(growth_experience >= 0)",
    "amplify_type INTEGER NOT NULL DEFAULT 0 CHECK(amplify_type BETWEEN 0 AND 4)",
    "amplify_value INTEGER NOT NULL DEFAULT 0 CHECK(amplify_value BETWEEN 0 AND 65535)",
)

MAIL_COLUMNS_LEGACY: tuple[str, ...] = (
    "custom_option_ids INTEGER NOT NULL DEFAULT 0",
    "growth_experience INTEGER NOT NULL DEFAULT 0 CHECK(growth_experience >= 0)",
    "reinforcement INTEGER NOT NULL DEFAULT 0 CHECK(reinforcement BETWEEN 0 AND 31)",
    "refinement INTEGER NOT NULL DEFAULT 0 CHECK(refinement BETWEEN 0 AND 8)",
    "amplify_type INTEGER NOT NULL DEFAULT 0 CHECK(amplify_type BETWEEN 0 AND 4)",
    "amplify_value INTEGER NOT NULL DEFAULT 0 CHECK(amplify_value BETWEEN 0 AND 65535)",
)

#: Same story as the item tables -- `attachment_expires_at` and
#: `retention_seconds` land *between* `mist_imbued` and the custom-option group
#: in the live save, not at the end.
MAIL_COLUMNS_CURRENT: tuple[str, ...] = (
    "attachment_expires_at INTEGER NOT NULL DEFAULT 0 CHECK(attachment_expires_at>=0)",
    "retention_seconds INTEGER NOT NULL DEFAULT 0 CHECK(retention_seconds>=0)",
    "custom_option_ids INTEGER NOT NULL DEFAULT 0",
    "growth_experience INTEGER NOT NULL DEFAULT 0 CHECK(growth_experience >= 0)",
    "reinforcement INTEGER NOT NULL DEFAULT 0 CHECK(reinforcement BETWEEN 0 AND 31)",
    "refinement INTEGER NOT NULL DEFAULT 0 CHECK(refinement BETWEEN 0 AND 8)",
    "amplify_type INTEGER NOT NULL DEFAULT 0 CHECK(amplify_type BETWEEN 0 AND 4)",
    "amplify_value INTEGER NOT NULL DEFAULT 0 CHECK(amplify_value BETWEEN 0 AND 65535)",
)

FAVORITE_INDEX = (
    "CREATE UNIQUE INDEX uq_characters_favorite ON characters"
    "(account_id, favorite_position) WHERE favorite_position > 0"
)

#: 0.4.4 maintains the account explorer roster from `characters` itself.  Both
#: triggers name `account_explorer`, a table 0.3.6 does not have, which is why
#: they belong to the current set only.
EXPLORER_TRIGGERS: tuple[str, ...] = (
    """CREATE TRIGGER explorer_character_created AFTER INSERT ON characters BEGIN
    INSERT INTO account_explorer(account_id,created_at) VALUES(NEW.account_id,NEW.created_at)
        ON CONFLICT(account_id) DO NOTHING;
    INSERT INTO account_explorer_contributions(account_id,character_id,experience)
        VALUES(NEW.account_id,NEW.character_id,MAX(0,NEW.experience))
        ON CONFLICT(account_id,character_id) DO UPDATE SET
        experience=MAX(account_explorer_contributions.experience,excluded.experience);
END""",
    """CREATE TRIGGER explorer_character_experience AFTER UPDATE OF experience ON characters BEGIN
    INSERT INTO account_explorer_contributions(account_id,character_id,experience)
        VALUES(NEW.account_id,NEW.character_id,MAX(0,NEW.experience))
        ON CONFLICT(account_id,character_id) DO UPDATE SET
        experience=MAX(account_explorer_contributions.experience,excluded.experience);
END""",
)


@dataclass(frozen=True, slots=True)
class Migration:
    """One table's worth of upgrade, in the order the columns must be added."""
    table: str
    definitions: tuple[str, ...] = ()
    ddl: tuple[str, ...] = ()

    @property
    def statements(self) -> tuple[str, ...]:
        return (tuple(ADD_COLUMN.format(table=self.table, definition=d)
                      for d in self.definitions) + self.ddl)

    @property
    def columns(self) -> tuple[str, ...]:
        return tuple(d.split(None, 1)[0] for d in self.definitions)

    def __str__(self) -> str:
        return f"{self.table}: +{self.columns or 'ddl only'}"


#: 0.3.6's gap.  Kept verbatim because the oracle save, the pinned test counts
#: and the bundled `data/BootstrapSchema.sql` all belong to that release.
LEGACY: tuple[Migration, ...] = (
    Migration("account_cargo_items", ITEM_COLUMNS_LEGACY),
    Migration("character_items", ITEM_COLUMNS_LEGACY),
    Migration("character_quest_progress",
              ("counter_initialized INTEGER NOT NULL DEFAULT 0",)),
    Migration("system_mail", MAIL_COLUMNS_LEGACY),
    Migration("characters", (), (FAVORITE_INDEX,)),
)

#: 0.4.4's gap, as measured by `tools/check_migrate044.py`.
CURRENT: tuple[Migration, ...] = (
    Migration("account_cargo_items", CARGO_COLUMNS_CURRENT),
    Migration("character_items", ITEM_COLUMNS_CURRENT),
    Migration("character_quest_progress",
              ("counter_initialized INTEGER NOT NULL DEFAULT 0",)),
    Migration("system_mail", MAIL_COLUMNS_CURRENT),
    Migration("characters", (), (FAVORITE_INDEX, *EXPLORER_TRIGGERS)),
)

#: What each set introduces that the other does not, and the table whose
#: presence in a bootstrap script proves which release the script belongs to.
NEWER_TABLES: tuple[str, ...] = ("account_explorer",)

#: The active set.  `DFO_REF=0.4.4` selects the newer one; the package defaults
#: to 0.3.6 so every pinned count in `tests/` keeps meaning what it meant.
MIGRATIONS: tuple[Migration, ...] = (
    CURRENT if paths.REFERENCE == "0.4.4" else LEGACY
)

#: Every statement in order, for callers that just want to run them.
STATEMENTS: tuple[str, ...] = tuple(
    s for m in MIGRATIONS for s in m.statements)

#: table -> columns this module adds.  The drift baseline test asserts
#: `diff()` names exactly these and nothing else.
ADDED_COLUMNS: dict[str, tuple[str, ...]] = {
    m.table: m.columns for m in MIGRATIONS if m.columns
}
ADDED_INDEXES: tuple[str, ...] = ("uq_characters_favorite",)


def _trigger_names(statements: tuple[str, ...]) -> tuple[str, ...]:
    names = []
    for stmt in statements:
        head = stmt.strip().split()
        if len(head) >= 3 and head[0].upper() == "CREATE" and head[1].upper() == "TRIGGER":
            names.append(head[2])
    return tuple(names)


ADDED_TRIGGERS: tuple[str, ...] = _trigger_names(
    tuple(d for m in MIGRATIONS for d in m.ddl))


def for_script(sql: str) -> tuple[Migration, ...]:
    """The upgrade set that matches a bootstrap script's own text.

    The script is the thing that decides what is missing, so it -- not the
    environment -- is what this keys off.  A script that already declares
    `account_explorer` is a 0.4.4-or-later script and needs `CURRENT`.
    """
    lowered = sql.lower()
    if any(f"create table if not exists {t}" in lowered
           or f"create table {t}" in lowered for t in NEWER_TABLES):
        return CURRENT
    return LEGACY


def save_is_new(conn: sqlite3.Connection) -> bool:
    """Does a live save look like 0.4.4 or later?"""
    row = conn.execute("select 1 from sqlite_master where type='table' "
                       "and name=? limit 1", (NEWER_TABLES[0],)).fetchone()
    return row is not None


def statements_for(sql: str) -> tuple[str, ...]:
    return tuple(s for m in for_script(sql) for s in m.statements)


def apply(conn: sqlite3.Connection, *, script: str | None = None) -> None:
    """Run the upgrade layer, skipping whatever the database already has.

    `script` is the bootstrap text the database was built from; without it the
    live schema answers the same question, one `pragma` later.

    Skipping is not politeness -- `ADD COLUMN` on a column that exists is an
    error, and the newest release's script already carries columns the older
    set would add.  Making every statement conditional means one code path
    upgrades either release, and re-running is a no-op.
    """
    migrations = for_script(script) if script is not None else (CURRENT,)
    existing = {
        table: {r[1] for r in conn.execute(f'pragma table_info("{table}")')}
        for table, _ in ((m.table, None) for m in migrations)
    }
    have_triggers = {name for (name,) in conn.execute(
        "select name from sqlite_master where type='trigger'")}

    for m in migrations:
        known = existing.get(m.table, set())
        for definition in m.definitions:
            if definition.split(None, 1)[0] in known:
                continue
            conn.execute(ADD_COLUMN.format(table=m.table, definition=definition))
        for ddl in m.ddl:
            names = _trigger_names((ddl,))
            if names and names[0] in have_triggers:
                continue
            conn.execute(ddl)


def build(path: str | Path, *, overwrite: bool = False) -> sqlite3.Connection:
    """Create a save at `path`: bootstrap script, then this module's upgrades.

    Returns an open writable connection.  Refuses an existing file unless
    `overwrite`, so a mistyped path cannot cost someone their character data.
    """
    path = Path(path)
    if path.exists():
        if not overwrite:
            raise FileExistsError(f"{path} exists; pass overwrite=True to replace it")
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)

    from .schema import connect                                   # noqa: PLC0415
    conn = connect(path)
    script = paths.BOOTSTRAP_SQL.read_text(encoding="utf-8")
    conn.executescript(script)
    apply(conn, script=script)
    return conn


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=None,
                    help="build a fresh save here and verify it against the reference")
    ap.add_argument("--print", action="store_true", help="print the statements and exit")
    a = ap.parse_args()

    if a.print or a.out is None:
        for i, statement in enumerate(STATEMENTS, 1):
            print(f"{i:2}. {statement}")
        return 0

    from . import schema                                         # noqa: PLC0415
    conn = build(a.out, overwrite=True)
    expected = schema.Schema.from_connection(
        schema.connect(paths.SAVE_DB, readonly=True))
    report = schema.diff(expected=expected, actual=schema.Schema.from_connection(conn))
    print(f"built {a.out}: {len(expected.tables)} tables expected, "
          f"{len(schema.Schema.from_connection(conn).tables)} present")
    print(report)
    return 0 if report.clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
