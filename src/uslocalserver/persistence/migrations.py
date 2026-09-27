"""The upgrade layer the server runs after `BootstrapSchema.sql`.

`BootstrapSchema.sql` creates 54 tables and 5 triggers -- and then the server
keeps going, adding 17 columns across 4 tables and one partial unique index.
Because the script uses `CREATE TABLE IF NOT EXISTS` the gap never raises: an
un-migrated database is valid SQLite that quietly returns NULL for every field
the game actually stores there.

The exe does contain `ALTER TABLE ` and ` ADD COLUMN ` as string fragments,
but only as concatenation pieces; there is no readable list of finished
statements.  These 17 were therefore read back off the real save: snapshot
both schemas with `schema.Schema.from_connection`, diff them, and take each
added column's definition verbatim out of the live `CREATE TABLE` text.

    account_cargo_items       5 columns
    character_items           5 columns
    character_quest_progress  1 column
    system_mail               6 columns
    characters                1 index

The acceptance test is the reconstruction itself: build a database from the
bootstrap script plus this module and `schema.diff(expected=real,
actual=built)` must come back clean -- same columns in the same order, same
types, defaults and CHECK clauses, same index and its WHERE clause.

Note the ordering constraint this relies on: SQLite's `ADD COLUMN` appends to
the end of the column list, which is exactly where the real save has them.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from .schema import apply_ddl

ADD_COLUMN = "alter table {table} add column {definition}"

#: Same five columns land on both item tables; kept in one place so the two
#: cannot drift apart in a later edit.
ITEM_COLUMNS: tuple[str, ...] = (
    "expires_at INTEGER NOT NULL DEFAULT 0 CHECK(expires_at >= 0)",
    "custom_option_ids INTEGER NOT NULL DEFAULT 0",
    "growth_experience INTEGER NOT NULL DEFAULT 0 CHECK(growth_experience >= 0)",
    "amplify_type INTEGER NOT NULL DEFAULT 0 CHECK(amplify_type BETWEEN 0 AND 4)",
    "amplify_value INTEGER NOT NULL DEFAULT 0 CHECK(amplify_value BETWEEN 0 AND 65535)",
)

FAVORITE_INDEX = (
    "CREATE UNIQUE INDEX uq_characters_favorite ON characters"
    "(account_id, favorite_position) WHERE favorite_position > 0"
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


MIGRATIONS: tuple[Migration, ...] = (
    Migration("account_cargo_items", ITEM_COLUMNS),
    Migration("character_items", ITEM_COLUMNS),
    Migration("character_quest_progress",
              ("counter_initialized INTEGER NOT NULL DEFAULT 0",)),
    Migration("system_mail", (
        "custom_option_ids INTEGER NOT NULL DEFAULT 0",
        "growth_experience INTEGER NOT NULL DEFAULT 0 CHECK(growth_experience >= 0)",
        "reinforcement INTEGER NOT NULL DEFAULT 0 CHECK(reinforcement BETWEEN 0 AND 31)",
        "refinement INTEGER NOT NULL DEFAULT 0 CHECK(refinement BETWEEN 0 AND 8)",
        "amplify_type INTEGER NOT NULL DEFAULT 0 CHECK(amplify_type BETWEEN 0 AND 4)",
        "amplify_value INTEGER NOT NULL DEFAULT 0 CHECK(amplify_value BETWEEN 0 AND 65535)",
    )),
    Migration("characters", (), (FAVORITE_INDEX,)),
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


def apply(conn: sqlite3.Connection) -> None:
    apply_ddl(conn, STATEMENTS)


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
    conn.executescript(paths.BOOTSTRAP_SQL.read_text(encoding="utf-8"))
    apply(conn)
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
