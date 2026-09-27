"""The save's schema, the upgrade layer, and the one typed query M0 ships.

The numbers below were measured off the real save.  The important one is the
drift baseline: `BootstrapSchema.sql` is a *lie* about the database the server
runs -- 17 columns and one index short -- and because the script uses
`CREATE TABLE IF NOT EXISTS` nothing ever raises.  Pinning the 17 keeps a
narrowed or widened migration layer from passing unnoticed, the same way
`test_opcodes.py` pins its opcode counts.
"""
from __future__ import annotations

import functools
import sqlite3
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.persistence import characters, migrations, schema

EXPECTED_TABLES = 54
EXPECTED_TRIGGERS = 5
EXPECTED_INDEXES = 12            # real save; the script alone has 11
BOOTSTRAP_INDEXES = 11
EXPECTED_FOREIGN_KEYS = 48
EXPECTED_CHECKS = 62

#: What `migrations.py` adds, and the whole of what it may add.
ADDED_COLUMNS = {
    "account_cargo_items": ("expires_at", "custom_option_ids", "growth_experience",
                            "amplify_type", "amplify_value"),
    "character_items": ("expires_at", "custom_option_ids", "growth_experience",
                        "amplify_type", "amplify_value"),
    "character_quest_progress": ("counter_initialized",),
    "system_mail": ("custom_option_ids", "growth_experience", "reinforcement",
                    "refinement", "amplify_type", "amplify_value"),
}
ADDED_INDEXES = ("uq_characters_favorite",)
EXPECTED_ADDED = sum(len(c) for c in ADDED_COLUMNS.values())     # 17


@functools.lru_cache(maxsize=1)
def real_schema() -> schema.Schema:
    return schema.Schema.from_connection(schema.connect(paths.SAVE_DB, readonly=True))


def bootstrap_schema() -> schema.Schema:
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.executescript(paths.BOOTSTRAP_SQL.read_text(encoding="utf-8"))
    return schema.Schema.from_connection(conn)


class Upscaled(unittest.TestCase):
    """Builds one migrated database for the whole class; SQLite is cheap."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls._tmp.name) / "save.db"
        cls.conn = migrations.build(cls.path)
        cls.schema = schema.Schema.from_connection(cls.conn)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls._tmp.cleanup()

    def executable(self, **row):
        """Insert a valid `characters` row, defaulting everything required."""
        values = {"character_id": 1, "account_id": 1, "slot_index": 0,
                  "name": "Test", "class_id": 1, "level": 1,
                  "created_at": 0, "updated_at": 0, **row}
        columns = ", ".join(f'"{c}"' for c in values)
        marks = ", ".join("?" * len(values))
        return self.conn.execute(
            f"insert into characters ({columns}) values ({marks})",
            tuple(values.values()))

    def wipe(self):
        # Children first, or an earlier test's rows block the parent delete.
        self.conn.execute("pragma foreign_keys=off")
        for table in ("character_items", "characters", "accounts"):
            self.conn.execute(f"delete from {table}")
        self.conn.execute("pragma foreign_keys=on")

    def account(self, account_id=1):
        self.conn.execute("insert into accounts (account_id, created_at, updated_at) "
                          "values (?, 0, 0)", (account_id,))


class Shape(Upscaled):
    def test_table_trigger_and_index_counts(self):
        self.assertEqual(len(self.schema.tables), EXPECTED_TABLES)
        self.assertEqual(len(self.schema.triggers), EXPECTED_TRIGGERS)
        self.assertEqual(len(self.schema.indexes), EXPECTED_INDEXES)

    def test_the_script_alone_is_one_index_short(self):
        boot = bootstrap_schema()
        self.assertEqual(len(boot.tables), EXPECTED_TABLES)
        self.assertEqual(len(boot.triggers), EXPECTED_TRIGGERS)
        self.assertEqual(len(boot.indexes), BOOTSTRAP_INDEXES)

    def test_triggers_keep_the_semicolons_inside_their_bodies(self):
        # Reading the file with split(';') would truncate these at the first
        # inner statement; executescript is what makes them whole.
        sql = self.schema.triggers["gm_inventory_update"]
        self.assertIn("; insert into gm_inventory_revisions", sql)
        self.assertTrue(sql.endswith("end"), sql)

    def test_columns_come_back_in_declaration_order(self):
        self.assertEqual(self.schema.table("characters").column_names, characters.COLUMNS)

    def test_foreign_keys_and_checks_are_counted_whole(self):
        fks = sum(len(t.foreign_keys) for t in self.schema.tables.values())
        checks = sum(len(t.checks) for t in self.schema.tables.values())
        self.assertEqual(fks, EXPECTED_FOREIGN_KEYS)
        self.assertEqual(checks, EXPECTED_CHECKS)


class Drift(unittest.TestCase):
    """The baseline: exactly 17 columns and one index separate script from save."""

    def setUp(self):
        self.report = schema.diff(expected=real_schema(), actual=bootstrap_schema())

    def test_the_real_save_matches_itself(self):
        self.assertTrue(schema.diff(expected=real_schema(), actual=real_schema()).clean)

    def test_the_script_is_exactly_these_seventeen_columns_and_one_index_short(self):
        expected = {(t, c) for t, cols in ADDED_COLUMNS.items() for c in cols}
        self.assertEqual(len(expected), EXPECTED_ADDED)
        self.assertEqual(set(self.report.missing_columns), expected)
        self.assertEqual(self.report.missing_indexes, ADDED_INDEXES)
        self.assertEqual(self.report.summary(),
                         f"{EXPECTED_ADDED} missing column(s), 1 missing index(es)")

    def test_nothing_else_differs(self):
        # The 17 are the whole story: same tables, same types, same defaults,
        # same CHECK clauses, same triggers, same foreign keys both sides.
        self.assertEqual(self.report.extra_tables, ())
        self.assertEqual(self.report.missing_tables, ())
        self.assertEqual(self.report.extra_columns, ())
        self.assertEqual(self.report.changed_columns, ())
        self.assertEqual(self.report.changed_tables, ())
        self.assertEqual(self.report.extra_indexes, ())
        self.assertEqual(self.report.changed_indexes, ())
        self.assertEqual(self.report.changed_triggers, ())
        self.assertEqual(self.report.changed_foreign_keys, ())

    def test_the_affected_tables_are_the_five_the_migrations_name(self):
        # characters is there for the index alone -- no column of it changed.
        self.assertEqual(self.report.affected_tables,
                         ("account_cargo_items", "character_items",
                          "character_quest_progress", "characters", "system_mail"))
        self.assertEqual(self.report.affected_tables,
                         tuple(sorted({m.table for m in migrations.MIGRATIONS})))

    def test_a_missing_column_is_reported_with_its_table(self):
        self.assertIn(("character_items", "amplify_value"), self.report.missing_columns)
        self.assertFalse(self.report.clean)

    def test_the_report_lists_every_difference(self):
        text = str(self.report)
        self.assertIn("character_items.amplify_value", text)
        self.assertIn("index uq_characters_favorite", text)
        self.assertNotIn("~", text)          # nothing "changed", only added


class Reconstruction(Upscaled):
    def test_script_plus_migrations_reproduces_the_real_save(self):
        report = schema.diff(expected=real_schema(), actual=self.schema)
        self.assertTrue(report.clean, report)

    def test_the_reconstruction_keeps_the_column_order(self):
        for table, columns in ADDED_COLUMNS.items():
            live = real_schema().table(table).column_names
            self.assertEqual(self.schema.table(table).column_names, live)
            self.assertEqual(live[-len(columns):], columns)

    def test_the_added_columns_carry_their_defaults_and_checks(self):
        col = self.schema.table("character_items").column("amplify_type")
        self.assertEqual(col.type, "INTEGER")
        self.assertTrue(col.notnull)
        self.assertEqual(col.default, "0")
        self.assertEqual(col.checks, ("(amplify_type between 0 and 4)",))
        quest = self.schema.table("character_quest_progress").column("counter_initialized")
        self.assertEqual(quest.checks, ())
        self.assertEqual(quest.default, "0")

    def test_the_partial_index_survives_with_its_where_clause(self):
        index = self.schema.indexes["uq_characters_favorite"]
        self.assertTrue(index.unique)
        self.assertTrue(index.partial)
        self.assertEqual(index.where, "favorite_position > 0")
        self.assertEqual(index.columns, ("account_id", "favorite_position"))


class UpgradeSemantics(Upscaled):
    """The upgrade has to be enforced, not merely declared."""

    def setUp(self):
        self.wipe()

    def test_a_freshly_migrated_row_defaults_to_the_added_values(self):
        self.account()
        self.executable()
        self.conn.execute(
            "insert into character_items (character_id, list_type, slot_index, "
            "item_id, count, durability, random_options, avatar_sockets, updated_at) "
            "values (1, 0, 0, 1, 1, 0, X'', X'', 0)")
        row = self.conn.execute("select * from character_items").fetchone()
        self.assertEqual(row["expires_at"], 0)
        self.assertEqual(row["growth_experience"], 0)
        self.assertEqual(row["amplify_value"], 0)

    def test_the_added_check_clause_is_live(self):
        self.account()
        self.executable()
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "insert into character_items (character_id, list_type, slot_index, "
                "item_id, count, durability, random_options, avatar_sockets, "
                "updated_at, amplify_type) values (1, 0, 0, 1, 1, 0, X'', X'', 0, 5)")

    def test_the_partial_index_allows_many_unpinned_and_one_pinned(self):
        self.account()
        self.executable(character_id=1, slot_index=0, name="A", favorite_position=0)
        self.executable(character_id=2, slot_index=1, name="B", favorite_position=0)
        self.executable(character_id=3, slot_index=2, name="C", favorite_position=1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.executable(character_id=4, slot_index=3, name="D", favorite_position=1)

    def test_foreign_keys_are_actually_on(self):
        # `PRAGMA foreign_keys=ON` inside an implicit transaction is silently
        # dropped, which is why `connect` uses isolation_level=None.
        with self.assertRaises(sqlite3.IntegrityError):
            self.executable(character_id=1, account_id=9999)

    def test_a_table_check_still_bites_after_the_upgrade(self):
        self.account()
        with self.assertRaises(sqlite3.IntegrityError):
            self.executable(level=111)


class Characters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = schema.connect(paths.SAVE_DB, readonly=True)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_account_zero_lists_both_characters_in_slot_order(self):
        # Name and slot are the character's identity on the select screen; the
        # rest of the row is what playing mutates -- XRenYing's town went
        # 38 -> 168 in the 2026-09-27 session, on the live save these tests
        # deliberately read.  The mutable fields are compared against the row
        # itself in `test_the_summary_exposes_more_than_the_name`.
        got = [(c.name, c.slot_index) for c in characters.list_characters(self.conn, 0)]
        self.assertEqual(got, [("XRenYing", 0), ("LRouDao", 1)])

    def test_the_summary_exposes_more_than_the_name(self):
        first = characters.list_characters(self.conn, 0)[0]
        self.assertEqual(first.character_id, 1)
        self.assertEqual(first.class_id, 11)
        self.assertTrue(first.pinned)
        row = self.conn.execute(
            "select town_id, area_id, town_state from characters "
            "where character_id = 1").fetchone()
        self.assertEqual(first.location, tuple(row))
        self.assertEqual(str(first), f"XRenYing Lv110 class=11 "
                                     f"town={row[0]}/{row[1]} slot=0")

    def test_an_account_with_no_characters_is_an_empty_list(self):
        self.assertEqual(characters.list_characters(self.conn, 4242), [])

    def test_find_by_name(self):
        self.assertEqual(characters.find(self.conn, 0, "LRouDao").class_id, 1)
        self.assertIsNone(characters.find(self.conn, 0, "Nobody"))
        self.assertIsNone(characters.find(self.conn, 1, "XRenYing"))

    def test_every_column_is_populated_from_the_row(self):
        summary = characters.list_characters(self.conn, 0)[0]
        for name in characters.COLUMNS:
            self.assertIsNotNone(getattr(summary, name), name)


class Connection(unittest.TestCase):
    def test_autocommit_is_off_so_the_pragma_survives(self):
        conn = schema.connect(paths.SAVE_DB, readonly=True)
        self.addCleanup(conn.close)
        self.assertIsNone(conn.isolation_level)
        self.assertEqual(conn.execute("pragma foreign_keys").fetchone()[0], 1)

    def test_a_readonly_connection_refuses_writes(self):
        conn = schema.connect(paths.SAVE_DB, readonly=True)
        self.addCleanup(conn.close)
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("insert into accounts (account_id, created_at, updated_at) "
                         "values (999, 0, 0)")

    def test_a_readonly_connection_opens_a_database_that_is_not_wal(self):
        # Switching to WAL needs write access; doing it unconditionally turns
        # a plain read-only open into "attempt to write a readonly database".
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plain.db"
            seed = sqlite3.connect(path)
            seed.execute("create table t (a)")
            seed.commit()
            seed.close()
            conn = schema.connect(path, readonly=True)
            try:
                self.assertNotEqual(conn.execute("pragma journal_mode").fetchone()[0], "wal")
                self.assertEqual(conn.execute("select count(*) from t").fetchone()[0], 0)
            finally:
                conn.close()          # Windows will not delete an open database

    def test_writing_connections_do_use_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = migrations.build(Path(tmp) / "save.db")
            try:
                self.assertEqual(conn.execute("pragma journal_mode").fetchone()[0], "wal")
            finally:
                conn.close()

    def test_build_refuses_to_clobber_an_existing_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "save.db"
            path.write_bytes(b"precious")
            with self.assertRaises(FileExistsError):
                migrations.build(path)
            self.assertEqual(path.read_bytes(), b"precious")


class Descriptors(unittest.TestCase):
    def setUp(self):
        self.built = bootstrap_schema()

    def test_a_check_clause_is_not_clipped_at_its_first_close_paren(self):
        # A regex up to the first ')' yields "check(expires_at >= 0" for the
        # migrated column; the splitter has to count brackets.
        col = real_schema().table("character_items").column("expires_at")
        self.assertEqual(col.checks, ("(expires_at >= 0)",))
        col = real_schema().table("system_mail").column("claimed")
        self.assertEqual(col.checks, ("(claimed in (0,1))",))

    def test_table_constraints_are_not_mistaken_for_columns(self):
        # characters' 15 table-level CHECKs sit after the column list; a naive
        # split would invent columns named "CHECK".
        table = real_schema().table("characters")
        self.assertEqual(len(table.constraints), 16)     # 15 checks + 1 foreign key
        self.assertNotIn("check", table.column_names)
        self.assertEqual(len(table.checks), 15)

    def test_composite_foreign_keys_stay_one_key(self):
        # `pragma foreign_key_list` returns one row per column; a naive read
        # would call this two single-column keys pointing at the same place.
        table = real_schema().table("character_quest_progress")
        self.assertEqual(len(table.foreign_keys), 1)
        fk = table.foreign_keys[0]
        self.assertEqual(fk.columns, ("character_id", "quest_id"))
        self.assertEqual((fk.ref_table, fk.ref_columns),
                         ("character_quests", ("character_id", "quest_id")))
        cascading = real_schema().table("character_bakal_auctions").foreign_keys[0]
        self.assertEqual(cascading.columns, ("character_id", "run_id"))
        self.assertEqual(cascading.ref_table, "character_bakal_reward_plans")
        self.assertEqual(cascading.on_delete, "CASCADE")

    def test_a_single_column_foreign_key_keeps_its_actions(self):
        fk = real_schema().table("account_cargo_items").foreign_keys[0]
        self.assertEqual(fk.columns, ("account_id",))
        self.assertEqual(fk.on_delete, "CASCADE")

    def test_autoincrement_is_noticed(self):
        self.assertIn("system_mail", [t.name for t in real_schema().tables.values()
                                      if t.autoincrement])
        self.assertFalse(bootstrap_schema().table("characters").autoincrement)

    def test_pk_columns_come_back_in_key_order(self):
        table = real_schema().table("character_items")
        self.assertEqual(table.pk_columns, ("character_id", "list_type", "slot_index"))
        self.assertEqual(real_schema().table("characters").pk_columns, ("character_id",))

    def test_asking_for_a_table_that_is_not_there_names_the_problem(self):
        with self.assertRaises(KeyError) as ctx:
            real_schema().table("charcter_items")
        self.assertIn("charcter_items", str(ctx.exception))

    def test_asking_for_a_column_that_is_not_there_names_the_problem(self):
        with self.assertRaises(KeyError) as ctx:
            real_schema().table("characters").column("levl")
        self.assertIn("levl", str(ctx.exception))


class Repository(Upscaled):
    def setUp(self):
        self.wipe()
        self.repo = schema.Repository.of(self.conn, "characters")

    def test_a_typo_in_a_column_name_never_reaches_sql(self):
        self.account()
        self.executable()
        with self.assertRaises(KeyError) as ctx:
            self.repo.select(nmae="X")
        self.assertIn("nmae", str(ctx.exception))
        with self.assertRaises(KeyError):
            self.repo.insert({"character_id": 2, "nmae": "X"})
        with self.assertRaises(KeyError):
            self.repo.update(1, levl=2)

    def test_select_and_count(self):
        self.account()
        self.executable(character_id=1, slot_index=0, name="A")
        self.executable(character_id=2, slot_index=1, name="B")
        self.assertEqual([r["name"] for r in self.repo.select(account_id=1)], ["A", "B"])
        self.assertEqual(self.repo.count(), 2)
        self.assertEqual(self.repo.count(account_id=1), 2)
        self.assertEqual(self.repo.count(account_id=7), 0)

    def test_get_by_primary_key(self):
        self.account()
        self.executable()
        self.assertEqual(self.repo.get(1)["name"], "Test")
        self.assertIsNone(self.repo.get(2))
        with self.assertRaises(ValueError):
            self.repo.get(1, 2)

    def test_insert_update_delete(self):
        self.account()
        self.repo.insert({"character_id": 1, "account_id": 1, "slot_index": 0,
                          "name": "A", "class_id": 1, "level": 1,
                          "created_at": 0, "updated_at": 0})
        self.assertEqual(self.repo.update(1, level=42), 1)
        self.assertEqual(self.repo.get(1)["level"], 42)
        self.assertEqual(self.repo.delete(1), 1)
        self.assertEqual(self.repo.count(), 0)

    def test_upsert_inserts_then_updates_in_place(self):
        self.account()
        row = {"character_id": 1, "account_id": 1, "slot_index": 0, "name": "A",
               "class_id": 1, "level": 1, "created_at": 0, "updated_at": 0}
        self.repo.upsert(row)
        self.repo.upsert({**row, "level": 99})
        self.assertEqual(self.repo.count(), 1)
        self.assertEqual(self.repo.get(1)["level"], 99)

    def test_upsert_on_a_composite_key(self):
        self.account()
        items = schema.Repository.of(self.conn, "account_cargo_items")
        row = {"account_id": 1, "list_type": 12, "slot_index": 0, "item_id": 7,
               "count": 1, "durability": 0, "random_options": b"",
               "avatar_sockets": b"", "updated_at": 0}
        items.upsert(row)
        items.upsert({**row, "count": 5})
        self.assertEqual(items.count(), 1)
        self.assertEqual(items.select(account_id=1)[0]["count"], 5)

    def test_iterating_yields_every_row(self):
        self.account()
        self.executable(character_id=1, slot_index=0, name="A")
        self.executable(character_id=2, slot_index=1, name="B")
        self.assertEqual(sorted(r["name"] for r in self.repo), ["A", "B"])

    def test_a_missing_table_names_the_problem(self):
        with self.assertRaises(KeyError):
            schema.Repository.of(self.conn, "no_such_table")


if __name__ == "__main__":
    unittest.main()
