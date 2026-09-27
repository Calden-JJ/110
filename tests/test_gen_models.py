"""The generated content models, and the traps the generator exists to avoid.

`tools/gen_models.py` reads the 69 table bodies and writes three files.  The
tests below are less about the code it emits than about the four ways the
classification behind it could be wrong:

  * *inferring a type from the first record.*  `map_content.maps[0]` has five
    keys; six more appear only further down.  Reading `maps[0]` alone would
    have made them vanish.
  * *trusting `_index.json`.*  Its `top_keys` stops at 12, so
    `quest_awakening_effects` looks like it has 12 keys and has 138.  Nothing
    here reads it.
  * *the size gate.*  A container just under `MIN_RECORDS` is config and just
    over it is a record set, so the boundary cases are pinned explicitly --
    they are where the threshold, not the shape, decides.
  * *`i` leaking into game code.*  Everything is keyed by canonical table name.
"""
from __future__ import annotations

import contextlib
import functools
import io
import json
import re
import unittest
from unittest import mock

import _bootstrap  # noqa: F401

import gen_models
import map_tables
from uslocalserver import paths
from uslocalserver.game import data

EXPECTED_TABLES = 69
EXPECTED_KINDS = {"config": 40, "dict-with-records": 21, "flat-list": 1,
                  "record-set-root": 7}
EXPECTED_RECORD_SETS = 36
EXPECTED_FIELDS = 223

#: Containers just under `MIN_RECORDS`, so they are config, not rows.  Pinned
#: because the gate, not the shape, is what puts them there: `teleport_potions`
#: is a `dict-with-records` table whose `towns` is one entry short of becoming a
#: record set, and `tournaments.tournaments` and `image_communication.npcs` are
#: record sets in every way except size.
BELOW_THE_GATE = (
    ("cargo", "personalTools", 16),
    ("cargo", "secondTools", 16),
    ("teleport_potions", "towns", 16),
    ("hell_party", "worldmaps", 15),
    ("equipment_specificity", "Groups", 4),
    ("wisdom", "maps", 4),
    ("equipment_specificity", "SpecialPoints", 3),
    ("tournaments", "tournaments", 2),
    ("image_communication", "npcs", 2),
)

#: Exactly at the gate, so it *is* a record set.  The other side of the pin.
AT_THE_GATE = ("progression_items", "items")

#: Keys of `map_content.maps[0]`.  Six more appear only in later records -- the
#: union of all 17081 is 11 fields, and a first-record generator would see five.
#: (This is also why the record-set gate the plan proposed, key sets agreeing by
#: Jaccard >= 0.9, would have dropped this table at 0.33.)
FIRST_MAP_KEYS = ("id", "monsterFlags", "monsterLevelValues", "monsters", "type")
LATE_MAP_KEYS = ("autoMove", "disableRebirth", "elevatorLevel", "monsterParseError",
                 "monsterTeams", "startArea")
#: And of the five in the first record, only these two are in *every* record --
#: so three of them are optional too, which the first record cannot show either.
ALWAYS_PRESENT = ("id", "type")

#: The index digest, against the body it is a digest of.
INDEX_TRUNCATION = {"quest_awakening_effects": (12, 138),
                    "equipment_systems": (12, 19),
                    "disjoint_content": (12, 19)}

FIELD_LINE = re.compile(r"^    ([A-Za-z_][A-Za-z0-9_]*): (.+)$")


@functools.lru_cache(maxsize=1)
def surveyed() -> dict:
    return gen_models.build()


@functools.lru_cache(maxsize=1)
def rendered() -> dict[str, str]:
    return gen_models.render(surveyed())


def sets() -> dict[tuple[str, str | None], dict]:
    return {(e["table"], e["key"]): e for e in surveyed()["record_sets"]}


def source(name: str) -> str:
    return (paths.GAME_DATA_DIR / name).read_text(encoding="utf-8")


class Regeneration(unittest.TestCase):
    def test_the_committed_files_are_reproducible_byte_for_byte(self):
        for name, text in rendered().items():
            self.assertEqual(text, source(name), name)

    def test_the_skipped_manifest_is_reproducible(self):
        self.assertEqual(gen_models.render_skipped(surveyed()),
                         paths.GEN_MODELS_SKIPPED.read_text(encoding="utf-8"))

    def test_the_check_flag_reports_the_committed_files_as_current(self):
        # `build` is stubbed out: the CLI wiring is what is under test, and
        # re-reading 77 MB of tables to prove it would double the suite's time.
        with mock.patch.object(gen_models, "build", surveyed), \
                mock.patch("sys.argv", ["gen_models.py", "--check"]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gen_models.main(), 0)


class Classification(unittest.TestCase):
    def test_the_kinds_add_up(self):
        self.assertEqual(surveyed()["kinds"], EXPECTED_KINDS)
        self.assertEqual(sum(EXPECTED_KINDS.values()), EXPECTED_TABLES)

    def test_the_record_sets_add_up(self):
        row = surveyed()["record_sets"]
        self.assertEqual(len(row), EXPECTED_RECORD_SETS)
        self.assertEqual(len({e["class"] for e in row}), EXPECTED_RECORD_SETS)
        self.assertEqual(sum(len(e["fields"]) for e in row), EXPECTED_FIELDS)

    def test_nothing_is_skipped_and_that_is_declared(self):
        # A skip is a table the generator refuses to model.  There are none;
        # if that changes the reason has to be written down here.
        self.assertEqual(surveyed()["skipped"], [])

    def test_a_table_can_hold_several_record_sets(self):
        # Keyed by table name alone, eight of the 36 would silently overwrite
        # one another: `teleport_potions` has four.
        counts = {}
        for table, _ in sets():
            counts[table] = counts.get(table, 0) + 1
        self.assertEqual({t: n for t, n in counts.items() if n > 1},
                         {"dungeon_worldmap": 2, "enchant_emblem": 2,
                          "hell_party": 3, "npc_shop_rules": 2,
                          "teleport_potions": 4})

    def test_the_size_gate_is_pinned_on_both_sides(self):
        known = sets()
        for table, key, size in BELOW_THE_GATE:
            with self.subTest(f"{table}.{key}"):
                self.assertNotIn((table, key), known)
                self.assertIn(key, data.CONFIG_KEYS[table])
                self.assertLess(size, gen_models.MIN_RECORDS)
        self.assertIn(AT_THE_GATE, known)
        self.assertNotIn(AT_THE_GATE[1], data.CONFIG_KEYS[AT_THE_GATE[0]])
        self.assertEqual(sets()[AT_THE_GATE]["records"], gen_models.MIN_RECORDS)

    def test_the_pinned_sizes_are_the_ones_in_the_bodies(self):
        # Otherwise the pin above is just a number agreeing with itself.
        for table, key, size in BELOW_THE_GATE + ((*AT_THE_GATE, gen_models.MIN_RECORDS),):
            with self.subTest(f"{table}.{key}"):
                self.assertEqual(len(data.load(table)[key]), size)

    def test_the_only_flat_array_is_the_potion_list(self):
        self.assertEqual(surveyed()["flat"], {"total_war_potions": "int"})
        self.assertEqual(len(data.flat("total_war_potions")), 495)


class Fields(unittest.TestCase):
    def test_types_come_from_every_record_not_the_first(self):
        entry = sets()[("map_content", "maps")]
        self.assertEqual(entry["records"], 17081)
        names = [f[0] for f in entry["fields"]]
        self.assertEqual(len(names), 11)
        for key in FIRST_MAP_KEYS + LATE_MAP_KEYS:
            self.assertIn(key, names)
        # The first record has five of those keys and none of the other six.
        body = data.load("map_content")
        self.assertEqual(sorted(body["maps"][0]), list(FIRST_MAP_KEYS))
        annotations = {f[0]: f[1] for f in entry["fields"]}
        for key in ALWAYS_PRESENT:
            self.assertNotIn("| None", annotations[key])
        for key in tuple(k for k in FIRST_MAP_KEYS if k not in ALWAYS_PRESENT) + LATE_MAP_KEYS:
            self.assertIn("| None", annotations[key])

    def test_the_index_digest_is_not_what_the_types_were_read_from(self):
        # The index truncates `top_keys` at 12, so it understates exactly the
        # tables with the most keys.  Counting the body instead is the point.
        index = {e["i"]: e for e in map_tables.load_index()}
        by_name = map_tables.by_name()
        for name, (listed, real) in INDEX_TRUNCATION.items():
            with self.subTest(name):
                body = data.load(name)
                self.assertEqual(len(index[by_name[name]["i"]]["top_keys"]), listed)
                self.assertEqual(len(body), real)
                self.assertGreater(real, listed)

    def test_every_any_is_marked_for_review(self):
        lines = [m for line in source("models.py").splitlines()
                 if (m := FIELD_LINE.match(line))]
        self.assertEqual(len(lines), EXPECTED_FIELDS,
                         "the field-line pattern stopped matching the output")
        for match in lines:
            with self.subTest(match.group(1)):
                if "Any" in match.group(2):
                    self.assertIn("# NEEDS-REVIEW", match.group(2))

    def test_the_unions_are_marked_too(self):
        # Not `Any`, but still not one type: `int | str` says the field has two
        # shapes and a reader should look at it.
        marked = [f for e in surveyed()["record_sets"] for f in e["fields"] if f[2]]
        self.assertEqual(len(marked), 6)
        self.assertEqual(sum(1 for f in marked if "Any" in f[1]), 4)

    def test_bool_folds_into_int_rather_than_becoming_a_union(self):
        # `bool` is an `int` in Python, so `bool | int` is noise, not a review.
        ann, why = gen_models._union({"bool", "int"})
        self.assertEqual((ann, why), ("int", None))
        self.assertEqual(gen_models._union({"int", "float"}), ("float", None))
        self.assertEqual(gen_models._union({"int", "str"}),
                         ("int | str", "union of int | str"))


class Package(unittest.TestCase):
    def test_every_table_is_reachable_by_name(self):
        self.assertEqual(len(data.FILES), EXPECTED_TABLES)
        self.assertEqual(len(set(data.FILES.values())), EXPECTED_TABLES)
        self.assertEqual(sorted(data.FILES), sorted(map_tables.by_name()))
        for name, file in data.FILES.items():
            self.assertTrue((paths.TABLES_DIR / file).is_file(), name)

    def test_nothing_is_keyed_by_number(self):
        # The manifest order is the one thing that might be wrong, so it is
        # confined to `_table_map.json`; no game code sees an `i`.
        for name in data.RECORD_SETS:
            self.assertFalse(name.isdigit(), name)
        self.assertEqual(len(data.CONFIG_KEYS), EXPECTED_TABLES)

    def test_the_config_keys_are_what_is_left_over(self):
        self.assertEqual(data.CONFIG_KEYS["map_content"], ("source", "client"))
        self.assertEqual(data.CONFIG_KEYS["total_war_potions"], ())
        # A body that is itself the record set has no top-level keys left.
        self.assertEqual(data.CONFIG_KEYS["quest_npc_ranges"], ())
        # A container that was modelled is not advertised as config as well.
        for name, sets_of in data.RECORD_SETS.items():
            for key in sets_of:
                if key is not None:
                    self.assertNotIn(key, data.CONFIG_KEYS[name])

    def test_the_rows_carry_the_records(self):
        self.assertEqual(len(data.rows("dungeon_list")), 3244)
        self.assertEqual(data.rows("dungeon_list")[0].path, "Dungeon/Act1/Lorien.dgn")
        self.assertEqual(len(data.rows("hell_party", "maps")), 34)
        self.assertEqual(data.rows("hell_party", "groups")[0].__class__.__name__,
                         "HellPartyGroupsRow")

    def test_a_table_with_several_sets_demands_a_key(self):
        with self.assertRaises(KeyError) as caught:
            data.rows("hell_party")
        self.assertIn("dungeons", str(caught.exception))

    def test_rows_are_coerced_to_the_annotated_types(self):
        row = data.rows("buff_swap")[0]
        self.assertIsInstance(row.skills, tuple)
        self.assertIsInstance(data.rows("dungeon_content")[0].difficulty, tuple)

    def test_rows_are_frozen(self):
        import dataclasses
        row = data.rows("dungeon_list")[0]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            row.id = 1

    def test_load_returns_the_shared_body(self):
        self.assertIs(data.load("map_content"), data.load("map_content"))

    def test_a_declared_field_absent_from_a_record_loads_as_none(self):
        # `map_content.maps[0]` has no `startArea`; the union type says `| None`
        # and the loader has to honour it rather than raising.
        row = data.rows("map_content")[0]
        self.assertIsNone(row.startArea)
        self.assertEqual(row.id, 405)


if __name__ == "__main__":
    unittest.main()
