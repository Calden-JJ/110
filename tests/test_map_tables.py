"""The table-name mapping, and the three ways it could be silently wrong.

`data/tables/NNN_<slug>.json` files are numbered by the build order of the
exe's resource manifest.  Nothing in the data carries the number, so the
mapping is a claim -- and each of these is a way it could be a wrong one:

  * a *permutation*: pair the wrong manifest list with the index and all 69
    names shift.  `_names.json` is the same names alphabetised, so it is one
    zip away from doing exactly that.
  * a *truncation*: the previous `MANIFEST_REGION` end stopped one byte short
    of the 69th record, which yields a plausible-looking 68.
  * a *coincidence*: some tables the index records nothing to tell apart, so
    for those the order is the only evidence there is.

Each is pinned below.
"""
from __future__ import annotations

import functools
import json
import unittest

import _bootstrap  # noqa: F401

import map_tables
from uslocalserver import paths

EXPECTED_TABLES = 69
EXPECTED_DOMAINS = {"characters": 5, "dungeons": 26, "items": 31, "quests": 7}
EXPECTED_ANCHORED = 15

#: (i, name, fingerprint) -- every one of these must be confirmed by something
#: in the table body that is not the manifest position.
ANCHORS = (
    (4, "dye_content", "key:avatarTypes"),
    (15, "monster_experience", "source:monster/monsterexp.tbl"),
    (20, "equipment_specificity", "source:equipmentspecificity"),
    (23, "quest_content", "source:list/quest.lst"),
    (24, "image_communication", "source:imagecommunication.etc"),
    (30, "npc_shop_content", "source:list/itemshop.lst"),
    (31, "creature_content", "source:list/equipment.lst"),
    (34, "disjoint_content", "source:etc/disjoint.etc"),
    (35, "package_content", "key:packages"),
    (42, "buff_swap", "source:switchingsupportskill.etc"),
    (44, "dungeon_worldmap", "source:list/worldmap.lst"),
    (46, "map_content", "source:list/map.lst"),
    (52, "tournaments", "key:tournaments"),
    (60, "dusky_island_operations", "source:duskyisland.etc"),
    (62, "hell_party", "source:hell party"),
)

#: The anchors small enough to read back from disk, so the confirmation is
#: against real table bodies and not only against `_index.json`'s digest of
#: them.  Both fingerprint kinds are represented.
BODY_CHECKED = (15, 24, 44, 52, 60, 62)

#: Tables the index records nothing to separate: same kind, same entry count,
#: same top-level keys, same source.  For these the manifest order is the
#: whole of the evidence, so they are where it can actually cost something.
EXPECTED_INDISTINGUISHABLE = (
    (("quest_npc_ranges", 29), ("scenario_visits", 47)),
    (("dungeon_list", 43), ("dungeon_content", 45)),
    (("destroyed_castle_admission", 64), ("meister_admission", 65)),
)


@functools.lru_cache(maxsize=1)
def payload() -> dict:
    return map_tables.load()


@functools.lru_cache(maxsize=1)
def manifest() -> tuple[dict, ...]:
    return tuple(map_tables.read_manifest())


def tables() -> dict[str, dict]:
    return {t["name"]: t for t in payload()["tables"]}


def body(i: int) -> dict:
    entry = payload()["tables"][i]
    return json.loads((paths.TABLES_DIR / entry["file"]).read_text(encoding="utf-8"))


class Regeneration(unittest.TestCase):
    def test_output_is_reproducible_byte_for_byte(self):
        built = map_tables.build_payload(list(manifest()), map_tables.load_index())
        self.assertEqual(map_tables.render(built),
                         paths.TABLE_MAP.read_text(encoding="utf-8"))

    def test_the_committed_map_lists_the_same_tables_as_the_exe(self):
        self.assertEqual([(t["i"], t["name"], t["domain"]) for t in payload()["tables"]],
                         [(t["i"], t["name"], t["domain"]) for t in manifest()])


class Bijection(unittest.TestCase):
    def test_every_manifest_name_meets_exactly_one_document(self):
        row = payload()["tables"]
        self.assertEqual(len(row), EXPECTED_TABLES)
        self.assertEqual(len({t["name"] for t in row}), EXPECTED_TABLES)
        self.assertEqual(len({t["file"] for t in row}), EXPECTED_TABLES)
        self.assertEqual([t["i"] for t in row], list(range(EXPECTED_TABLES)))

    def test_the_file_number_matches_the_position(self):
        index = {e["i"]: e for e in map_tables.load_index()}
        for t in payload()["tables"]:
            self.assertEqual(t["file"], index[t["i"]]["file"])
            self.assertEqual(t["slug"], index[t["i"]]["slug"])

    def test_domain_counts(self):
        self.assertEqual(payload()["domains"], EXPECTED_DOMAINS)
        self.assertEqual(sum(EXPECTED_DOMAINS.values()), EXPECTED_TABLES)

    def test_the_names_are_the_ones_the_corpus_uses(self):
        names = tables()
        for name in ("map_content", "quest_content", "npc_shop_content",
                     "dungeon_worldmap", "destroyed_castle_growth"):
            self.assertIn(name, names)
        self.assertNotIn("", names)

    def test_a_table_lookup_never_goes_through_the_slug(self):
        # Nine documents share a slug with another document; `file` is the
        # identity, and the name is what game code asks for.
        dupes = payload()["duplicate_slugs"]
        self.assertEqual(dupes["list"], [8, 28, 29, 32, 47, 48, 49, 54])
        self.assertEqual(dupes["list_dungeon.lst"], [43, 45])
        self.assertEqual(dupes["Contents_2022_HigherDungeon_higher_dungeon_e"], [64, 65])


class Anchors(unittest.TestCase):
    def test_all_fifteen_are_confirmed(self):
        self.assertEqual([(a["i"], a["name"], a["fingerprint"])
                          for a in payload()["anchors"]], list(ANCHORS))

    def test_exactly_fifteen_tables_claim_a_fingerprint(self):
        counts = {}
        for t in payload()["tables"]:
            counts[t["confidence"]] = counts.get(t["confidence"], 0) + 1
        self.assertEqual(counts["anchored"], EXPECTED_ANCHORED)
        self.assertEqual(counts["manifest"], EXPECTED_TABLES - EXPECTED_ANCHORED)
        anchored = [t["i"] for t in payload()["tables"] if t["confidence"] == "anchored"]
        self.assertEqual(anchored, [i for i, _, _ in ANCHORS])

    def test_the_anchors_hold_against_the_table_bodies_themselves(self):
        # Not against `_index.json`: an anchor that only agrees with a digest
        # of the body would be checking the wrong link in the chain.
        for i in BODY_CHECKED:
            _, name, fingerprint = next(a for a in ANCHORS if a[0] == i)
            self.assertEqual(payload()["tables"][i]["name"], name)
            kind, token = fingerprint.split(":", 1)
            data = body(i)
            if kind == "source":
                self.assertIn(token, str(data.get("source", "")).lower(), name)
            else:
                self.assertIn(token, data, name)

    def test_the_two_anchors_that_correct_earlier_guesses(self):
        # Both were mis-numbered in the pre-manifest notes, which had 37 for
        # equipment_specificity and 30 for shop_content. The bodies name
        # themselves, so the old rows are simply wrong -- and 18, which the
        # notes never mentioned, is where shop_content really lives.
        self.assertEqual(tables()["equipment_specificity"]["i"], 20)
        self.assertEqual(tables()["npc_shop_content"]["i"], 30)
        self.assertEqual(tables()["shop_content"]["i"], 18)
        self.assertIn("equipmentspecificity", str(body(20)["Source"]).lower())
        # shop_content is a different table from npc_shop_content, and its
        # body does not claim list/itemshop.lst -- so the old row was two
        # errors, not one.
        self.assertNotIn("itemshop", str(body(18).get("source", "")).lower())


class AlphabeticalListing(unittest.TestCase):
    def test_it_holds_the_same_names_as_a_set(self):
        listed = map_tables.load_names()
        self.assertEqual(len(listed), EXPECTED_TABLES)
        got = sorted(t["name"] for t in payload()["tables"])
        want = sorted(map_tables.RESOURCE.search(e.encode()).group("name").decode()
                      for e in listed)
        self.assertEqual(got, want)

    def test_it_is_alphabetical_so_zips_into_a_permutation(self):
        listed = map_tables.load_names()
        self.assertEqual(listed, sorted(listed))
        self.assertNotEqual(listed, [t["name"] for t in payload()["tables"]])
        self.assertEqual(map_tables.RESOURCE.search(listed[0].encode())
                         .group("name").decode(), "character_stats")
        self.assertEqual(payload()["tables"][0]["name"], "cargo")


class Window(unittest.TestCase):
    """`MANIFEST_REGION` is a scan window, and the walk needs the whole record."""

    def test_the_walk_finds_sixty_nine(self):
        self.assertEqual(len(manifest()), EXPECTED_TABLES)

    def test_the_previous_end_stopped_one_byte_short(self):
        # Regression: with endpos at the old constant the last name -- which
        # starts on that very byte -- is excluded, and 68 tables look fine.
        with paths.EXE.open("rb") as fh:
            fh.seek(paths.MANIFEST_REGION[0])
            data = fh.read(map_tables.WINDOW)
        short = list(map_tables.RESOURCE.finditer(data, 0, 0x58F3572 - paths.MANIFEST_REGION[0]))
        self.assertEqual(len(short), EXPECTED_TABLES - 1)
        self.assertNotIn("destroyed_castle_growth",
                         [m.group("name").decode() for m in short])
        self.assertEqual(manifest()[-1]["name"], "destroyed_castle_growth")

    def test_the_walk_stops_at_the_crypto_namespace(self):
        # The listing carries on into USLocalServer.Protocol.Crypto.Tables.*;
        # that boundary, not an offset, is what ends the game-table section.
        self.assertEqual(manifest()[-1]["i"], EXPECTED_TABLES - 1)
        self.assertNotIn("algo06_misty1_s7", [t["name"] for t in payload()["tables"]])
        with paths.EXE.open("rb") as fh:
            fh.seek(paths.MANIFEST_REGION[0])
            data = fh.read(map_tables.WINDOW)
        boundary = map_tables.STOP.search(data).start()
        after = data[boundary:boundary + 200]
        self.assertIn(b"USLocalServer.Protocol.Crypto.Tables.algo06_misty1_s7.bin", after)


class Indistinguishable(unittest.TestCase):
    def test_the_pinned_pairs_are_exactly_the_indistinguishable_ones(self):
        groups = payload()["index_identical"]
        self.assertEqual(len(groups), len(EXPECTED_INDISTINGUISHABLE))
        names = {t["i"]: t["name"] for t in payload()["tables"]}
        self.assertEqual(
            [tuple((names[i], i) for i in g["i"]) for g in groups],
            list(EXPECTED_INDISTINGUISHABLE))

    def test_they_really_are_indistinguishable_in_the_index(self):
        index = {e["i"]: e for e in map_tables.load_index()}
        for group in EXPECTED_INDISTINGUISHABLE:
            digests = {json.dumps({
                "kind": index[i]["kind"],
                "entries": index[i]["entries"],
                "top_keys": sorted(index[i].get("top_keys") or ()),
                "source": index[i].get("source"),
            }, sort_keys=True) for _, i in group}
            self.assertEqual(len(digests), 1, group)

    def test_one_of_them_is_not_separable_by_source_either(self):
        # dungeon_list and dungeon_content both name "list/dungeon.lst", so a
        # source-only check would happily swap them.  Their bodies do differ,
        # but nothing the index records says so: same kind, same entry count,
        # same keys, same source.  (Compare small fields, never the lists --
        # `assertEqual` on two of these builds a difflib diff over ~400 KB of
        # repr and does not come back.)
        self.assertEqual(body(43)["source"], body(45)["source"])
        self.assertEqual(len(body(43)["dungeons"]), len(body(45)["dungeons"]))
        self.assertEqual(sorted(body(43)["dungeons"][0]), ["id", "path"])
        self.assertEqual(sorted(body(45)["dungeons"][0]),
                         ["basisLevel", "difficulty", "id", "minLevel"])


class Lookup(unittest.TestCase):
    def test_by_name_resolves_every_table(self):
        by_name = map_tables.by_name()
        self.assertEqual(len(by_name), EXPECTED_TABLES)
        entry = by_name["map_content"]
        self.assertEqual((entry["name"], entry["domain"], entry["i"]),
                         ("map_content", "dungeons", 46))
        self.assertTrue((paths.TABLES_DIR / entry["file"]).is_file())

    def test_every_referenced_file_exists(self):
        for t in payload()["tables"]:
            self.assertTrue((paths.TABLES_DIR / t["file"]).is_file(), t["file"])


if __name__ == "__main__":
    unittest.main()
