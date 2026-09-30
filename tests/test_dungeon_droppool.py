"""M3.5's live drops: `droppool.roll` over the corpus's own kills.

The roll has four rules and a test apiece.  A cinematic record -- the story
actors and hunt dummies -- leaves nothing: 150 corpus kills, none with a
drop.  A code table 050 gives a `monsters` pool is a box or a pot: 99 of 99
corpus kills dropped, the item weighted by the pool, so code 1's 50/100/200
weights on 1000/1004/1047 are the test's own distribution.  A Boss leaves
its gold and one equipment *every* kill -- the reference's own bosses did it
only about half the time (68 of 129 left gold, 80 an item), so the pair is
a deliberate richness: the amount re-rolls into the measured band and the
item comes off the corpus's own kills of that code.  Everything else rolls
the user's two independent chances -- 8% gold, 12% material -- whose item
pools come off the corpus's layers, deepest first.

Dungeon 3's 109014858 is the pair the capture killed most (33 kills, 29 of
them empty, four single-gold sets) and its own pair holds no material, so
the code layer's `world 3142` answers; dungeon 6's nine kills of the same
code are the fall-through that lands there too.  Gold is the one field
re-rolled: the corpus's amounts are samples of table 050's `gold[basisLevel]`
`[level, max, min]`, so a live amount lands anywhere inside the range -- the
test reads 100002627's basis 140 as `[15, 3072]` and expects amounts past
every one the corpus saw.
"""
from __future__ import annotations

import random
import unittest

import _bootstrap  # noqa: F401

from uslocalserver.game.dungeon import droppool, drops, maze
from uslocalserver.game.dungeon.maze import Spawn
from uslocalserver.game.shop import buy

#: Table 050's pool for code 1, and the pair rows dungeon 3's 109014858
#: holds -- both read back so the file and the table stay checkable here.
BOX_1 = ((1000, 50), (1047, 200), (1004, 100))
D3_TILE = [[[], 29], [[["gold", 0, 32]], 2], [[["gold", 0, 21]], 1],
           [[["gold", 0, 24]], 1]]

#: Dungeon 3's boss pair: two kills, each a gold and a type2 equipment.
D3_BOSS_PAIR = [[[["gold", 0, 23], ["type2", 400090160, 1]], 2],
                [[["gold", 0, 29], ["type2", 31303, 1]], 1]]

#: `gold[basisLevel]` as `(max, min)`: dungeons 3, 6 and 140 -- and the two
#: boss bands the same rows scale to (35..52 at basis 3 over its 34).
GOLD_RANGE_3 = (34, 15)
GOLD_RANGE_7 = (64, 15)
GOLD_RANGE_140 = (3072, 15)
BOSS_BAND_3 = (35, 52)
BOSS_BAND_5 = (49, 73)


def _spawn(code: int, *words: str) -> Spawn:
    return Spawn(monster=code, flags=0, counts=True, words=words)


def _boss(code: int) -> Spawn:
    return Spawn(monster=code, flags=maze.BOSS_FLAGS, counts=True,
                 words=("boss",))


class ObjectRuleTest(unittest.TestCase):
    """The boxes and pots: table 050's own pool, one item every kill."""

    def test_a_cinematic_record_leaves_nothing(self):
        rng = random.Random(0)
        self.assertEqual(droppool.roll(7115, _spawn(75099, "cinematic"),
                                       rng=rng), ())

    def test_an_object_draws_weighted_from_its_own_table_pool(self):
        self.assertEqual(droppool._object_pools()[1], BOX_1)
        rng = random.Random(7)
        facts = [droppool.roll(3, _spawn(1), rng=rng) for _ in range(300)]
        counts: dict[int, int] = {}
        for fact in facts:
            self.assertEqual(len(fact), 1)
            self.assertEqual(fact[0].kind, "monster")
            self.assertEqual(fact[0].value, 1)
            counts[fact[0].item] = counts.get(fact[0].item, 0) + 1
        self.assertEqual(set(counts), {1000, 1047, 1004})
        self.assertGreater(counts[1047], counts[1004])
        self.assertGreater(counts[1004], counts[1000])

    def test_an_equipment_pool_item_takes_a_live_uid(self):
        rng = random.Random(3)
        facts = [droppool.roll(7115, _spawn(62970), rng=rng)[0]
                 for _ in range(20)]
        for fact in facts:
            self.assertEqual((fact.item, fact.kind), (400320513, "monster"))
            self.assertGreaterEqual(fact.value, 1)
            self.assertLess(fact.value, buy.INSTANCE_LIMIT)
        self.assertGreater(len({fact.value for fact in facts}), 1)

    def test_the_frame_an_object_kill_sends(self):
        rng = random.Random(11)
        fact = droppool.roll(3, _spawn(1), rng=rng)
        rows = drops.rows(fact, 7)
        self.assertEqual(drops.note(rows), f"[7:{rows[0].item}x1/monster]")
        self.assertEqual(len(drops.body(16, rows)), 188)


class BossRuleTest(unittest.TestCase):
    """Rank Boss: its gold and one equipment, every single kill."""

    def test_the_pair_is_gold_then_the_corpus_own_equipment(self):
        self.assertEqual(droppool._pools()["pairs"]["3/107000903"],
                         D3_BOSS_PAIR)
        rng = random.Random(0)
        seen = set()
        for _ in range(200):
            facts = droppool.roll(3, _boss(107000903), rng=rng)
            self.assertEqual([f.kind for f in facts], ["gold", "type2"])
            self.assertTrue(BOSS_BAND_3[0] <= facts[0].value
                            <= BOSS_BAND_3[1])
            self.assertGreaterEqual(facts[1].value, 1)   # a live uid
            self.assertLess(facts[1].value, buy.INSTANCE_LIMIT)
            seen.add(facts[1].item)
        self.assertEqual(seen, {400090160, 31303})

    def test_the_band_scales_with_the_basis(self):
        """dungeon 5's row maxes at 48: 49..73 by the same 35/34..52/34."""
        self.assertEqual(droppool._gold_table()[5][0], 48)
        rng = random.Random(1)
        amounts = [droppool._boss_gold(5, rng) for _ in range(200)]
        self.assertTrue(all(BOSS_BAND_5[0] <= a <= BOSS_BAND_5[1]
                            for a in amounts))
        self.assertGreater(len(set(amounts)), 5)

    def test_a_boss_frame_carries_both_rows(self):
        facts = droppool.roll(3, _boss(107000903), rng=random.Random(2))
        rows = drops.rows(facts, 1)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(drops.body(7, rows)), 364)
        note = drops.note(rows)
        self.assertIn("/gold", note)
        self.assertIn("/type2", note)


class NormalRuleTest(unittest.TestCase):
    """The ordinary monster: 8% gold, 12% material, independently."""

    def test_the_rates_are_the_configured_ones(self):
        rng = random.Random(3)
        facts = [droppool.roll(3, _spawn(109014858), rng=rng)
                 for _ in range(4000)]
        gold = sum(1 for f in facts if any(e.kind == "gold" for e in f))
        mats = sum(1 for f in facts if any(e.kind != "gold" for e in f))
        self.assertAlmostEqual(gold / 4000, droppool.NORMAL_GOLD_CHANCE,
                               delta=0.015)
        self.assertAlmostEqual(mats / 4000, droppool.NORMAL_MATERIAL_CHANCE,
                               delta=0.018)

    def test_the_gold_amounts_reroll_inside_the_range(self):
        rng = random.Random(1)
        amounts = [f[0].value
                   for f in (droppool.roll(3, _spawn(109014858), rng=rng)
                             for _ in range(4000))
                   if f and f[0].kind == "gold"]
        low, high = GOLD_RANGE_3[1], GOLD_RANGE_3[0]
        self.assertTrue(amounts)
        self.assertTrue(all(low <= a <= high for a in amounts))
        self.assertGreater(len(set(amounts)), 3)     # the 3 observed amounts

    def test_the_material_comes_from_the_layers_own_pool(self):
        """Dungeon 3's own pair holds no material, so the walk lands on the
        code layer's `world 3142` -- the item its kills of the code left."""
        rng = random.Random(4)
        mats = [e for f in (droppool.roll(3, _spawn(109014858), rng=rng)
                            for _ in range(2000))
                for e in f if e.kind != "gold"]
        self.assertTrue(mats)
        self.assertEqual({(e.kind, e.item) for e in mats}, {("world", 3142)})

    def test_an_unseen_room_pools_the_global_materials(self):
        """A dungeon the corpus never killed in has no basis row, so no gold
        can re-roll -- the material still lands, off the global mix."""
        allowed = {entry[1] for entries, _ in droppool._pools()["global"]
                   for entry in entries if droppool._is_material(entry[1])}
        self.assertTrue(allowed)
        rng = random.Random(5)
        facts = [droppool.roll(999999, _spawn(999999), rng=rng)
                 for _ in range(400)]
        self.assertTrue(any(not fact for fact in facts))
        self.assertTrue(any(fact for fact in facts))
        for fact in facts:
            for entry in fact:
                self.assertIn(entry.item, allowed)

    def test_the_same_seed_is_the_same_roll(self):
        first = [droppool.roll(3, _spawn(109014858), rng=random.Random(9))
                 for _ in range(50)]
        second = [droppool.roll(3, _spawn(109014858), rng=random.Random(9))
                  for _ in range(50)]
        self.assertEqual(first, second)


class FactTest(unittest.TestCase):
    """The one re-rolled field, and the record values."""

    def test_the_amounts_run_past_every_observed_one(self):
        """Dungeon 100002627's basis 140 reads `[15, 3072]`; the pair's own
        six gold sets hold 201..1694, so a live max above 1694 is the range
        speaking, not the sets."""
        self.assertEqual(droppool._gold_table()[140], GOLD_RANGE_140)
        rng = random.Random(4)
        amounts = [entry.value
                   for fact in (droppool.roll(100002627, _spawn(109013660),
                                              rng=rng) for _ in range(2000))
                   for entry in fact if entry.kind == "gold"]
        self.assertTrue(amounts)
        self.assertTrue(all(15 <= a <= 3072 for a in amounts))
        self.assertGreater(max(amounts), 1694)

    def test_a_dungeon_past_the_table_keeps_the_observed_amount(self):
        self.assertNotIn(0, droppool._gold_table())
        self.assertEqual(droppool._gold(999999, 77, random.Random(6)), 77)

    def test_a_stackable_keeps_its_observed_count(self):
        fact = droppool._fact(["dcod-local-policy/pvf-material", 10333178, 8],
                              100002627, random.Random(0))
        self.assertEqual((fact.item, fact.kind, fact.value),
                         (10333178, "dcod-local-policy/pvf-material", 8))

    def test_an_equipment_item_takes_a_live_uid_wherever_it_comes_from(self):
        rng = random.Random(6)
        fact = droppool._fact(["type2", 10459, 1], 3, rng)
        self.assertEqual(fact.item, 10459)
        self.assertGreaterEqual(fact.value, 1)
        self.assertLess(fact.value, buy.INSTANCE_LIMIT)


if __name__ == "__main__":
    unittest.main()
