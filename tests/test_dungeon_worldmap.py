"""`(0,5)`'s state byte: the highest set difficulty index.

The rule was first fitted to worldmap 2 alone, whose `difficulty` arrays are
all prefixes -- there "the number of set tiers minus one" and "the highest
set index" agree, and the first reading shipped.  Half the table (1,051 of
2,070 arrays) is not a prefix.  Worldmap 39 carries three of those --
316 `(0,0,0,1,0)`, 7539 `(0,0,1,0,0)`, 315 `(0,1,0,0,0)` -- the old rule
sent their state 0, and the client dropped the connection on 2026-09-30
(`Logs/server-rewrite.log`, the only worldmap-39 select on record).

The `REFERENCE` fixtures below are the reference logs' own `DUNGEON-SELECT-15`
lines, nodes and states copied out verbatim (one line per worldmap, 19
worldmaps across the logs; these seven carry every shape: states 0-4, prefix
and non-prefix arrays, and nodes table 045 has no row for).  They are the
evidence for the rule -- recompute them all with the old formula and 8,753
node states disagree.
"""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

from uslocalserver.game.dungeon import blocks

#: `(worldmap, nodes, states)`, one reference log line each.
REFERENCE = [
    (2, [3, 5, 6, 7, 8, 9, 1000, 7143, 240, 7164, 291100431, 291100432,
         100003693, 100003332],
     [0, 0, 0, 0, 0, 0, 0, 1, 3, 1, 3, 3, 0, 3]),
    (4, [21, 22, 24, 25, 26, 27, 9619, 100003313],
     [1, 1, 1, 1, 1, 1, 1, 0]),
    (6, [40, 41, 42, 43, 141, 45, 46],
     [2, 2, 2, 2, 2, 2, 2]),
    (7, [61, 50, 51, 52, 53, 242, 7123, 7146],
     [1, 1, 1, 1, 1, 1, 1, 1]),
    (12, [80, 81, 82, 88, 89, 83, 84, 85, 90, 2005, 5107, 7150, 9615, 9614,
          291100420, 291100424, 100002771],
     [2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 3, 1, 2, 3, 3, 3, 3]),
    # 5340..5345 have no table-045 row; the line sends 1 for all six.
    (49, [291100268, 291100293, 291100308, 291100309, 291100317, 291100319,
          5340, 5341, 5342, 5343, 5344, 5345, 7300, 7304, 7308, 7312, 7316,
          7327, 7322, 530, 7191, 291100371],
     [3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 4, 3]),
]

#: Worldmap 39, the bug4 crash: gate (30,2) of XRenYing's town.  No reference
#: line exists for it; this is the fixed rule's own output, and the three
#: nodes in the middle are the non-prefix ones that used to read 0.
CRASH_NODES = [310, 311, 312, 313, 314, 316, 317, 7539, 7155, 315,
               291100331, 291100318, 291100332, 9613, 9611, 9612,
               5406, 5407, 5335, 5336, 5337, 5338, 5339]
CRASH_STATES = [3, 3, 3, 3, 3, 3, 3, 2, 1, 1, 3, 1, 3, 3, 3, 3, 3, 3, 2, 2,
                2, 2, 2]


class ReferenceLineTest(unittest.TestCase):
    def test_every_logged_state_recomputes(self):
        for worldmap, nodes, states in REFERENCE:
            with self.subTest(worldmap=worldmap):
                self.assertEqual([blocks.node_state(n) for n in nodes], states)

    def test_the_states_text_is_the_logged_text(self):
        for worldmap, nodes, states in REFERENCE:
            with self.subTest(worldmap=worldmap):
                self.assertEqual(blocks.states_text(nodes),
                                 "[" + ",".join(map(str, states)) + "]")


class CrashWorldmapTest(unittest.TestCase):
    def test_worldmap_39_sends_the_last_set_tier(self):
        self.assertEqual(blocks.worldmap_nodes(39), CRASH_NODES)
        self.assertEqual(blocks.states_text(CRASH_NODES),
                         "[" + ",".join(map(str, CRASH_STATES)) + "]")

    def test_the_three_non_prefix_nodes(self):
        """The old rule sent 0 for all three; that is the state-0 frame the
        client answered with a dropped connection."""
        self.assertEqual([blocks.node_state(n) for n in (316, 7539, 315)],
                         [3, 2, 1])

    def test_the_refresh_copy_is_untouched(self):
        body = blocks.worldmap_body(CRASH_NODES, state=blocks.REFRESH_STATE)
        self.assertEqual(body[2 + 4], blocks.REFRESH_STATE)


class MissingRowTest(unittest.TestCase):
    def test_a_node_the_table_lacks_reads_one(self):
        """5340..5345: worldmap 49 lists them, table 045 has no row, and its
        own reference line sends 1 for all six."""
        self.assertEqual([blocks.node_state(n) for n in range(5340, 5346)],
                         [1, 1, 1, 1, 1, 1])

    def test_a_row_without_a_difficulty_array_reads_one(self):
        """7143/7164 of worldmap 2: logged rows, no array, logged state 1."""
        self.assertEqual([blocks.node_state(n) for n in (7143, 7164)], [1, 1])


if __name__ == "__main__":
    unittest.main()
