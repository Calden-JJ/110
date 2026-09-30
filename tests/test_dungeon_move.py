"""M3.2's room chain: the `(1,45)` request, its `(0,29)`, and `alive=k/n`.

Every frame below is the 09-28 capture's own plaintext, taken from the
`(0,29)` that answers one of its 16 moves; the seeds are read off those same
frames, since a run repeats its four bytes in every room it draws.  The ids
are the run's own arithmetic -- 53129's seven records are 7..13, the frame's,
and the count starts at 14 -- and the lines are the `DUNGEON-MOVE-45` lines
verbatim, `alive=k/n` and `N29=` included.

The two counts come apart in three rooms: 76126 draws eight records but
reads 5/8, its three story actors being records that never count; 53129
draws the five of table 046 plus table 049's two apcs and reads 5/7; and a
kill of any of those five records leaves the count where it was.
"""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

from uslocalserver.game.dungeon import die, entry, loaded, maze
from uslocalserver.game.dungeon.run import DungeonRun, DungeonSession

#: `(1,45)`'s 16 responses, three of them.  Dungeon 7115's room 53129, the
#: seven-record one (`1 2 3 4 0 | 1 0`, the last of each group zeroed).
MOVE_53129 = (
    "020000d5fb486100000100000000000000ffffffffffffffff00000000000001"
    "89cf0000070000000000000700f9f50000010000000000000000000100010000"
    "000800f9f50000010000000000000000000200020000000900f9f50000010000"
    "000000000000000300030000000a00fcf5000001000000000000000000040004"
    "0000000b00fcf50000010000000000000000000000000000000c003c01000001"
    "0500000000000000000100010000000d003d0100000105000000000000000000"
    "0000ff0000000000")
#: Dungeon 3's boss room: the boss 107000903 flags 0x03, the story actors
#: 109015589/75099/109015622 0x00, the four 109014870 0x00.
MOVE_76126 = (
    "0300007edee36400000100000000000000ffffffffffffffff00000000000001"
    "5e29010008000000000000240047b46006030300000000000000000100010000"
    "00250025727f060300000000000000000002000200000026005b250100030000"
    "000000000000000300030000002700566f7f0603000000000000000000040004"
    "0000002800566f7f06030000000000000000000500050000002900566f7f0603"
    "0000000000000000000600060000002a00566f7f060300000000000000000007"
    "00070000002b0046727f0603000000000000000000000000ff00000000000000")
#: Dungeon 6's second run: its start room is empty (48B, the `ff` marker and
#: no records), so 76143's four records are the run's first, 96..99.
MOVE_76143 = (
    "0100000cff160a00000100000000000000ffffffffffffffff00000000000001"
    "6f290100040000000000006000536f7f06070000000000000000000100010000"
    "006100536f7f06070000000000000000000200020000006200526f7f06070000"
    "000000000000000300030000006300526f7f0607000000000000000000000000"
    "ff00000000000000")
#: ... and the same run walking back in: 40B, map id 0xff00, no records.
REVISIT_76143 = (
    "0100000cff160a00000100000000000000ffffffffffffffff00000000000000"
    "00ff000000000000")
REVISIT_76144 = (
    "0200000cff160a00000100000000000000ffffffffffffffff00000000000000"
    "00ff000000000000")

#: Two `(1,39)` bodies, plaintext off the capture's wire: the 112B shape's
#: first byte names the story actor 109015589 of 76123, the 128B shape's the
#: second monster of the tutorial's first room.
DIED_112 = (
    "15000000ffff0000000000000000000000007e0000000000000000000000003d"
    "02a500000000010c6a073d020000a50000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000b16c8dcd00")
DIED_128 = (
    "0200000003000000000000000000000000005900000000000000010000000111"
    "010300010000000000000001008603f100000000005218002e030000f0000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000ea9083e0000000")


def _run(dungeon: int, maze_n: int, cell: tuple[int, int], map_id: int,
         seed: str, base: int) -> DungeonRun:
    run = DungeonRun(dungeon=dungeon, maze=maze_n, cell=cell, map_id=map_id,
                     seed=bytes.fromhex(seed), base=base)
    run.enter(map_id)
    return run


def _tutorial() -> DungeonRun:
    """Dungeon 7115's run, walked to its third room, 53129."""
    run = _run(7115, 0, (0, 0), 53127, "d5fb4861", 1)
    run.move_to((1, 0))
    run.move_to((2, 0))
    return run


def _boss_room() -> DungeonRun:
    """Dungeon 3's run, walked to its boss room, 76126."""
    run = _run(3, 1, (0, 1), 76121, "7edee364", 17)
    for cell in ((1, 1), (1, 0), (2, 0), (3, 0)):
        run.move_to(cell)
    return run


def _dungeon_six() -> DungeonRun:
    """Dungeon 6's second run: base 96, its empty start room, then 76143."""
    run = _run(6, 1, (0, 0), 76141, "0cff160a", 96)
    run.move_to((1, 0))
    return run


class RoomSpawnsTest(unittest.TestCase):
    def test_the_apcs_are_a_second_group(self):
        groups = maze.room_spawns(53129)
        self.assertEqual([len(group) for group in groups], [5, 2])
        self.assertEqual([spawn.monster for spawn in groups[1]], [316, 317])
        self.assertEqual([spawn.flags for spawn in groups[1]], [0x05, 0x05])
        self.assertEqual(maze.record_count(53129), 7)

    def test_the_boss_and_the_story_actors(self):
        records = [spawn for group in maze.room_spawns(76126)
                   for spawn in group]
        self.assertEqual(len(records), 8)
        self.assertEqual([spawn.flags for spawn in records],
                         [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        self.assertEqual([spawn.counts for spawn in records],
                         [True, False, False] + [True] * 4 + [False])

    def test_the_empty_room_has_none(self):
        self.assertEqual(maze.record_count(76141), 0)


class RoomFrameTest(unittest.TestCase):
    def test_the_seven_record_room(self):
        run = _tutorial()
        self.assertEqual((run.map_id, run.first_id), (53129, 7))
        self.assertEqual(entry.room_body(run, revisit=False).hex(), MOVE_53129)
        self.assertEqual(entry.content_len(53129, revisit=False), 195)

    def test_the_boss_room(self):
        run = _boss_room()
        self.assertEqual((run.map_id, run.first_id), (76126, 36))
        self.assertEqual(entry.room_body(run, revisit=False).hex(), MOVE_76126)

    def test_the_empty_start_room_leaves_the_ids_alone(self):
        run = _run(6, 1, (0, 0), 76141, "0cff160a", 96)
        self.assertEqual(entry.room_body(run, revisit=False)[40], 0xFF)
        self.assertEqual(len(entry.room_body(run, revisit=False)), 48)
        self.assertEqual(entry.content_len(76141, revisit=False), 43)
        run.move_to((1, 0))
        self.assertEqual(run.first_id, 96)
        self.assertEqual(entry.room_body(run, revisit=False).hex(), MOVE_76143)

    def test_a_revisit_is_forty_bytes(self):
        run = _dungeon_six()
        run.move_to((2, 0))
        self.assertTrue(run.move_to((1, 0)))
        self.assertEqual(entry.room_body(run, revisit=True).hex(), REVISIT_76143)
        self.assertEqual(entry.content_len(76143, revisit=True), 34)
        self.assertTrue(run.move_to((2, 0)))
        self.assertEqual(entry.room_body(run, revisit=True).hex(), REVISIT_76144)


class MoveNoteTest(unittest.TestCase):
    def test_a_first_visit_line(self):
        run = _tutorial()
        self.assertEqual(
            loaded.move_note(run, (1, 0), False),
            "dungeon=7115 maze=0 (1,0)->(2,0) map=53129 revisit=False "
            "alive=5/7 N29=195B")

    def test_the_boss_rooms_line(self):
        run = _boss_room()
        self.assertEqual(
            loaded.move_note(run, (2, 0), False),
            "dungeon=3 maze=1 (2,0)->(3,0) map=76126 revisit=False "
            "alive=5/8 N29=217B")

    def test_a_revisit_line(self):
        run = _dungeon_six()
        run.move_to((2, 0))
        for seq in range(96, 100):
            run.kill(seq)
        run.move_to((1, 0))
        self.assertEqual(
            loaded.move_note(run, (2, 0), True),
            "dungeon=6 maze=1 (2,0)->(1,0) map=76143 revisit=True "
            "alive=0/4 N29=34B")

    def test_the_move_answers_with_the_one_frame(self):
        session = DungeonSession(character_id=3, key=3, town=None)
        self.assertIsNone(loaded.move(session, (1, 0)))
        session.run = _tutorial()
        frames, text = loaded.move(session, (3, 0))
        self.assertEqual([opcode for opcode, _ in frames],
                         [entry.SPAWN_OPCODE])
        self.assertEqual(frames[0][1][0], 3)               # cell (3,0)
        self.assertEqual(text.split(" ")[2], "(2,0)->(3,0)")
        self.assertEqual(text.split(" ")[3], "map=53130")


class AliveTest(unittest.TestCase):
    def test_only_the_counted_records_move_the_count(self):
        run = _boss_room()
        self.assertEqual(run.alive(76126), (5, 8))
        run.kill(36)                                       # 107000903, the boss
        self.assertEqual(run.alive(76126), (4, 8))
        run.kill(43)                                       # 109015622, an actor
        self.assertEqual(run.alive(76126), (4, 8))
        run.kill(37)                                       # 109015589, another
        self.assertEqual(run.alive(76126), (4, 8))
        run.kill(39)
        self.assertEqual(run.alive(76126), (3, 8))

    def test_the_apcs_are_records_that_never_count(self):
        run = _tutorial()
        self.assertEqual(run.alive(53129), (5, 7))
        for seq in (7, 8, 9, 10, 11):
            run.kill(seq)
        self.assertEqual(run.alive(53129), (0, 7))

    def test_an_id_no_drawn_room_holds_is_ignored(self):
        """The capture's own refusal: id 43 while this run's rooms start at
        71 -- and 43 is a live id of the run before it."""
        run = _dungeon_six()
        self.assertEqual(run.alive(76143), (4, 4))
        run.kill(43)
        self.assertEqual(run.alive(76143), (4, 4))
        run.kill(96)
        self.assertEqual(run.alive(76143), (3, 4))


class DieSequenceTest(unittest.TestCase):
    def test_the_first_byte_is_the_sequence(self):
        self.assertEqual(len(bytes.fromhex(DIED_112)), 112)
        self.assertEqual(len(bytes.fromhex(DIED_128)), 128)
        self.assertEqual(die.sequence(bytes.fromhex(DIED_112)), 21)
        self.assertEqual(die.sequence(bytes.fromhex(DIED_128)), 2)


if __name__ == "__main__":
    unittest.main()
