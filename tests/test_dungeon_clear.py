"""M3.5's clear chain: the `(1,46)` five frames, the `(1,117)` check, and the
quest burst a boss-cell-clearing kill carries.

Every constant is the 09-28 capture's own plaintext -- the five reply bodies
are conn=4's wire, decrypted, and the lines are verbatim.  The `(0,35)` card
is the whole point of the chain: 257 + 29k bytes whose first 257 and last
three numbers the line reads, and the first captured one is 286B.

The boss burst's three frames are the capture's `(1,39)` answers, and its
`(0,21)` list is built from the shipped quest table with the character the
baseline seeds -- XJianHun, class 0, grow 1/0 -- at the level the kill lands
on: 3 for dungeon 3's boss, 5 for dungeon 5's.
"""
from __future__ import annotations

import sqlite3
import unittest

import _bootstrap  # noqa: F401

from uslocalserver.game.dungeon import blocks, cardpool, clear, die
from uslocalserver.game.dungeon.run import DungeonRun, DungeonSession
from uslocalserver.game.town import queststate

#: The tutorial clear, 21:10:47: its `(0,34)`, `(0,35)`, `(0,37)`, `(1,69)`
#: and `(1,70)` bodies in the order the wire carries them.
ACK_64769 = "0001FD00000000000000000000000000"
CARD_286 = (
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000120000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)
#: ... and the body that card goes out as: the line counts 286B, and the
#: `(0,35)` tile left two zero bytes past it.
CARD_286_BODY = CARD_286 + "0000"
EXP_480_1 = (
    "01E001000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
STAGE_BODY_8 = "0100000000000000"
STAGE_FLAGS_24 = "010100FFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000"

#: Dungeon 3's clear, 21:11:39, and dungeon 5's, 21:12:53: the two 315B cards.
CARD_315_3 = (
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000022000000000000000000000000000000000000000000000000E1383318010000000000000000000000000000000000000000000000000000000000000054010000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)
CARD_315_5 = (
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000001400000000000000000000000000000000000000000000000056F6CB18010000000000000000000000000000000000000000000000000000000000000044020000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

#: The two `(1,117)` requests, verbatim: `03 00` + the id, twelve zeros.
CHECK_36 = "03002400000000000000000000000000"
CHECK_68 = "03004400000000000000000000000000"
#: The `(0,115)` the capture answers both with.
BOSS_ACK_36 = "01012400000000000000000000000000"

#: The three lines, `conn=4 ` off the front.
TUTORIAL_NOTE = (
    "dungeon=7115 maze=0 cell=(3,0) clear=64769ms level=1 exp=480 -> "
    "(0,34) 9B + (0,37) 82B + (1,69) 1B + (1,70) 17B + (0,35) 286B "
    "free=1 paid=1 cost=100; source=C46/movie completion")
DUNGEON3_NOTE = (
    "dungeon=3 maze=1 cell=(3,0) clear=36268ms level=3 exp=2296 -> "
    "(0,34) 9B + (0,37) 82B + (1,69) 1B + (1,70) 17B + (0,35) 315B "
    "free=2 paid=1 cost=340; source=C46/movie completion")
DUNGEON5_NOTE = (
    "dungeon=5 maze=0 cell=(3,1) clear=32380ms level=5 exp=7338 -> "
    "(0,34) 9B + (0,37) 82B + (1,69) 1B + (1,70) 17B + (0,35) 315B "
    "free=2 paid=1 cost=580; source=C46/movie completion")
QUEST_COMBAT_NOTE = ("key=3 quest=3145 dungeon=3 difficulty=0 trigger=1->0")

#: The boss burst's `(0,342)`/`(0,291)`/`(0,21)` -- dungeon 3's kill, whose
#: character had finished nothing and carried 3145 at trigger 1.
FINISHED_EMPTY = "0000000000000000"
IN_PROGRESS_3145 = "0100490C000000000000000000000000"
AVAILABLE_LEVEL_3 = ("1C0000001003180820A11820A21820A31820A41820A51820A61820A7"
                     "1820A818")
AVAILABLE_LEVEL_5 = ("1C0000001005180820A11820A21820A31820A41820A51820A61820A7"
                     "1820A818")


def _run(dungeon: int, maze_n: int, cell: tuple[int, int], map_id: int,
         seed: str, base: int) -> DungeonRun:
    run = DungeonRun(dungeon=dungeon, maze=maze_n, cell=cell, map_id=map_id,
                     seed=bytes.fromhex(seed), base=base)
    run.enter(map_id)
    return run


def _tutorial_boss() -> DungeonRun:
    """Dungeon 7115's boss room, 53130 -- what the clear's line names."""
    run = _run(7115, 0, (0, 0), 53127, "d5fb4861", 1)
    for cell in ((1, 0), (2, 0), (3, 0)):
        run.move_to(cell)
    return run


def _dungeon_three_boss() -> DungeonRun:
    run = _run(3, 1, (0, 1), 76121, "7edee364", 17)
    for cell in ((1, 1), (1, 0), (2, 0), (3, 0)):
        run.move_to(cell)
    return run


def _session() -> DungeonSession:
    return DungeonSession(character_id=3, key=3, town=None)


class ClearFrameTest(unittest.TestCase):
    def test_the_clock_body_is_nine_bytes_padded_to_sixteen(self):
        body = clear.clear_ms_body(64769)
        self.assertEqual(len(body), 9)
        self.assertEqual(body.hex().upper(), ACK_64769[:18])
        self.assertEqual(clear.padded(clear.ACK_OPCODE, body).hex().upper(),
                         ACK_64769)

    def test_the_tutorials_five_frames_are_the_captured_ones(self):
        card = bytes.fromhex(CARD_286)[:286]
        result = clear.resolution(_tutorial_boss(), 1, 480, 64769, card)
        self.assertEqual([opcode for opcode, _ in result.frames],
                         [clear.ACK_OPCODE, clear.CARD_OPCODE, die.EXP_OPCODE,
                          clear.STAGE_OPCODE, clear.STAGE_FLAGS_OPCODE])
        self.assertEqual([body.hex().upper() for _, body in result.frames],
                         [ACK_64769, CARD_286_BODY, EXP_480_1, STAGE_BODY_8,
                          STAGE_FLAGS_24])
        self.assertEqual(result.note, TUTORIAL_NOTE)

    def test_the_clear_leaves_the_character_where_it_stands(self):
        result = clear.resolution(_dungeon_three_boss(), 3, 2296, 36268,
                                  bytes.fromhex(CARD_315_3)[:315])
        self.assertEqual((result.level, result.experience), (3, 2296))
        self.assertEqual(result.note, DUNGEON3_NOTE)

    def test_the_three_captured_cards_spell_their_purses(self):
        self.assertEqual(
            clear.card_purse(bytes.fromhex(CARD_286)[:286]), (1, 1, 100))
        self.assertEqual(
            clear.card_purse(bytes.fromhex(CARD_315_3)[:315]), (2, 1, 340))
        self.assertEqual(
            clear.card_purse(bytes.fromhex(CARD_315_5)[:315]), (2, 1, 580))

    def test_a_card_with_no_bytes_reads_no_purse(self):
        """The degenerate input `clear.resolution` still answers: an empty
        body goes out as it is, and the line counts 0B with three zeros.
        (`game._dungeon_clear` rolls a real card for a live clear.)"""
        result = clear.resolution(_tutorial_boss(), 1, 480, 64769, b"")
        self.assertEqual(len(result.frames), 5)
        self.assertEqual(result.frames[1][1], b"")            # (0,35) 0B
        self.assertEqual(
            result.note,
            "dungeon=7115 maze=0 cell=(3,0) clear=64769ms level=1 exp=480 -> "
            "(0,34) 9B + (0,37) 82B + (1,69) 1B + (1,70) 17B + (0,35) 0B "
            "free=0 paid=0 cost=0; source=C46/movie completion")
        self.assertEqual(clear.card_purse(b""), (0, 0, 0))

    def test_the_card_writer_reproduces_the_captured_cards(self):
        """`cardpool.card_bytes` off each card's own fields -- 286B with no
        item, and d3's and d5's 315B with theirs -- byte for byte."""
        cases = ((CARD_286, cardpool.Reward(free=1, gold=18, cost=100)),
                 (CARD_315_3, cardpool.Reward(free=2, gold=34, cost=340,
                                              items=((406010081, 1),))),
                 (CARD_315_5, cardpool.Reward(free=2, gold=20, cost=580,
                                              items=((416020054, 1),))))
        for text, reward in cases:
            card = bytes.fromhex(text)
            self.assertEqual(len(card), 257 + 29 * reward.free)
            self.assertEqual(cardpool.card_bytes(reward), card)
            self.assertEqual(clear.card_purse(card),
                             (reward.free, 1, reward.cost))


class BossCheckTest(unittest.TestCase):
    def test_the_target_sits_behind_the_two_byte_constant(self):
        self.assertEqual(clear.check_target(bytes.fromhex(CHECK_36)), 36)
        self.assertEqual(clear.check_target(bytes.fromhex(CHECK_68)), 68)

    def test_the_flags_read_the_rooms_the_run_has_drawn(self):
        run = _dungeon_three_boss()
        self.assertEqual(clear.check_flags(run, 36), (True, False))
        run.cleared.add(run.map_id)
        self.assertEqual(clear.check_flags(run, 36), (True, True))

    def test_an_id_of_no_drawn_room_is_invalid(self):
        """The 09-25 log's 51 sends: a target past every room drawn so far."""
        run = _dungeon_three_boss()
        self.assertEqual(clear.check_flags(run, 145), (False, False))
        self.assertEqual(clear.check_flags(run, 0), (False, False))

    def test_the_note_and_the_echo(self):
        self.assertEqual(clear.check_note(36, True, True),
                         "target=36 valid=True clear=True")
        self.assertEqual(blocks.boss_ack_body(36).hex().upper(), BOSS_ACK_36)


class BossBurstTest(unittest.TestCase):
    """`boss_burst` against the capture's own kill, on hand-built rows."""

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("create table character_finished_quests "
                          "(character_id integer, quest_id integer)")
        self.conn.execute("create table character_quest_progress "
                          "(character_id integer, quest_id integer, "
                          "trigger_value integer)")

    def tearDown(self):
        self.conn.close()

    def _accept(self, quest: int, trigger: int = 1) -> None:
        self.conn.execute("insert into character_quest_progress values (?, ?, ?)",
                          (3, quest, trigger))

    def test_the_room_to_quest_table(self):
        self.assertEqual(queststate.clear_map_quest(76126), (3145, 3))
        self.assertEqual(queststate.clear_map_quest(76136), (3146, 5))
        self.assertIsNone(queststate.clear_map_quest(53130))

    def test_the_dungeon_three_kill(self):
        self._accept(3145)
        burst = clear.boss_burst(self.conn, 3, 76126,
                                 queststate.Seeker(3, 0, 1, 0), key=3,
                                 difficulty=0)
        self.assertEqual([opcode for opcode, _ in burst.frames],
                         [queststate.FINISHED_OPCODE,
                          queststate.IN_PROGRESS_OPCODE,
                          queststate.AVAILABLE_OPCODE])
        self.assertEqual([body.hex().upper() for _, body in burst.frames],
                         [FINISHED_EMPTY, IN_PROGRESS_3145, AVAILABLE_LEVEL_3])
        self.assertEqual(burst.note, QUEST_COMBAT_NOTE)

    def test_the_kills_level_is_what_the_list_is_built_at(self):
        self._accept(3146)
        burst = clear.boss_burst(self.conn, 3, 76136,
                                 queststate.Seeker(5, 0, 1, 0), key=3,
                                 difficulty=0)
        self.assertEqual(burst.frames[2][1].hex().upper(), AVAILABLE_LEVEL_5)

    def test_the_trigger_write_is_what_the_frames_report(self):
        self._accept(3145)
        clear.boss_burst(self.conn, 3, 76126, queststate.Seeker(3, 0, 1, 0),
                         key=3, difficulty=0)
        self.assertEqual(
            self.conn.execute("select trigger_value from "
                              "character_quest_progress where quest_id = 3145")
            .fetchone()[0], 0)

    def test_a_room_no_clear_map_quest_names_is_silent(self):
        self.assertIsNone(clear.boss_burst(self.conn, 3, 53130,
                                           queststate.Seeker(1, 0, 1, 0),
                                           key=3, difficulty=0))


if __name__ == "__main__":
    unittest.main()
