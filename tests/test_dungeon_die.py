"""M3.3's kill chain: the `(1,39)` request, its `(0,38)` and `(0,37)` replies,
and the branches the records pick.

Every constant is the 09-28 capture's own plaintext -- the reply bodies off
conn=4's wire, the lines verbatim -- and each run is rebuilt to the state the
capture's own order of `(1,39)` leaves behind: 76123's gold kill reads 3/5
because its first record is a story actor that never counts, and the boss room
reads 4/8 for the same reason.  The room 75099 is answered two different ways:
in dungeon 3's boss room, with four records still standing, it is a
`story/friendly actor, no experience`; in dungeon 5's, with nothing left, the
same monster confirms the `cinematic map objective`.  And the room-clear
suffix belongs to the kill that empties a room *other* than the boss cell --
dungeon 3's 76123 -- while the boss cell's own empty kill carries `(0,31)`.

The three refusals: the capture's own, which names 43 while the live run's
rooms start at 44, and the 09-25 log's 585 and 654, which pin `alive=` to the
room the run stands in rather than the session's id counter.
"""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

from uslocalserver.game.dungeon import blocks, die, drops
from uslocalserver.game.dungeon.run import DungeonRun, DungeonSession

#: The 128B `(1,39)` that killed 76123's 22 -- the capture's only gold drop.
DEATH_22 = (
    "160000000300000000000000000000000000930000000000000001000000011101"
    "03003C0000000000000001007502FA000000000142610000020000FE0000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000362F9556000000"
)
#: The 112B refusal shape: 43, a live id of the run before this one.
DEATH_43_REFUSED = (
    "2B330000FFFF000000000000000000000000000000000000000000000000000000"
    "000000000100FC6B0091010000F500000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000002FFC567A00"
)

#: `(0,38)` bodies, verbatim: one gold row, the boss room's two rows, and the
#: three empty ones (8B, the `00 00 ff 00` trailer and no records).
DROP_22_GOLD = (
    "160001000300000003000000000020000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000FFFF03000000FF00000000"
)
DROP_36_BOSS = (
    "240002000A0000000A000000000017000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000FFFF03000B0000000B0030E4D817DE489104003C00"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000FFFF03000000FF0000"
    "00"
)
DROP_15_CLEAR = "0F0000000000FF00"
DROP_43_ACTOR = "2B0000000000FF00"
DROP_23_ROOM_CLEAR = "170000000000FF00"
DROP_70_OBJECTIVE = "460000000000FF00"
DROP_4_EMPTY = "040000000000FF00"

ENABLE_BODY = "00000000000000000000000000000000"

#: `(0,37)` bodies: 96B -- the level byte, the cumulative total as u64le, a
#: zero byte at [12], then SP, SP, TP, TP as u16le at [13]/[15]/[17]/[19].
#: The sub-256 samples cannot separate this reading from a big-endian one two
#: bytes left; the level-55 frame can, and does.  Six off the capture's wire.
EXP_150_1 = (
    "019600000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
EXP_480_1 = (
    "01E001000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
EXP_880_1 = (
    "017003000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
EXP_1040_2 = (
    "021004000000000000000000001E001E0000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
EXP_1120_2 = (
    "026004000000000000000000001E001E0000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
EXP_2000_2 = (
    "02D007000000000000000000001E001E0000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
#: Dungeon 6's basis level 7, the capture's last exp line.
EXP_13780_7 = (
    "07D43500000000000000000000B400B40000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
#: The 09-30 save's level-55 kill (dungeon 3, +3 exp): 985 = `d9 03` little
#: endian at [13], TP 6 at [17]/[19], [12] zero -- the frame that tells the
#: little-endian reading from the big-endian one the sub-256 samples allow.
EXP_90427461_55 = (
    "3745D063050000000000000000D903D90306000600" "000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)

#: The notes, `conn=4 ` off the front.
GOLD_NOTE = (
    "dungeon=3 map=76123 seq=22 code=109014858 monsterLevel=3 rank=Normal "
    "cleanup=0 hellGroup=0 hellOrder=0 drops=[3:0x32/gold] died; "
    "+80 exp (base=80, contractBonus=0) -> total=880 level=1; alive=3/5 "
    "cell=(1,1) boss=(3,0) -> 2 frame(s)")
BOSS_NOTE = (
    "dungeon=3 map=76126 seq=36 code=107000903 monsterLevel=3 rank=Boss "
    "cleanup=0 hellGroup=0 hellOrder=0 "
    "drops=[10:0x23/gold,11:400090160x1/type2] died; "
    "+80 exp (base=80, contractBonus=0) -> total=2000 level=2; alive=4/8 "
    "cell=(3,0) boss=(3,0) -> 2 frame(s)")
LEVEL_UP_NOTE = (
    "dungeon=3 map=76123 seq=24 code=109014858 monsterLevel=3 rank=Normal "
    "cleanup=0 hellGroup=0 hellOrder=0 drops=[] died; "
    "+80 exp (base=80, contractBonus=0) -> total=1040 level=2 "
    "**LEVEL UP** from 1; alive=1/5 cell=(1,1) boss=(3,0) -> 2 frame(s)")
ROOM_CLEAR_NOTE = (
    "dungeon=3 map=76123 seq=23 code=109014862 monsterLevel=3 rank=Normal "
    "cleanup=0 hellGroup=0 hellOrder=0 drops=[] died; "
    "+80 exp (base=80, contractBonus=0) -> total=1120 level=2; alive=0/5 "
    "cell=(1,1) boss=(3,0) -> 2 frame(s) (room clear; dungeon clear conditions "
    "pending or already acknowledged)")
CLEAR_NOTE = (
    "dungeon=7115 map=53130 seq=15 code=62965 monsterLevel=1 rank=Normal "
    "cleanup=0 hellGroup=0 hellOrder=0 drops=[] died; "
    "+30 exp (base=30, contractBonus=0) -> total=480 level=1; alive=0/5 "
    "cell=(3,0) boss=(3,0) -> 3 frame(s) including (0,31) ENABLE_CLEAR "
    "(boss room cleared)")
ACTOR_NOTE = (
    "dungeon=3 map=76126 seq=43 code=109015622 monsterLevel=3 rank=Normal "
    "cleanup=0 hellGroup=0 hellOrder=0 drops=[] died; "
    "story/friendly actor, no experience; alive=5/8 cell=(3,0) boss=(3,0) "
    "-> 1 frame(s)")
OBJECTIVE_NOTE = (
    "dungeon=5 map=76136 seq=70 code=75099 monsterLevel=5 rank=Normal "
    "cleanup=0 hellGroup=0 hellOrder=0 drops=[] died; "
    "+0 exp (base=0, contractBonus=0) -> total=7338 level=5; "
    "cinematic map objective confirmed; alive=0/11 cell=(3,1) boss=(3,1) "
    "-> 1 frame(s) (room clear; dungeon clear conditions pending or already "
    "acknowledged)")
REFUSAL_NOTE = (
    f"could not find a live monster sequence in the request "
    f"(plain={DEATH_43_REFUSED}, alive=44); ignoring")


def _run(dungeon: int, maze_n: int, cell: tuple[int, int], map_id: int,
         seed: str, base: int) -> DungeonRun:
    run = DungeonRun(dungeon=dungeon, maze=maze_n, cell=cell, map_id=map_id,
                     seed=bytes.fromhex(seed), base=base)
    run.enter(map_id)
    return run


def _dungeon_three() -> DungeonRun:
    """Dungeon 3's run, walked to 76123 -- ids 21..25, the first a story
    actor."""
    run = _run(3, 1, (0, 1), 76121, "7edee364", 17)
    run.move_to((1, 1))
    return run


def _boss_room() -> DungeonRun:
    """Dungeon 3's run, walked to its boss room, 76126."""
    run = _run(3, 1, (0, 1), 76121, "7edee364", 17)
    for cell in ((1, 1), (1, 0), (2, 0), (3, 0)):
        run.move_to(cell)
    return run


def _tutorial_boss() -> DungeonRun:
    """Dungeon 7115's run, walked to its boss room, 53130."""
    run = _run(7115, 0, (0, 0), 53127, "d5fb4861", 1)
    for cell in ((1, 0), (2, 0), (3, 0)):
        run.move_to(cell)
    return run


def _dungeon_five_boss() -> DungeonRun:
    """Dungeon 5's run, walked to its boss room, 76136 -- ids 60..70, the last
    two the story actor 69 and the dummy 70."""
    run = _run(5, 0, (0, 0), 76131, "6ac82500", 44)
    for cell in ((0, 1), (1, 1), (2, 1), (3, 1)):
        run.move_to(cell)
    return run


def _resolve(session: DungeonSession, run: DungeonRun, seq: int,
             exp_before: int, facts: tuple[drops.Fact, ...] = ()) -> die.Resolution:
    """The handler's own path: the id is recorded first, the kill second."""
    map_id, spawn = run.kill(seq)
    return die.resolution(session, run, map_id, spawn, seq,
                          die.Play(exp_before=exp_before, drops=facts))


class DieArithmeticTest(unittest.TestCase):
    def test_the_level_thresholds(self):
        self.assertEqual(die.level_for(999), 1)
        self.assertEqual(die.level_for(1000), 2)
        self.assertEqual(die.level_for(1040), 2)
        self.assertEqual(die.level_for(2034), 2)
        self.assertEqual(die.level_for(2035), 3)

    def test_the_base_experience_below_the_monster(self):
        self.assertEqual(die.base_experience(1, 1), 30)
        self.assertEqual(die.base_experience(3, 1), 80)        # 72 x 10/9
        self.assertEqual(die.base_experience(3, 2), 80)
        self.assertEqual(die.base_experience(3, 3), 72)
        self.assertEqual(die.base_experience(5, 5), 95)
        self.assertEqual(die.base_experience(7, 7), 120)

    def test_the_base_experience_above_the_monster(self):
        self.assertEqual(die.base_experience(3, 55), 3)        # 72 x 3/55

    def test_the_sp_column(self):
        self.assertEqual([die.sp_for(level) for level in (1, 2, 3, 5, 7)],
                         [0, 30, 60, 120, 180])

    def test_the_remaining_sp_comes_off_the_skill_rows(self):
        self.assertEqual(die.spent_for(1, [(54, 14), (7, 15)]), (575, 0))
        self.assertEqual(die.spent_for(1, [(99999, 5)]), (0, 0))
        self.assertEqual(die.remaining(55, (4010, 0)), (910, 6))
        self.assertEqual(die.remaining(2, (12, 0)), (18, 0))
        self.assertEqual(die.remaining(1, (50, 0)), (0, 0))    # clamped


class ExpFrameTest(unittest.TestCase):
    def test_the_first_kill_of_the_capture(self):
        self.assertEqual(die.exp_body(1, 150, 0, 0).hex().upper(), EXP_150_1)

    def test_a_second_level_frame(self):
        self.assertEqual(
            die.exp_body(2, 1120, die.sp_for(2), die.tp_for(2)).hex().upper(),
            EXP_1120_2)

    def test_the_level_up_frame_carries_the_new_level(self):
        self.assertEqual(die.exp_body(2, 1040, 30, 0).hex().upper(), EXP_1040_2)

    def test_the_dungeon_six_frame(self):
        self.assertEqual(
            die.exp_body(7, 13780, die.sp_for(7), die.tp_for(7)).hex().upper(),
            EXP_13780_7)

    def test_the_level_55_frame_pins_the_little_endian_reading(self):
        self.assertEqual(die.exp_body(55, 90427461, 985, 6).hex().upper(),
                         EXP_90427461_55)


class DropFrameTest(unittest.TestCase):
    def test_the_gold_row_spells_its_amount_in_decimal(self):
        rows = drops.rows((drops.Fact(0, 32, "gold"),), 3)
        self.assertEqual(drops.note(rows), "[3:0x32/gold]")
        self.assertEqual(drops.body(22, rows).hex().upper(), DROP_22_GOLD)

    def test_the_two_row_boss_kill(self):
        rows = drops.rows((drops.Fact(0, 23, "gold"),
                           drops.Fact(400090160, 76630238, "type2")), 10)
        self.assertEqual(drops.note(rows),
                         "[10:0x23/gold,11:400090160x1/type2]")
        self.assertEqual(drops.body(36, rows).hex().upper(), DROP_36_BOSS)
        self.assertEqual(drops.records(bytes.fromhex(DROP_36_BOSS)),
                         ((0, 23), (400090160, 76630238)))

    def test_an_empty_answer_is_eight_bytes(self):
        self.assertEqual(drops.body(4, ()).hex().upper(), DROP_4_EMPTY)


class ResolutionTest(unittest.TestCase):
    def test_the_gold_kill(self):
        session = DungeonSession(character_id=3, key=3, town=None)
        session.next_ground = 3
        run = _dungeon_three()
        result = _resolve(session, run, 22, 800,
                          (drops.Fact(0, 32, "gold"),))
        self.assertEqual([opcode for opcode, _ in result.frames],
                         [die.DROP_OPCODE, die.EXP_OPCODE])
        self.assertEqual(result.frames[0][1].hex().upper(), DROP_22_GOLD)
        self.assertEqual(result.frames[1][1].hex().upper(), EXP_880_1)
        self.assertEqual(result.note, GOLD_NOTE)
        self.assertEqual((result.level, result.experience), (1, 880))
        self.assertEqual(session.next_ground, 4)

    def test_the_boss_kill(self):
        session = DungeonSession(character_id=3, key=3, town=None)
        session.next_ground = 10
        run = _boss_room()
        run.kill(43)                               # the actor, one line earlier
        result = _resolve(session, run, 36, 1920,
                          (drops.Fact(0, 23, "gold"),
                           drops.Fact(400090160, 76630238, "type2")))
        self.assertEqual(result.frames[0][1].hex().upper(), DROP_36_BOSS)
        self.assertEqual(result.frames[1][1].hex().upper(), EXP_2000_2)
        self.assertEqual(result.note, BOSS_NOTE)
        self.assertEqual(session.next_ground, 12)

    def test_the_level_up_and_the_room_clear(self):
        session = DungeonSession(character_id=3, key=3, town=None)
        run = _dungeon_three()
        _resolve(session, run, 22, 800)
        _resolve(session, run, 25, 880)
        up = _resolve(session, run, 24, 960)
        self.assertEqual(up.note, LEVEL_UP_NOTE)
        self.assertEqual(up.frames[1][1].hex().upper(), EXP_1040_2)
        cleared = _resolve(session, run, 23, 1040)
        self.assertEqual(cleared.note, ROOM_CLEAR_NOTE)
        self.assertEqual(cleared.frames[1][1].hex().upper(), EXP_1120_2)
        self.assertEqual(len(cleared.frames), 2)   # 76123 is not the boss cell

    def test_the_tutorials_boss_room_clears(self):
        session = DungeonSession(character_id=3, key=3, town=None)
        session.next_ground = 3
        run = _tutorial_boss()
        for seq in (14, 18, 17, 16):
            run.kill(seq)
        result = _resolve(session, run, 15, 450)
        self.assertEqual([opcode for opcode, _ in result.frames],
                         [die.DROP_OPCODE, die.EXP_OPCODE, blocks.ENABLE_OPCODE])
        self.assertEqual(result.frames[0][1].hex().upper(), DROP_15_CLEAR)
        self.assertEqual(result.frames[1][1].hex().upper(), EXP_480_1)
        self.assertEqual(result.frames[2][1].hex().upper(), ENABLE_BODY)
        self.assertEqual(result.note, CLEAR_NOTE)

    def test_the_actor_with_the_room_still_full(self):
        session = DungeonSession(character_id=3, key=3, town=None)
        run = _boss_room()
        result = _resolve(session, run, 43, 1920)
        self.assertEqual([opcode for opcode, _ in result.frames],
                         [die.DROP_OPCODE])
        self.assertEqual(result.frames[0][1].hex().upper(), DROP_43_ACTOR)
        self.assertEqual(result.note, ACTOR_NOTE)

    def test_the_objective_only_comes_once_the_room_is_empty(self):
        session = DungeonSession(character_id=3, key=3, town=None)
        run = _dungeon_five_boss()
        for seq in range(60, 68):
            run.kill(seq)
        _resolve(session, run, 68, 7243)           # the boss, and the (0,31)
        result = _resolve(session, run, 70, 7338)  # the dummy, one line later
        self.assertEqual([opcode for opcode, _ in result.frames],
                         [die.DROP_OPCODE])
        self.assertEqual(result.frames[0][1].hex().upper(), DROP_70_OBJECTIVE)
        self.assertEqual(result.note, OBJECTIVE_NOTE)


class RefusalTest(unittest.TestCase):
    def test_the_captures_refusal_line(self):
        plain = bytes.fromhex(DEATH_43_REFUSED)
        self.assertEqual(len(plain), 112)
        self.assertEqual(die.sequence(plain), 43)
        self.assertEqual(die.refusal_note(plain, 44), REFUSAL_NOTE)

    def test_the_start_room_that_has_nothing_standing_but_an_actor(self):
        session = DungeonSession(character_id=3, key=3, town=None)
        session.next_id = 44
        run = session.begin(5, 0)
        self.assertEqual((run.base, run.map_id), (44, 76131))
        self.assertEqual(run.live_id(), 44)

    def test_the_lowest_id_still_standing(self):
        """The 09-25 log's 76254: 584/586/587/588 down, the next up is 585."""
        run = _run(50, 2, (2, 2), 76254, "00000000", 584)
        for seq in (584, 586, 587, 588):
            run.kill(seq)
        self.assertEqual(run.live_id(), 585)

    def test_a_room_walked_into_a_second_ago(self):
        """... and 76307's single record, read 654 a second after entry."""
        run = _run(51, 1, (2, 1), 76307, "00000000", 654)
        self.assertEqual(run.live_id(), 654)


if __name__ == "__main__":
    unittest.main()
