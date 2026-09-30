"""M3.6's flip chain and settlement: `(1,69)`/`(1,70)`/`(1,71)` and `(1,72)`.

Every constant is the 09-28 capture's own -- the four `(1,71)` requests and
lines, the three `(1,72)` sends, the state frames' two sizes, and the town
pair the settlement builds from the row at (38,2) pos=(89,249) dir=4.  The
save tests replay the two fed commits the diff feeds (`diff_dungeon.
commit_feed`) and the story settle's retry, which the live save's own
in-progress quest 3147 opens -- `entry.retry_quest` finds the same dungeon 6,
maze 1 the reference's line names.
"""
from __future__ import annotations

import random
import shutil
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401
import _save

from uslocalserver import paths
from uslocalserver.game.dungeon import card, cardpool, clear, reward, settle
from uslocalserver.game.dungeon.run import DungeonRun, DungeonSession
from uslocalserver.game.item import refresh
from uslocalserver.game.shop import buy
from uslocalserver.game.town import movement, queststate
from uslocalserver.persistence import characters, items, materials, schema

CHARACTER = 3
KEY = 3
NOW = 1_790_600_000

#: The two `(1,71)` requests: the side index and seven zeros.
COMMIT_FREE = bytes(8)
COMMIT_PAID = b"\x01" + bytes(7)

#: The three `(1,72)` sends of the capture and the silent one after the
#: story's (run#525): state, option, context, thirteen zeros.
SETTLE_OPT2 = bytes.fromhex("01020100000000000000000000000000")
SETTLE_OPT3 = bytes.fromhex("01030100000000000000000000000000")
SETTLE_OPT1 = bytes.fromhex("01010100000000000000000000000000")
SETTLE_SILENT = bytes.fromhex("01030100000000000000000000000000")
STATE_TWO = bytes.fromhex("02020100000000000000000000000000")

#: The stage replies: `01` and `01 01 00` + fourteen `ff`, padded by tile.
STAGE_REPLY = bytes.fromhex("0100000000000000")
STAGE_FLAGS_REPLY = bytes.fromhex(
    "010100ffffffffffffffffffffffffffff00000000000000")

#: The four acks: option 2 -> 2, option 3 -> 3, option 1 -> 0, and the
#: story's follow-up counting the attempt the story advanced to.
ACK_OPT2 = bytes.fromhex("01010200000000000000000000000000")
ACK_OPT3 = bytes.fromhex("01010300000000000000000000000000")
ACK_OPT1 = bytes.fromhex("01010000000000000000000000000000")
ACK_OPT3_ATTEMPT2 = bytes.fromhex("01020300000000000000000000000000")

#: The two state frames, verbatim, and the dungeon-5 paid one.
STATE_FREE = bytes.fromhex(
    "0100ff00" + "00ffff00" * 7 + "0000000000000000")
STATE_PAID_31002 = bytes.fromhex(
    "010000011a79000001000000" + "00ffff00" * 7 + "0000000000000000")
STATE_PAID_22001 = bytes.fromhex(
    "01000001f155000001000000" + "00ffff00" * 7 + "0000000000000000")

#: The `(1,72)` town triple off run#372's wire: the row at the gate area.
TOWN_ACK = bytes.fromhex("01030001000000000000000000000000")
TOWN_23 = bytes.fromhex("030026000000020000005900f9000401")
TOWN_24 = bytes.fromhex("2600000002000000010003005900f90004010100")

#: The dungeon-3 card, cut to the 315B the clear line counts.  `card_purse`
#: reads free=2, paid=1, cost=340 off it and `Result.of` the +34 gold.
CARD_315 = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000200000000220000000000000000000000000000000000000000000000"
    "00e1383318010000000000000000000000000000000000000000000000000000"
    "0000000000540100000000000000000000000000000000000000000000000000"
    "0001000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000")

#: The four `DUNGEON-CARD-71` lines, verbatim.
NOTE_71_D3_FREE = (
    "key=3 dungeon=3 run=b67cba62cbe745b485f6704c6556dae1 side=0 cost=0 "
    "goldDelta=34 balance=5066 rewards=0x34,406010081x1 committed")
NOTE_71_D3_PAID = (
    "key=3 dungeon=3 run=b67cba62cbe745b485f6704c6556dae1 side=1 cost=340 "
    "goldDelta=-340 balance=4726 rewards=31002x1 committed")
NOTE_71_D5_FREE = (
    "key=3 dungeon=5 run=ec0fe4f93495404cb08c6a274d4eaef1 side=0 cost=0 "
    "goldDelta=20 balance=4785 rewards=0x20,416020054x1 committed")
NOTE_71_D5_PAID = (
    "key=3 dungeon=5 run=ec0fe4f93495404cb08c6a274d4eaef1 side=1 cost=580 "
    "goldDelta=-580 balance=4205 rewards=22001x1 committed")

#: The `DUNGEON-CARD-STAGE` and `SETTLEMENT-72` prose, verbatim.
STAGE_NOTE = "key=3 opcode=69 free=True paid=False"
STAGE_FLAGS_NOTE = "key=3 opcode=70 free=True paid=True"
SETTLE_NOTE_OPT2 = (
    "key=3 dungeon=3 state=1 option=2 context=1 replay=False -> 4 frame(s)")
SETTLE_NOTE_OPT3 = (
    "key=3 dungeon= state=1 option=3 context=1 replay=True -> 1 frame(s)")
SETTLE_NOTE_STORY = (
    "key=3 dungeon=5 state=1 option=1 context=1 replay=False -> 7 frame(s)")
STORY = "story quest=3146 -> quest=3147 dungeon=6; native retry pending"


def _save_copy() -> Path:
    # The 0.4.4 save ships one character; the ids this module names
    # are cloned from it so the foreign keys resolve.
    return _save.fresh(CHARACTER, 1, 2, 3)


def _run(dungeon: int) -> DungeonRun:
    run = DungeonRun(dungeon=dungeon, maze=0, cell=(0, 0), map_id=76121,
                     seed=bytes.fromhex("6ac82500"), base=1)
    run.enter(76121)
    return run


def _result(dungeon: int, cost: int, gold: int, run_id: str) -> "card.Result":
    return card.Result(dungeon=dungeon, cost=cost, gold=gold,
                       run_id=bytes.fromhex(run_id))


def _record(slot: int, item: int, value: int) -> refresh.SlotRecord:
    return refresh.SlotRecord(slot_index=slot, item_id=item, value=value)


class RequestTest(unittest.TestCase):
    def test_the_commit_reads_only_its_side_byte(self):
        self.assertEqual(card.COMMIT_BODY_SIZE, 8)
        self.assertEqual(card.side_of(COMMIT_FREE), 0)
        self.assertEqual(card.side_of(COMMIT_PAID), 1)

    def test_the_settle_reads_state_option_context(self):
        self.assertEqual(settle.SETTLE_BODY_SIZE, 16)
        self.assertEqual(settle.request_fields(SETTLE_OPT2), (1, 2, 1))
        self.assertEqual(settle.request_fields(SETTLE_OPT3), (1, 3, 1))
        self.assertEqual(settle.request_fields(SETTLE_OPT1), (1, 1, 1))


class BodyTest(unittest.TestCase):
    def test_the_stage_replies(self):
        self.assertEqual(clear.padded(clear.STAGE_OPCODE, clear.STAGE_BODY),
                         STAGE_REPLY)
        self.assertEqual(
            clear.padded(clear.STAGE_FLAGS_OPCODE, clear.STAGE_FLAGS_BODY),
            STAGE_FLAGS_REPLY)

    def test_the_state_frames(self):
        self.assertEqual(card.state_body(None), STATE_FREE)
        self.assertEqual(len(card.state_body(None)), 40)
        self.assertEqual(card.state_body(31002), STATE_PAID_31002)
        self.assertEqual(card.state_body(22001), STATE_PAID_22001)
        self.assertEqual(len(card.state_body(31002)), 48)

    def test_the_acks(self):
        self.assertEqual(settle.ack_body(0, 2), ACK_OPT2)
        self.assertEqual(settle.ack_body(0, 3), ACK_OPT3)
        self.assertEqual(settle.ack_body(0, 1), ACK_OPT1)
        self.assertEqual(settle.ack_body(1, 3), ACK_OPT3_ATTEMPT2)


class NoteTest(unittest.TestCase):
    def test_the_commit_lines(self):
        d3 = _result(3, 340, 34, "b67cba62cbe745b485f6704c6556dae1")
        d5 = _result(5, 580, 20, "ec0fe4f93495404cb08c6a274d4eaef1")
        self.assertEqual(
            card.commit_note(KEY, d3, 0, 0, 34, 5066, (_record(12, 406010081, 1),)),
            NOTE_71_D3_FREE)
        self.assertEqual(
            card.commit_note(KEY, d3, 1, 340, -340, 4726, (_record(13, 31002, 1),)),
            NOTE_71_D3_PAID)
        self.assertEqual(
            card.commit_note(KEY, d5, 0, 0, 20, 4785, (_record(10, 416020054, 1),)),
            NOTE_71_D5_FREE)
        self.assertEqual(
            card.commit_note(KEY, d5, 1, 580, -580, 4205, (_record(14, 22001, 1),)),
            NOTE_71_D5_PAID)

    def test_the_gold_marker_is_decimal_and_the_items_follow(self):
        # `0x34` and `0x20` are the capture's, both decimal deltas behind the
        # marker.  A stackable prints its record's value, anything else x1.
        self.assertEqual(card.rewards_text(34, (_record(12, 406010081, 1),)),
                         "0x34,406010081x1")
        self.assertEqual(card.rewards_text(-340, ()), "")
        self.assertEqual(card.rewards_text(20, (_record(65, 1001, 5),)),
                         "0x20,1001x5")

    def test_the_stage_and_settle_lines(self):
        flipped = card.Result(dungeon=3, free=True, paid=False)
        self.assertEqual(card.stage_note(KEY, 69, flipped), STAGE_NOTE)
        flipped = card.Result(dungeon=5, free=True, paid=True)
        self.assertEqual(card.stage_note(KEY, 70, flipped), STAGE_FLAGS_NOTE)
        self.assertEqual(
            settle.settle_note(KEY, _run(3), 1, 2, 1, False, 4),
            SETTLE_NOTE_OPT2)
        self.assertEqual(
            settle.settle_note(KEY, None, 1, 3, 1, True, 1),
            SETTLE_NOTE_OPT3)
        self.assertEqual(
            settle.story_line(queststate.prerequisite(3147), 3147, 6), STORY)


class CardPoolTest(unittest.TestCase):
    """The live roll: the corpus's own rows for a dungeon the capture played,
    and the file's fallback for one it did not."""

    def test_the_writer_reproduces_the_captured_card(self):
        reward = cardpool.Reward(free=2, gold=34, cost=340,
                                 items=((406010081, 1),))
        self.assertEqual(len(CARD_315), 257 + 29 * reward.free)
        self.assertEqual(cardpool.card_bytes(reward), CARD_315)

    def test_a_corpus_dungeon_rolls_its_own_rows(self):
        """d3's two observed rows carry 32 and 34 gold -- both already past
        the floor -- and the item-less one draws the fill-in 40% of the
        time, off the corpus-wide pool."""
        rng = random.Random(0)
        seen = set()
        for _ in range(200):
            reward = cardpool.roll(3, rng=rng)
            self.assertIn(reward.free, (1, 2))
            self.assertIn(reward.gold, (32, 34))
            self.assertEqual((reward.cost, reward.paid), (340, True))
            if reward.gold == 34:
                self.assertEqual(reward.items, ((406010081, 1),))
            else:
                self.assertLessEqual(len(reward.items), 1)
            body = cardpool.card_bytes(reward)
            self.assertEqual(len(body), 257 + 29 * reward.free)
            self.assertEqual(clear.card_purse(body), (reward.free, 1, 340))
            self.assertEqual(card.Result.of(body, 3).gold, reward.gold)
            seen.add((reward.free, reward.gold, bool(reward.items)))
        self.assertGreater(len(seen), 1)
        self.assertTrue(any(items for _, _, items in seen))
        self.assertTrue(any(not items for _, _, items in seen))

    def test_a_disabled_dungeon_rolls_nothing(self):
        reward = cardpool.roll(100000151)
        self.assertEqual(reward, cardpool.Reward(free=0, gold=0, cost=0))
        body = cardpool.card_bytes(reward)
        self.assertEqual(len(body), 257)
        self.assertEqual(clear.card_purse(body), (0, 0, 0))

    def test_a_dungeon_outside_the_corpus_uses_the_fallback(self):
        """Dungeon 4 was never cleared in the capture: its free count comes
        off its basis band, its gold off the ratio pool, and its cost is
        still 051's own (6580 at basis 55)."""
        rng = random.Random(1)
        for _ in range(100):
            reward = cardpool.roll(4, rng=rng)
            self.assertIn(reward.free, (1, 2))
            self.assertGreater(reward.gold, 0)
            self.assertLessEqual(len(reward.items), reward.free)
            self.assertEqual((reward.cost, reward.paid), (6580, True))
            self.assertEqual(clear.card_purse(cardpool.card_bytes(reward)),
                             (reward.free, 1, 6580))

    def test_the_paid_item_is_the_dungeons_own_six_times_in_ten(self):
        rng = random.Random(0)
        d3 = [cardpool.paid_item(3, rng=rng) for _ in range(200)]
        self.assertIn(31002, d3)
        self.assertIn(None, d3)
        # A dungeon with no side-1 observation draws the corpus-wide pool.
        pool = {102030568, 106040572, 114010045, 116000072, 100050204,
                100312827, 100344129, 22001, 31002}
        drew = [cardpool.paid_item(999999, rng=rng) for _ in range(200)]
        self.assertTrue({i for i in drew if i} <= pool)
        self.assertGreaterEqual(len({i for i in drew if i}), 2)

    def test_the_paid_refund_never_loses(self):
        rng = random.Random(1)
        for cost in (340, 580, 6580):
            amounts = [cardpool.paid_gold(cost, rng=rng) for _ in range(200)]
            self.assertTrue(all(cost <= a <= round(cost * 1.5)
                                for a in amounts))
            self.assertGreater(len(set(amounts)), 10)
        self.assertEqual(cardpool.paid_gold(0), 0)

    def test_a_free_flip_that_rolled_no_gold_takes_the_floor(self):
        """Dungeon 100002627's rows carry gold 0 on nine of them -- the
        material top-ups -- and the floor answers with `gold[050][140]`'s
        own `[15, 3072]`, so a live card never shows no gold at all."""
        rng = random.Random(3)
        amounts = [cardpool._floor_gold(rng, 100002627) for _ in range(200)]
        self.assertTrue(all(15 <= a <= 3072 for a in amounts))
        self.assertGreater(len(set(amounts)), 10)
        golds = [cardpool.roll(100002627, rng=rng).gold for _ in range(200)]
        self.assertTrue(all(g > 0 for g in golds))
        self.assertTrue(all(15 <= g <= 3072 for g in golds))


class ResultTest(unittest.TestCase):
    def test_the_card_offsets(self):
        self.assertEqual(clear.card_purse(CARD_315), (2, 1, 340))
        result = card.Result.of(CARD_315, 3)
        self.assertEqual((result.dungeon, result.cost, result.gold),
                         (3, 340, 34))
        self.assertEqual(len(result.run_id), 16)
        self.assertEqual((result.free, result.paid, result.attempt,
                          result.retried), (False, False, 0, False))


class SaveTest(unittest.TestCase):
    """The write path, against a copy of the real save."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        self.session = DungeonSession(
            character_id=CHARACTER, key=KEY,
            town=movement.TownSession(character_id=CHARACTER, town=38,
                                      area=2, key=KEY))
        self.session.result = card.Result.of(CARD_315, 3)
        self.session.run = _run(3)
        self.bag((0, 0, 5032), (9, 27118, 1))

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def bag(self, *rows: tuple[int, int, int]) -> None:
        self.conn.execute("delete from character_items where character_id = ? "
                          "and list_type = 0", (CHARACTER,))
        self.conn.executemany(
            "insert into character_items (character_id, list_type, slot_index, "
            "item_id, count, updated_at) values (?, 0, ?, ?, ?, 1)",
            [(CHARACTER, slot, item, count) for slot, item, count in rows])

    def grant(self, run_id: str, gold: int,
              *rows: tuple[int, int, int]) -> card.Grant:
        return card.Grant(run_id=bytes.fromhex(run_id),
                          write=reward.Write(gold=gold,
                                             rows=tuple(_record(*r) for r in rows)))

    def test_the_fed_free_commit_writes_the_reference_s_own(self):
        result = card.resolution(
            self.conn, self.session, CHARACTER, 0,
            self.grant("b67cba62cbe745b485f6704c6556dae1", 5066,
                       (12, 406010081, 1)), NOW)
        self.assertEqual(result.frames[0], (card.COMMIT_OPCODE, STATE_FREE))
        self.assertEqual(result.note, NOTE_71_D3_FREE)
        self.assertEqual(self.session.result.run_id,
                         bytes.fromhex("b67cba62cbe745b485f6704c6556dae1"))
        self.assertTrue(self.session.result.free)
        written = items.load(self.conn, CHARACTER, 0, 12)
        self.assertEqual((written.item_id, written.count), (406010081, 1))
        self.assertEqual(card.purse(self.conn, CHARACTER), 5066)
        # The list frame carries the bag the write left: gold, the starter
        # row, and the grant, in slot order -- then the twelve-cell account
        # band the town entry's inventory ends with too (the capture's commit
        # frames are 18/19/20 rows against the character's own six).  The
        # band's counts are the save's own, so they are mirrored, not pinned.
        body = result.frames[1][1]
        self.assertEqual(result.frames[1][0], card.LIST_OPCODE)
        self.assertEqual(len(body) % 8, 0)
        records = reward.list_records(body)
        own, band = records[:3], records[3:]
        self.assertEqual([(r.slot_index, r.item_id, r.value) for r in own],
                         [(0, 0, 5066), (9, 27118, 1), (12, 406010081, 1)])
        account = characters.by_id(self.conn, CHARACTER).account_id
        counts = {m.item_id: m.count
                  for m in materials.items(self.conn, account)}
        self.assertEqual(
            [(r.slot_index, r.item_id, r.value) for r in band],
            [(cell, item_id, counts.get(item_id, 0))
             for cell, item_id in enumerate(buy.BAG_ITEMS, buy.BAG_CELL_BASE)])

    def test_the_fed_paid_commit_teaches_the_state_frame_its_item(self):
        self.session.result.run_id = bytes.fromhex(
            "b67cba62cbe745b485f6704c6556dae1")
        self.session.result.free = True
        result = card.resolution(
            self.conn, self.session, CHARACTER, 1,
            self.grant("b67cba62cbe745b485f6704c6556dae1", 4726,
                       (13, 31002, 1)), NOW)
        self.assertEqual(result.frames[0],
                         (card.COMMIT_OPCODE, STATE_PAID_31002))
        self.assertEqual(result.note, NOTE_71_D3_PAID)
        self.assertEqual(self.session.result.paid_item, 31002)
        self.assertTrue(self.session.result.paid)

    def test_an_unfed_commit_still_moves_the_purse(self):
        result = card.resolution(self.conn, self.session, CHARACTER, 0, None,
                                 NOW)
        self.assertEqual(result.frames[0], (card.COMMIT_OPCODE, STATE_FREE))
        self.assertEqual(card.purse(self.conn, CHARACTER), 5066)
        self.assertIn("goldDelta=34 balance=5066 rewards=0x34 committed",
                      result.note)
        self.assertIn(f"run={self.session.result.run_id.hex()}", result.note)

    def test_an_unfed_free_commit_lands_the_clears_roll(self):
        """The live roll's items ride the result (`Result.of(items=...)`) and
        land where a pickup's would -- the first free cell past the base."""
        self.session.result = card.Result.of(CARD_315, 3,
                                             items=((406010081, 1),))
        result = card.resolution(self.conn, self.session, CHARACTER, 0, None,
                                 NOW)
        self.assertEqual(card.purse(self.conn, CHARACTER), 5066)
        self.assertIn("balance=5066 rewards=0x34,406010081x1 committed",
                      result.note)
        landed = items.load(self.conn, CHARACTER, 0, 10)
        self.assertEqual((landed.item_id, landed.count), (406010081, 1))
        self.assertTrue(self.session.result.free)

    def test_an_unfed_paid_commit_refunds_and_maybe_lands_its_item(self):
        """Side 1 with nothing fed: the refund brings the purse back
        `340..510` against the 340 cost -- never a net loss -- the item
        lands six times in ten off d3's own pool (31002, the state frame
        teaching it), and the other four times the frame stays the free
        one and no item lands."""
        seen_gold, paid_times, missed = set(), 0, 0
        for _ in range(60):
            paid = card.resolution(self.conn, self.session, CHARACTER, 1,
                                   None, NOW)
            delta = card.purse(self.conn, CHARACTER) - 5032
            self.assertTrue(0 <= delta <= 170)
            seen_gold.add(delta)
            self.assertTrue(self.session.result.paid)
            if self.session.result.paid_item is None:
                missed += 1
                self.assertEqual(paid.frames[0],
                                 (card.COMMIT_OPCODE, STATE_FREE))
                self.assertIsNone(items.load(self.conn, CHARACTER, 0, 10))
            else:
                paid_times += 1
                self.assertEqual(self.session.result.paid_item, 31002)
                self.assertEqual(paid.frames[0],
                                 (card.COMMIT_OPCODE, STATE_PAID_31002))
                landed = items.load(self.conn, CHARACTER, 0, 10)
                self.assertEqual(landed.item_id, 31002)
                self.assertIn("31002x1 committed", paid.note)
            self.assertIn(f"side=1 cost=340 goldDelta={delta} "
                          f"balance={5032 + delta} rewards=", paid.note)
            if delta:
                self.assertIn(f"rewards=0x{delta}", paid.note)
            self.bag((0, 0, 5032), (9, 27118, 1))
            self.session.result = card.Result.of(CARD_315, 3)
        self.assertGreater(len(seen_gold), 5)
        self.assertGreater(paid_times, 20)
        self.assertGreater(missed, 10)

    def test_an_unfed_disabled_commit_grants_nothing(self):
        """Dungeon 100000151: free=0, disabled, so both sides are empty."""
        self.session.result = card.Result.of(b"", 100000151)
        result = card.resolution(self.conn, self.session, CHARACTER, 1, None,
                                 NOW)
        self.assertEqual(result.frames[0], (card.COMMIT_OPCODE, STATE_FREE))
        self.assertEqual(card.purse(self.conn, CHARACTER), 5032)
        self.assertIn("side=1 cost=0 goldDelta=0 balance=5032 rewards= committed",
                      result.note)

    def test_the_state_frames_are_padded_to_the_commit_tile(self):
        free = card.resolution(self.conn, self.session, CHARACTER, 0, None, NOW)
        self.assertEqual(len(free.frames[0][1]), 40)
        paid = card.resolution(self.conn, self.session, CHARACTER, 1,
                               self.grant("ec0fe4f93495404cb08c6a274d4eaef1",
                                          4726, (14, 22001, 1)), NOW)
        self.assertEqual(paid.frames[0][1], STATE_PAID_22001)

    def _settle_row(self) -> None:
        self.conn.execute(
            "update characters set town_id = 38, area_id = 2, position_x = 89, "
            "position_y = 249, town_state = 4 where character_id = ?",
            (CHARACTER,))

    def test_option_two_leaves_the_run_at_the_row_s_position(self):
        self._settle_row()
        summary = characters.by_id(self.conn, CHARACTER)
        result = settle.resolution(self.conn, self.session, summary,
                                   SETTLE_OPT2)
        self.assertEqual(result.frames,
                         ((settle.SETTLE_OPCODE, ACK_OPT2),
                          (settle.blocks.ACK_OPCODE, TOWN_ACK),
                          (movement.AREA_ACK_OPCODE, TOWN_23),
                          (movement.AREA_ACK_2_OPCODE, TOWN_24)))
        self.assertEqual(result.note, SETTLE_NOTE_OPT2)
        self.assertIsNone(result.story)
        self.assertIsNone(self.session.run)

    def test_option_three_with_no_run_is_the_replay_ack(self):
        self.session.run = None
        self.session.result = None
        summary = characters.by_id(self.conn, CHARACTER)
        result = settle.resolution(self.conn, self.session, summary,
                                   SETTLE_OPT3)
        self.assertEqual(result.frames, ((settle.SETTLE_OPCODE, ACK_OPT3),))
        self.assertEqual(result.note, SETTLE_NOTE_OPT3)
        self.assertIsNone(result.story)

    def test_a_settle_after_the_story_prints_nothing(self):
        self.session.run = None
        self.session.result.retried = True
        summary = characters.by_id(self.conn, CHARACTER)
        result = settle.resolution(self.conn, self.session, summary,
                                   SETTLE_OPT3)
        self.assertEqual(result.frames, ((settle.SETTLE_OPCODE, ACK_OPT3),))
        self.assertIsNone(result.note)

    def test_a_state_that_is_not_one_only_acks(self):
        summary = characters.by_id(self.conn, CHARACTER)
        result = settle.resolution(self.conn, self.session, summary, STATE_TWO)
        self.assertEqual(result.frames, ((settle.SETTLE_OPCODE, ACK_OPT2),))
        self.assertEqual(
            result.note,
            "key=3 dungeon=3 state=2 option=2 context=1 replay=False "
            "-> 1 frame(s)")
        self.assertIsNotNone(self.session.run)

    def test_option_one_finds_the_retry_and_prints_the_story(self):
        self.conn.execute("delete from character_quest_progress where "
                          "character_id = ?", (CHARACTER,))
        self.conn.execute("delete from character_quests where character_id = ?",
                          (CHARACTER,))
        self.conn.execute("delete from character_finished_quests where "
                          "character_id = ? and quest_id = 3147", (CHARACTER,))
        queststate.accept(self.conn, CHARACTER, 3147, now=NOW)
        self.session.run = _run(5)
        self.session.result = card.Result(dungeon=5, cost=580, gold=20)
        summary = characters.by_id(self.conn, CHARACTER)
        result = settle.resolution(self.conn, self.session, summary,
                                   SETTLE_OPT1)
        self.assertEqual(result.story, STORY)
        self.assertEqual(result.note, SETTLE_NOTE_STORY)
        self.assertEqual([opcode.key() for opcode, _ in result.frames],
                         [(1, 72), (0, 342), (0, 291), (0, 21),
                          (0, 3), (0, 23), (0, 24)])
        self.assertEqual(result.frames[0][1], ACK_OPT1)
        self.assertEqual(self.session.result.attempt, 1)
        self.assertTrue(self.session.result.retried)
        self.assertIsNone(self.session.run)

        silent = settle.resolution(self.conn, self.session, summary,
                                   SETTLE_SILENT)
        self.assertEqual(silent.frames[0][1], ACK_OPT3_ATTEMPT2)
        self.assertIsNone(silent.note)


if __name__ == "__main__":
    unittest.main()
