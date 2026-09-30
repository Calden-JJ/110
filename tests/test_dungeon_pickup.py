"""M3.4's pickup: the `(1,43)` request, its two `(0,39)` answers, the `(0,14)`
gold refresh, and both refusals.

Every constant is the 09-28 capture's own plaintext -- the 24B requests and
the reply frames off conn=4's wire, the lines verbatim -- and the save tests
rebuild the bag the capture's own order of pickups leaves behind: the
tutorial's keys 1 and 2 land at 10 and 11, and dungeon 5's cleared run takes
keys 13 and 14 to slot 0 and key 15 to cell 18 four seconds later.

Two readings the capture decides that the code alone would not.  A *cleared*
run still hands its drops over -- the `(1,46)` at 21:12:53 is followed by the
21:12:59 pickups -- so `no active owner` is the run being gone, not the flag
`(1,46)` sets.  And a refusal leaves its object on the ground: the 09-25
log's key=10 and key=35 came back `other-room` at 18:46:46 and 18:51:45 and
committed 18 and 27 seconds later, when the run stood in their rooms again.
"""
from __future__ import annotations

import shutil
import struct
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401
import _save

from uslocalserver import paths
from uslocalserver.game.dungeon import drops, pickup
from uslocalserver.game.dungeon.run import DungeonRun, DungeonSession
from uslocalserver.game.item import refresh
from uslocalserver.game.shop import buy
from uslocalserver.persistence import items, schema

CHARACTER = 3
NOW = 1_790_000_000

#: The requests: the plaintext bodies under the capture's own 37B `(1,43)`
#: frames (13B header + these 24B, `tiles.algo_id(43)`).  `[0:4]` is the
#: ground slot, `[4]` zero, `[5]` the 0/1 flag -- 0 on the tutorial's two
#: sends and 1 on the rest -- then four (x, y) u16le pairs around the pick.
REQUEST_1 = bytes.fromhex("01000000000037032901A07948032B013D51DE0200000000")
REQUEST_3 = bytes.fromhex("0300000000013D02D900B20F6802CC00CC2F352300000000")
REQUEST_13 = bytes.fromhex("0D000000000138020001504E3902E9008F6A987E00000000")
REQUEST_14 = bytes.fromhex("0E00000000010303E30043452D03D9002323886800000000")
REQUEST_15 = bytes.fromhex("0F00000000012B03E300F80F4203E500D719104B00000000")
REQUEST_16 = bytes.fromhex("100000000001B202F20047288602F300CD498B4B00000000")
REQUEST_17 = bytes.fromhex("110000000001A303EB005E248A03EA00732BC24F00000000")
#: The one refusal the 09-25 log prints a whole body for: key=95, `no active
#: owner` twice, 117 ms after that session's `SETTLEMENT-72`.
REFUSED_95 = bytes.fromhex("5F00000000023903A901731D3903A9012F3C1B7100000000")

#: The 24B item replies: `u32le key | u16le character | 8 zero | u16le 3 |
#: u16le cell | 6 zero` -- one per item pickup of the capture.
ITEM_KEY_1_CELL_10 = (
    "010000000300000000000000000003000A00000000000000")
ITEM_KEY_2_CELL_11 = (
    "020000000300000000000000000003000B00000000000000")
ITEM_KEY_15_CELL_18 = (
    "0F0000000300000000000000000003001200000000000000")
ITEM_KEY_17_CELL_19 = (
    "110000000300000000000000000003001300000000000000")

#: The 56B gold replies: `u32le key | u16le character | 01 | u16le amount |
#: 00 00 01 | zero to 56`.  `amount` is what this pickup added.
GOLD_KEY_3_32 = (
    "0300000003000120000000010000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000")
GOLD_KEY_12_39 = (
    "0C00000003000127000000010000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000")
GOLD_KEY_13_17 = (
    "0D00000003000111000000010000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000")
GOLD_KEY_14_21 = (
    "0E00000003000115000000010000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000")
GOLD_KEY_16_52 = (
    "1000000003000134000000010000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000")

#: The gold refresh's first 48 bytes: `00 01 00` (list 0, one record), slot 0,
#: item 0, then the *new total* at `[9:13]` -- 5032, 4765, 4222, 4243 and
#: 4295, the notes' own `gold=`.  The other 120 bytes are zero in all five.
REFRESH_HEAD_5032 = (
    "000100000000000000A813000000000000000000000000000000000000000000"
    "00000000000000000000000000000000")
REFRESH_HEAD_4765 = (
    "0001000000000000009D12000000000000000000000000000000000000000000"
    "00000000000000000000000000000000")
REFRESH_HEAD_4222 = (
    "0001000000000000007E10000000000000000000000000000000000000000000"
    "00000000000000000000000000000000")
REFRESH_HEAD_4243 = (
    "0001000000000000009310000000000000000000000000000000000000000000"
    "00000000000000000000000000000000")
REFRESH_HEAD_4295 = (
    "000100000000000000C710000000000000000000000000000000000000000000"
    "00000000000000000000000000000000")

#: The lines, verbatim.
NOTE_1 = ("key=1 character=3 item=400320513 count=1 destination=0:10 "
          "gold=5000 committed")
NOTE_3 = ("key=3 character=3 item=0 count=32 destination=0:0 "
          "gold=5032 committed")
NOTE_13 = ("key=13 character=3 item=0 count=17 destination=0:0 "
           "gold=4222 committed")
NOTE_14 = ("key=14 character=3 item=0 count=21 destination=0:0 "
           "gold=4243 committed")
NOTE_15 = ("key=15 character=3 item=27602 count=1 destination=0:18 "
           "gold=4243 committed")
NOTE_16 = ("key=16 character=3 item=0 count=52 destination=0:0 "
           "gold=4295 committed")
NOTE_17 = ("key=17 character=3 item=400220171 count=1 destination=0:19 "
           "gold=4295 committed")
NO_OWNER_NOTE = (f"key=95 rejected: {pickup.NO_OWNER}; "
                 f"plain={REFUSED_95.hex().upper()}")


def _save_copy() -> Path:
    # The 0.4.4 save ships one character; the ids this module names
    # are cloned from it so the foreign keys resolve.
    return _save.fresh(CHARACTER, 1, 2, 3)


def _run(dungeon: int, maze_n: int, cell: tuple[int, int], map_id: int,
         seed: str, base: int) -> DungeonRun:
    run = DungeonRun(dungeon=dungeon, maze=maze_n, cell=cell, map_id=map_id,
                     seed=bytes.fromhex(seed), base=base)
    run.enter(map_id)
    return run


def _request(key: int) -> bytes:
    """A request plain for a slot the capture never names -- `slot_of` reads
    only the first field, so the rest is zero."""
    return struct.pack("<I", key) + bytes(20)


def _row(slot: int, item: int, value: int = 0, count: int = 1,
         durability: int = 0) -> drops.Row:
    """A ground record as a kill's `(0,38)` would have made it."""
    return drops.Row(slot=slot, item=item, value=value,
                     kind=drops.GOLD if item == pickup.GOLD_ITEM else "monster",
                     durability=durability, count=count)


def _value_offset(frame_body: bytes) -> int:
    """The record's `value` u32le -- the slot block starts at byte 3."""
    return struct.unpack_from("<I", frame_body, 9)[0]


class RequestTest(unittest.TestCase):
    def test_the_slot_is_the_first_field(self):
        for plain, key in ((REQUEST_1, 1), (REQUEST_3, 3), (REQUEST_13, 13),
                           (REQUEST_14, 14), (REQUEST_15, 15), (REQUEST_16, 16),
                           (REQUEST_17, 17), (REFUSED_95, 95)):
            with self.subTest(key=key):
                self.assertEqual(len(plain), pickup.REQUEST_SIZE)
                self.assertEqual(pickup.slot_of(plain), key)

    def test_the_refusal_line_is_the_whole_request_upper_case(self):
        self.assertEqual(pickup.refusal_note(95, pickup.NO_OWNER, REFUSED_95),
                         NO_OWNER_NOTE)


class ReplyBodyTest(unittest.TestCase):
    def test_the_item_bodies(self):
        for key, cell, expected in ((1, 10, ITEM_KEY_1_CELL_10),
                                    (2, 11, ITEM_KEY_2_CELL_11),
                                    (15, 18, ITEM_KEY_15_CELL_18),
                                    (17, 19, ITEM_KEY_17_CELL_19)):
            with self.subTest(key=key):
                body = pickup.item_body(key, CHARACTER, cell)
                self.assertEqual(len(body), pickup.ITEM_BODY_SIZE)
                self.assertEqual(body.hex().upper(), expected)

    def test_the_gold_bodies(self):
        for key, amount, expected in ((3, 32, GOLD_KEY_3_32),
                                      (12, 39, GOLD_KEY_12_39),
                                      (13, 17, GOLD_KEY_13_17),
                                      (14, 21, GOLD_KEY_14_21),
                                      (16, 52, GOLD_KEY_16_52)):
            with self.subTest(key=key):
                body = pickup.gold_body(key, CHARACTER, amount)
                self.assertEqual(len(body), pickup.GOLD_BODY_SIZE)
                self.assertEqual(body.hex().upper(), expected)


class SaveTest(unittest.TestCase):
    """The write path, against a copy of the real save and its triggers."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        self.session = DungeonSession(character_id=CHARACTER, key=3, town=None)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def bag(self, *rows: tuple[int, int, int]) -> None:
        """Wipe character 3's bag and lay out `(slot, item_id, count)` rows."""
        self.conn.execute("delete from character_items where character_id = ? "
                          "and list_type = ?", (CHARACTER, buy.GOLD_LIST))
        self.conn.executemany(
            "insert into character_items (character_id, list_type, slot_index, "
            "item_id, count, updated_at) values (?, ?, ?, ?, ?, 1)",
            [(CHARACTER, buy.GOLD_LIST, slot, item, count)
             for slot, item, count in rows])

    def drop(self, row: drops.Row, map_id: int = 76121) -> None:
        self.session.drop(map_id, (row,))
        self.session.run = _run(5, 0, (0, 0), map_id, "6ac82500", 44)

    def test_the_first_pickup_lands_past_the_occupied_base(self):
        self.bag((0, 0, 5000), (9, 27118, 1))
        self.drop(_row(1, 400320513, value=668198703, durability=48))
        result = pickup.resolution(self.conn, self.session, CHARACTER, 1,
                                   REQUEST_1, NOW)
        self.assertEqual(result.frames,
                         ((pickup.REPLY_OPCODE, bytes.fromhex(ITEM_KEY_1_CELL_10)),))
        self.assertEqual(result.note, NOTE_1)
        written = items.load(self.conn, CHARACTER, buy.GOLD_LIST, 10)
        self.assertEqual((written.item_id, written.count), (400320513, 1))
        self.assertEqual((written.instance_value, written.durability),
                         (668198703, 48))
        self.assertEqual(written.updated_at, NOW)

    def test_gold_adds_to_slot_zero_and_refreshes_it(self):
        self.bag((0, 0, 5000))
        self.drop(_row(3, pickup.GOLD_ITEM, value=32))
        result = pickup.resolution(self.conn, self.session, CHARACTER, 3,
                                   REQUEST_3, NOW)
        self.assertEqual([opcode for opcode, _ in result.frames],
                         [pickup.REPLY_OPCODE, refresh.OPCODE_SLOT])
        self.assertEqual(result.frames[0][1].hex().upper(), GOLD_KEY_3_32)
        body = result.frames[1][1]
        self.assertEqual(len(body), 168)
        self.assertEqual(body[:48].hex().upper(), REFRESH_HEAD_5032)
        self.assertEqual(body[48:], bytes(120))
        self.assertEqual(result.note, NOTE_3)
        self.assertEqual(items.load(self.conn, CHARACTER, buy.GOLD_LIST,
                                    buy.GOLD_SLOT).count, 5032)

    def test_gold_into_an_empty_slot_zero(self):
        self.bag()
        self.drop(_row(3, pickup.GOLD_ITEM, value=32))
        result = pickup.resolution(self.conn, self.session, CHARACTER, 3,
                                   REQUEST_3, NOW)
        self.assertEqual(result.frames[0][1].hex().upper(), GOLD_KEY_3_32)
        self.assertEqual(_value_offset(result.frames[1][1]), 32)
        self.assertEqual(items.load(self.conn, CHARACTER, buy.GOLD_LIST,
                                    buy.GOLD_SLOT).count, 32)

    def test_a_cleared_run_still_hands_its_drops_over(self):
        """The capture's 21:12:53 `(1,46)` then keys 13, 14 and 15 at
        21:12:59 -- `settled` is not what the guard reads."""
        self.bag((0, 0, 4205), (9, 27118, 1), (10, 416020054, 1),
                 (11, 400050187, 1), (12, 406010081, 1), (13, 31002, 1),
                 (14, 22001, 1), (15, 20002, 1), (16, 24002, 1),
                 (17, 22002, 1))
        self.drop(_row(13, pickup.GOLD_ITEM, value=17))
        self.drop(_row(14, pickup.GOLD_ITEM, value=21))
        self.drop(_row(15, 27602, value=76630238))
        self.drop(_row(16, pickup.GOLD_ITEM, value=52))
        self.drop(_row(17, 400220171, value=56640321))
        self.session.settled = True
        self.assertFalse(self.session.in_progress)
        self.assertIsNotNone(self.session.run)

        thirteen = pickup.resolution(self.conn, self.session, CHARACTER, 13,
                                     REQUEST_13, NOW)
        self.assertEqual(thirteen.frames[0][1].hex().upper(), GOLD_KEY_13_17)
        self.assertEqual(thirteen.frames[1][1][:48].hex().upper(),
                         REFRESH_HEAD_4222)
        self.assertEqual(thirteen.note, NOTE_13)

        fourteen = pickup.resolution(self.conn, self.session, CHARACTER, 14,
                                     REQUEST_14, NOW)
        self.assertEqual(fourteen.frames[0][1].hex().upper(), GOLD_KEY_14_21)
        self.assertEqual(fourteen.frames[1][1][:48].hex().upper(),
                         REFRESH_HEAD_4243)
        self.assertEqual(fourteen.note, NOTE_14)

        fifteen = pickup.resolution(self.conn, self.session, CHARACTER, 15,
                                    REQUEST_15, NOW)
        self.assertEqual(fifteen.frames, ((pickup.REPLY_OPCODE,
                                           bytes.fromhex(ITEM_KEY_15_CELL_18)),))
        self.assertEqual(fifteen.note, NOTE_15)
        landed = items.load(self.conn, CHARACTER, buy.GOLD_LIST, 18)
        self.assertEqual(landed.item_id, 27602)
        self.assertEqual(landed.instance_value, 76630238)

        sixteen = pickup.resolution(self.conn, self.session, CHARACTER, 16,
                                    REQUEST_16, NOW)
        self.assertEqual(sixteen.frames[0][1].hex().upper(), GOLD_KEY_16_52)
        self.assertEqual(sixteen.frames[1][1][:48].hex().upper(),
                         REFRESH_HEAD_4295)
        self.assertEqual(sixteen.note, NOTE_16)

        seventeen = pickup.resolution(self.conn, self.session, CHARACTER, 17,
                                      REQUEST_17, NOW)
        self.assertEqual(seventeen.frames, ((pickup.REPLY_OPCODE,
                                             bytes.fromhex(ITEM_KEY_17_CELL_19)),))
        self.assertEqual(seventeen.note, NOTE_17)
        self.assertEqual(self.session.ground, {})

    def test_a_non_stackable_never_merges(self):
        """conn=17's 100070728 landed at 13 and then at 15: the first row was
        still standing and `place` walked past it."""
        self.bag((0, 0, 4295), (13, 400220171, 1))
        self.drop(_row(20, 400220171, value=900))
        result = pickup.resolution(self.conn, self.session, CHARACTER, 20,
                                   _request(20), NOW)
        self.assertIn("destination=0:9", result.note)
        self.assertEqual(items.load(self.conn, CHARACTER, buy.GOLD_LIST,
                                    13).count, 1)
        self.assertEqual(items.load(self.conn, CHARACTER, buy.GOLD_LIST,
                                    9).item_id, 400220171)

    def test_a_stackable_merges_into_its_own_row(self):
        self.bag((0, 0, 4295), (65, 1001, 5))
        self.drop(_row(21, 1001, count=3))
        result = pickup.resolution(self.conn, self.session, CHARACTER, 21,
                                   _request(21), NOW)
        self.assertIn("destination=0:65", result.note)
        merged = items.load(self.conn, CHARACTER, buy.GOLD_LIST, 65)
        self.assertEqual(merged.count, 8)
        self.assertEqual(merged.instance_value, 0)

    def test_a_full_band_leaves_the_object_lying(self):
        self.bag((0, 0, 4295), *[(slot, 27118, 1)
                                 for slot in range(9, buy.BAG_CELL_BASE)])
        self.drop(_row(22, 400220171, value=900))
        result = pickup.resolution(self.conn, self.session, CHARACTER, 22,
                                   _request(22), NOW)
        self.assertFalse(result.committed)
        self.assertEqual(result.frames, ())
        self.assertEqual(result.note,
                         pickup.refusal_note(22, pickup.NO_ROOM,
                                             _request(22)))
        self.assertIn(22, self.session.ground)


class RefusalTest(unittest.TestCase):
    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        self.session = DungeonSession(character_id=CHARACTER, key=3, town=None)
        self.conn.execute("delete from character_items where character_id = ? "
                          "and list_type = ?", (CHARACTER, buy.GOLD_LIST))
        self.conn.execute(
            "insert into character_items (character_id, list_type, slot_index, "
            "item_id, count, updated_at) values (?, 0, 0, 0, 4295, 1)",
            (CHARACTER,))

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def test_no_run_refuses_and_leaves_the_object(self):
        self.session.drop(76131, (_row(95, pickup.GOLD_ITEM, value=10),))
        self.assertIsNone(self.session.run)
        result = pickup.resolution(self.conn, self.session, CHARACTER, 95,
                                   REFUSED_95, NOW)
        self.assertFalse(result.committed)
        self.assertEqual(result.frames, ())
        self.assertEqual(result.note, NO_OWNER_NOTE)
        self.assertIn(95, self.session.ground)
        self.assertEqual(items.load(self.conn, CHARACTER, buy.GOLD_LIST,
                                    buy.GOLD_SLOT).count, 4295)

    def test_another_room_refuses_then_commits_on_the_way_back(self):
        """The 09-25 key=10: refused `other-room`, then picked up 18 seconds
        later once the run stood in the room again."""
        self.session.run = _run(3, 1, (0, 1), 76121, "7edee364", 17)
        self.session.drop(76121, (_row(10, pickup.GOLD_ITEM, value=18),))
        self.session.run.move_to((1, 1))          # 76123, a different room

        refused = pickup.resolution(self.conn, self.session, CHARACTER, 10,
                                    _request(10), NOW)
        self.assertFalse(refused.committed)
        self.assertEqual(refused.note,
                         pickup.refusal_note(10, pickup.UNKNOWN, _request(10)))
        self.assertIn(10, self.session.ground)
        self.assertEqual(items.load(self.conn, CHARACTER, buy.GOLD_LIST,
                                    buy.GOLD_SLOT).count, 4295)

        self.session.run.move_to((0, 1))          # back to 76121
        committed = pickup.resolution(self.conn, self.session, CHARACTER, 10,
                                      _request(10), NOW)
        self.assertTrue(committed.committed)
        self.assertNotIn(10, self.session.ground)
        self.assertEqual(items.load(self.conn, CHARACTER, buy.GOLD_LIST,
                                    buy.GOLD_SLOT).count, 4313)


if __name__ == "__main__":
    unittest.main()
