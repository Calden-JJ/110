"""`(1,21)` NPC-BUY: the reference's four runs, byte for byte.

The runs are the live reference's own (09-27 22:54:05 and 23:15:29/30/31,
`conn=2`, account 0, character 2, `DFO110-0.3.6/Server/Logs/server-20260927.log`),
embedded verbatim: each run's 24B request, its ack, its `(0,14)` frames and
the closing board, all dumped out of the log's ciphertext with the project's
own `frame` + `tiles`.

Two of the four are gold buys (29127 for 45500, 1106 for 100) and two pay
5 x 3037 instead (3034, 3035), which is what makes the frame split visible:
the bought row rides the character frame when it lands in `character_items`
(29127 -> slot 17, 1106 -> slot 65) and the material frame when it lands in
`account_materials` (3034 -> cell 364, 3035 -> cell 365, with the paid 3037
at 367 ahead of it).

The save's pre-state each run needs is *set*, never assumed: the four
captured `updated_at`s are the captures' own seconds (22:54:05 ->
1790520845, 23:15:29/30/31 -> 1790522129/130/131), and the gold row, the
`account_materials` rows and the free slot are written by `setUp`.  One
value is not reproducible and is masked instead: an equipment row is born
with a random `instance_value` (700543244 on the 29127 one), so the ack and
the character frame are compared with that u32 substituted from the save.
"""
from __future__ import annotations

import asyncio
import io
import shutil
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import _bootstrap  # noqa: F401
import _save

from uslocalserver import paths
from uslocalserver.game.shop import buy
from uslocalserver.persistence import accounts, items, schema
from uslocalserver.persistence import materials
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

CHARACTER = 2
#: The four captures' own wall-clock seconds (+08:00), the stamps the
#: reference put on the rows it touched.
NOW_29127 = 1_790_520_845
NOW_3034 = 1_790_522_129
NOW_3035 = 1_790_522_130
NOW_1106 = 1_790_522_131

REQ_29127 = bytes.fromhex(
    "c771000023b400001e000000390000000000000000000000"
)
ACK_29127 = bytes.fromhex(
    "0192060000000000000000000000000000000000001100c77100000c71c129003000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000"
)
CHAR_29127 = bytes.fromhex(
    "00020000000000000092060000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000001100c77100000c71c129003000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000"
)

REQ_3034 = bytes.fromhex(
    "da0b0000010000000f000000020000000000000000000000"
)
ACK_3034 = bytes.fromhex(
    "016abc0000000000000000000000000000000000006c01da0b0000d79a0200000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000001dd0b00001d6203006f01000000"
)
CHAR_3034 = bytes.fromhex(
    "0001000000000000006abc0000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
MAT_3034 = bytes.fromhex(
    "0002006f01dd0b00001d620300000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000006c01da0b0000d79a0200000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000"
)

REQ_3035 = bytes.fromhex(
    "db0b0000010000000f000000020000000000000000000000"
)
ACK_3035 = bytes.fromhex(
    "016abc0000000000000000000000000000000000006d01db0b0000f5980200000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000001dd0b0000186203006f01000000"
)
CHAR_3035 = bytes.fromhex(
    "0001000000000000006abc0000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)
MAT_3035 = bytes.fromhex(
    "0002006f01dd0b000018620300000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000006d01db0b0000f5980200000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000"
)

REQ_1106 = bytes.fromhex(
    "52040000010000000f000000020000000000000000000000"
)
ACK_1106 = bytes.fromhex(
    "0106bc00000000000000000000000000000000000041005204000001000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000"
)
CHAR_1106 = bytes.fromhex(
    "00020000000000000006bc0000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000041005204000001000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000"
)

#: The `(0,1361)` that closes every run.
BOARD = bytes.fromhex("32000000000000000000000000000000")

BOARD_OPCODE = frame.Opcode(0, 1361, frame.OpcodeEncoding.U8_U16LE, True)
SLOT_OPCODE = frame.Opcode(0, 14, frame.OpcodeEncoding.U8_U16LE, True)


def _save_copy() -> Path:
    # The 0.4.4 save ships one character; the ids this module names
    # are cloned from it so the foreign keys resolve.
    return _save.fresh(CHARACTER, 1, 2, 3)


def _request(body: bytes) -> buy.BuyRequest:
    return buy.BuyRequest.parse(body)


class RequestTest(unittest.TestCase):
    def test_the_four_reference_bodies_parse_field_for_field(self):
        for body, item, word, shop, field in (
                (REQ_29127, 29127, 46115, 30, 57),
                (REQ_3034, 3034, 1, 15, 2),
                (REQ_3035, 3035, 1, 15, 2),
                (REQ_1106, 1106, 1, 15, 2)):
            with self.subTest(body=body.hex()):
                req = _request(body)
                self.assertEqual((req.item_id, req.word, req.shop_id,
                                  req.field), (item, word, shop, field))

    def test_the_request_lines_are_the_reference_ones(self):
        self.assertEqual(_request(REQ_29127).request_line(2),
                         "conn=2 request shop=30 item=29127 count=1 field=57 "
                         "layout=npc mode=0")
        self.assertEqual(_request(REQ_3034).request_line(2),
                         "conn=2 request shop=15 item=3034 count=1 field=2 "
                         "layout=npc mode=0")

    def test_a_body_of_another_size_is_refused(self):
        with self.assertRaises(ValueError):
            _request(REQ_29127[:-1])

    def test_the_shop_rules_agree_with_the_captures(self):
        """`field` is the shop rule's npc on all four; the paths decide the
        destination (two materials, two not)."""
        self.assertTrue(buy.in_shop(30, 29127))
        self.assertTrue(buy.in_shop(15, 3034))
        self.assertFalse(buy.in_shop(30, 1106))
        self.assertFalse(buy.into_bag(buy.shop_rule(29127)))
        self.assertFalse(buy.into_bag(buy.shop_rule(1106)))
        self.assertTrue(buy.into_bag(buy.shop_rule(3034)))


class FrameTest(unittest.TestCase):
    """`frames` over constructed outcomes -- one per captured run."""

    def test_the_29127_run_is_the_captured_ack_and_character_frame(self):
        outcome = buy.Outcome(
            True, price=45500, gold_after=1682,
            bought=_record(17, 29127, 700543244, durability=48),
            char_records=(_record(0, 0, 1682),
                          _record(17, 29127, 700543244, durability=48)))
        self.assertEqual(
            buy.frames(outcome),
            [(buy.OPCODE, ACK_29127),
             (SLOT_OPCODE, CHAR_29127),
             (BOARD_OPCODE, BOARD)])

    def test_the_3034_run_is_the_captured_ack_and_two_frames(self):
        bought = _record(364, 3034, 170711)
        outcome = buy.Outcome(
            True, price=0, material_slots=1, gold_after=48234,
            bought=bought,
            paid=(buy.MaterialMove(3037, 221725, 367),),
            char_records=(_record(0, 0, 48234),),
            material_records=(_record(367, 3037, 221725), bought))
        self.assertEqual(
            buy.frames(outcome),
            [(buy.OPCODE, ACK_3034),
             (SLOT_OPCODE, CHAR_3034),
             (SLOT_OPCODE, MAT_3034),
             (BOARD_OPCODE, BOARD)])

    def test_the_1106_run_is_the_captured_ack_and_character_frame(self):
        outcome = buy.Outcome(
            True, price=100, gold_after=48134,
            bought=_record(65, 1106, 1),
            char_records=(_record(0, 0, 48134), _record(65, 1106, 1)))
        self.assertEqual(
            buy.frames(outcome),
            [(buy.OPCODE, ACK_1106),
             (SLOT_OPCODE, CHAR_1106),
             (BOARD_OPCODE, BOARD)])


def _record(slot: int, item_id: int, value: int, *, durability: int = 0
            ) -> "refresh.SlotRecord":
    from uslocalserver.game.item import refresh
    return refresh.SlotRecord(slot_index=slot, item_id=item_id, value=value,
                              durability=durability)


class BagCellTest(unittest.TestCase):
    """`bag_cell` against a copy of the real save: the band table and the
    unobserved off-band fallback."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        self.account = accounts.sole_account(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def test_the_band_cells_do_not_move_with_the_bag(self):
        """The cells the 44 reference `TOWN-ITEMS` lines pin -- including the
        six large ids the old rank-by-item-id rule placed wrong (369 is
        10100115's cell, not 10099773's)."""
        cells = [buy.bag_cell(self.conn, self.account, i)
                 for i in buy.BAG_ITEMS]
        self.assertEqual(cells, list(range(363, 375)))
        self.conn.execute("delete from account_materials where item_id < 4000")
        self.conn.commit()
        self.assertEqual(buy.bag_cell(self.conn, self.account, 3034), 364)
        self.assertEqual(buy.bag_cell(self.conn, self.account, 10158124), 374)

    def test_an_off_band_material_lines_up_behind_the_band(self):
        """Item 3137 is buyable (`stackable/material/`) but never entered a
        bag in any log: it takes the first cell behind the band, and the next
        one after it -- inferred, the captures leave this open."""
        self.assertEqual(buy.bag_cell(self.conn, self.account, 3137), 375)
        materials.insert(self.conn, self.account, 3137, 5, 1)
        self.conn.commit()
        self.assertEqual(buy.bag_cell(self.conn, self.account, 3141), 376)


class SaveTest(unittest.TestCase):
    """`execute` against a copy of the real save: the effects and the pins."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        self.account = accounts.sole_account(self.conn)
        self._clear_slot(0, 17)
        self._clear_slot(0, 65)
        self._clear_item(1106)
        self._occupy(9, 16)
        # The bag's own rows: only those under 4000 matter to the cells the
        # ack carries, and these are the five the captures had.
        self.conn.execute("delete from account_materials where item_id < 4000")
        for item_id, count in ((3033, 170010), (3034, 170710),
                               (3035, 170228), (3036, 169747),
                               (3037, 221730)):
            materials.insert(self.conn, self.account, item_id, count, 1)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    # ------------------------------------------------------------- helpers

    def _gold(self, count: int) -> None:
        row = items.load(self.conn, CHARACTER, 0, 0)
        items.set_count(self.conn, row, count, 1)
        self.conn.commit()

    def _clear_slot(self, list_type: int, slot: int) -> None:
        if items.load(self.conn, CHARACTER, list_type, slot) is not None:
            items.delete(self.conn, CHARACTER, list_type, slot)

    def _clear_item(self, item_id: int) -> None:
        rows = self.conn.execute(
            "select slot_index from character_items where character_id = ? "
            "and list_type = 0 and item_id = ?",
            (CHARACTER, item_id)).fetchall()
        for (slot,) in rows:
            items.delete(self.conn, CHARACTER, 0, slot)

    def _occupy(self, first: int, last: int) -> None:
        """Fill empty cells of a run so a placement lands past it -- the
        equipment buy landed at 17 because 9..16 were taken."""
        for slot in range(first, last + 1):
            if items.load(self.conn, CHARACTER, 0, slot) is None:
                items.insert(self.conn, _filler(CHARACTER, slot))

    # --------------------------------------------------------------- runs

    def test_the_29127_buy_spends_45500_and_lands_the_equipment_row(self):
        self._gold(47182)
        out = buy.execute(self.conn, self.account, CHARACTER,
                          _request(REQ_29127), now=NOW_29127)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual((out.price, out.material_slots, out.gold_after),
                         (45500, 0, 1682))
        row = items.load(self.conn, CHARACTER, 0, 17)
        self.assertEqual((row.item_id, row.count, row.durability,
                          row.updated_at), (29127, 1, 48, NOW_29127))
        self.assertGreater(row.instance_value, 0)
        self.assertLess(row.instance_value, buy.INSTANCE_LIMIT)
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 0).count, 1682)
        self.assertEqual(_frames(out), _with_instance(ACK_29127, CHAR_29127,
                                                      row))

    def test_the_1106_buy_spends_100_and_takes_the_freed_cell_65(self):
        self._gold(48234)
        out = buy.execute(self.conn, self.account, CHARACTER,
                          _request(REQ_1106), now=NOW_1106)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual((out.price, out.gold_after), (100, 48134))
        row = items.load(self.conn, CHARACTER, 0, 65)
        self.assertEqual((row.item_id, row.count, row.instance_value,
                          row.durability, row.updated_at), (1106, 1, 0, 0,
                                                            NOW_1106))
        gold = items.load(self.conn, CHARACTER, 0, 0)
        self.assertEqual((gold.count, gold.updated_at), (48134, NOW_1106))
        self.assertEqual(_frames(out), [(buy.OPCODE, ACK_1106),
                                        (SLOT_OPCODE, CHAR_1106),
                                        (BOARD_OPCODE, BOARD)])

    def test_the_3034_buy_pays_3037_and_increments_the_bag_row(self):
        self._gold(48234)
        out = buy.execute(self.conn, self.account, CHARACTER,
                          _request(REQ_3034), now=NOW_3034)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual((out.price, out.material_slots, out.gold_after),
                         (0, 1, 48234))
        self.assertEqual(materials.load(self.conn, self.account, 3037).count,
                         221725)
        made = materials.load(self.conn, self.account, 3034)
        self.assertEqual((made.count, made.updated_at), (170711, NOW_3034))
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 0).count, 48234)
        self.assertEqual(_frames(out), [(buy.OPCODE, ACK_3034),
                                        (SLOT_OPCODE, CHAR_3034),
                                        (SLOT_OPCODE, MAT_3034),
                                        (BOARD_OPCODE, BOARD)])

    def test_the_3035_buy_pays_the_3037_the_3034_run_left(self):
        self._gold(48234)
        materials.set_count(self.conn, self.account, 3037, 221725, 1)
        self.conn.commit()
        out = buy.execute(self.conn, self.account, CHARACTER,
                          _request(REQ_3035), now=NOW_3035)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual(materials.load(self.conn, self.account, 3037).count,
                         221720)
        made = materials.load(self.conn, self.account, 3035)
        self.assertEqual((made.count, made.updated_at), (170229, NOW_3035))
        self.assertEqual(_frames(out), [(buy.OPCODE, ACK_3035),
                                        (SLOT_OPCODE, CHAR_3035),
                                        (SLOT_OPCODE, MAT_3035),
                                        (BOARD_OPCODE, BOARD)])

    def test_a_material_buy_without_the_materials_writes_nothing(self):
        self._gold(48234)
        materials.set_count(self.conn, self.account, 3037, 4, 1)
        self.conn.commit()
        out = buy.execute(self.conn, self.account, CHARACTER,
                          _request(REQ_3034), now=NOW_3034)
        self.assertEqual((out.ok, out.reason), (False, "not enough materials"))
        self.assertEqual(materials.load(self.conn, self.account, 3037).count, 4)
        self.assertEqual(materials.load(self.conn, self.account, 3034).count,
                         170710)
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 0).count, 48234)

    def test_a_buy_without_the_gold_writes_nothing(self):
        self._gold(100)
        out = buy.execute(self.conn, self.account, CHARACTER,
                          _request(REQ_29127), now=NOW_29127)
        self.assertEqual((out.ok, out.reason), (False, "not enough gold"))
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 0).count, 100)
        self.assertIsNone(items.load(self.conn, CHARACTER, 0, 17))

    def test_an_item_of_another_shop_writes_nothing(self):
        self._gold(48234)
        out = buy.execute(self.conn, self.account, CHARACTER,
                          replace(_request(REQ_29127), shop_id=15),
                          now=NOW_29127)
        self.assertEqual((out.ok, out.reason),
                         (False, "item is not in that shop"))
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 0).count, 48234)

    def test_a_stack_the_character_already_has_takes_the_buy(self):
        """The unmeasured merge, pinned to the model: 1106 sits at 65, so a
        second buy increments it rather than taking a cell of its own."""
        self._gold(48234)
        items.insert(self.conn, _filler(CHARACTER, 65, item_id=1106))
        self.conn.commit()
        out = buy.execute(self.conn, self.account, CHARACTER,
                          _request(REQ_1106), now=NOW_1106)
        self.assertTrue(out.ok, out.reason)
        row = items.load(self.conn, CHARACTER, 0, 65)
        self.assertEqual((row.item_id, row.count), (1106, 2))
        rows = self.conn.execute(
            "select slot_index from character_items where character_id = ? "
            "and list_type = 0 and item_id = ?",
            (CHARACTER, 1106)).fetchall()
        self.assertEqual([r[0] for r in rows], [65])


def _filler(character_id: int, slot: int, item_id: int = 22053,
            count: int = 1) -> items.ItemStack:
    return items.ItemStack(
        character_id=character_id, list_type=0, slot_index=slot,
        item_id=item_id, count=count, durability=0, instance_value=0,
        random_options=b"",
        avatar_sockets=b"", clone_appearance_id=0, reinforcement=0,
        refinement=0, fusion_item="", bakal_state="", transferred_option_mask=0,
        enchant_card_id=0, enchant_upgrade=0, mist_imbued=0, updated_at=1,
        expires_at=0, custom_option_ids=0, growth_experience=0, amplify_type=0,
        amplify_value=0)


def _frames(outcome: buy.Outcome) -> list[tuple[frame.Opcode, bytes]]:
    return buy.frames(outcome)


def _with_instance(want_ack: bytes, want_char: bytes, row: items.ItemStack):
    """The 29127 pair with the drawn `instance_value` written in: the ack's
    block at `[27:31]`, the character frame's second record at `[174:178]`."""
    value = struct.pack("<I", row.instance_value)
    return [(buy.OPCODE, want_ack[:27] + value + want_ack[31:]),
            (SLOT_OPCODE, want_char[:174] + value + want_char[178:]),
            (BOARD_OPCODE, BOARD)]


class SocketTest(unittest.TestCase):
    """The wiring: the 29127 buy on a real socket, three frames back."""

    def setUp(self):
        self.save = _save_copy()
        conn = schema.connect(self.save)
        self.account = accounts.sole_account(conn)
        gold = items.load(conn, 1, 0, 0)
        items.set_count(conn, gold, 47182, 1)
        for slot in (17,):
            if items.load(conn, 1, 0, slot) is not None:
                items.delete(conn, 1, 0, slot)
        for slot in range(9, 17):
            if items.load(conn, 1, 0, slot) is None:
                items.insert(conn, _filler(1, slot))
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _session(self, log, *frames):
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 save_db=self.save, unix_seconds=1_789_824_022)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                for seq, (main, sub, body) in enumerate(frames):
                    writer.write(frame.build(
                        frame.Link.GAME_C2S,
                        frame.Opcode(main, sub, frame.OpcodeEncoding.U8_U16LE, True),
                        tiles.encrypt_body(tiles.algo_id(sub), body), seq=seq))
                await writer.drain()
                got = bytearray()
                while True:
                    try:
                        chunk = await asyncio.wait_for(reader.read(65536),
                                                       timeout=2.0)
                    except asyncio.TimeoutError:
                        break
                    if not chunk:
                        break
                    got += chunk
                writer.close()
                return bytes(got)
            finally:
                server.close()

        return asyncio.run(run())

    def _decode(self, data):
        stream = frame.FrameStream(frame.Link.GAME_S2C)
        stream.feed(data)
        frames = []
        while (f := stream.next_frame()) is not None:
            frames.append((f.opcode,
                           tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)))
        return frames

    def test_the_equipment_buy_draws_the_three_frames_and_persists(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log, (1, 4, bytes(16)), (1, 21, REQ_29127))
        frames = self._decode(raw)[-3:]
        self.assertEqual([o.key() for o, _ in frames],
                         [(1, 21), (0, 14), (0, 1361)])

        conn = schema.connect(self.save, readonly=True)
        try:
            row = items.load(conn, 1, 0, 17)
            self.assertEqual((row.item_id, row.durability), (29127, 48))
            gold = items.load(conn, 1, 0, 0)
            self.assertEqual(gold.count, 1682)
        finally:
            conn.close()
        want_ack = ACK_29127[:27] + struct.pack("<I", row.instance_value) \
            + ACK_29127[31:]
        want_char = CHAR_29127[:174] + struct.pack("<I", row.instance_value) \
            + CHAR_29127[178:]
        self.assertEqual([b for _, b in frames],
                         [want_ack, want_char, BOARD])

        text = log._fh.getvalue()
        self.assertIn("NPC-BUY-21 conn=1 request shop=30 item=29127 count=1 "
                      "field=57 layout=npc mode=0", text)
        self.assertIn("NPC-BUY-21 conn=1 shop=30 item=29127 count=1 gold=45500 "
                      "materialSlots=0 limits=0 committed=true", text)
        self.assertIn("conn=1 (1,21) -> 3 frame(s) 592B", text)

    def test_a_body_of_the_wrong_size_is_logged_and_answers_nothing(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log, (1, 4, bytes(16)), (1, 21, bytes(25)))
        got = self._decode(raw)
        self.assertFalse([o for o, _ in got if o.key() in ((1, 21), (0, 14))])
        self.assertIn("NPC-BUY-21 conn=1 rejected=malformed request error=250",
                      log._fh.getvalue())

    def test_an_item_of_another_shop_is_refused_silently(self):
        log = Log(stream=io.StringIO())
        # shop 15's npc is 2, so the body is a plausible one answered "no".
        wrong_shop = struct.pack("<4I", 29127, 46115, 15, 2) + bytes(8)
        raw = self._session(log, (1, 4, bytes(16)), (1, 21, wrong_shop))
        got = self._decode(raw)
        self.assertFalse([o for o, _ in got if o.key() in ((1, 21), (0, 14))])
        self.assertIn("refused: item is not in that shop; not stored",
                      log._fh.getvalue())


if __name__ == "__main__":
    unittest.main()
