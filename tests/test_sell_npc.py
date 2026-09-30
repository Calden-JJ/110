"""`(1,22)` NPC-SELL: the reference's one sale, byte for byte.

Measured 2026-09-27 23:15:16 from the live reference (`conn=2`, account 0,
character 2, `DFO110-0.3.6/Server/Logs/server-20260927.log`): eight rows of
list 0 sold at npc 319's weapon shop 96.  The request is 104B, the answer
three frames -- a 72B ack, one 1488B `(0,14)` (the gold row plus the eight
emptied cells) and the 16B `(0,1361)` board, 1624B -- and every byte below is
the capture's own plaintext, dumped with `tools/dump_frames.py`.

The prices are the catalogue's `value` over five, exact on all eight rows
(13264 18720 -> 3744, ..., 29127 32760 -> 6552), and the gold before the sale
is *read off the capture's own arithmetic*: 48234 after minus the 46552 the
eight rows fetch = 1682, which is also what the same session's 22:54 buy
left (47182 - 45500).  The pre-state every run needs is *set*, never assumed:
the balance goes back to 1682 with a sentinel `updated_at` and the eight rows
are re-created with their own item ids, counts 1.

The one unexplained field is the request line's `tail=20`: it is row 0's
`cell` (2 * 9 + 2) and nothing else in the body is 20, so the line is
reproduced that way -- a reading of a single sample, not a rule.  Both log
lines are pinned whole -- 466 and 680 chars with the 49-char log prefix --
and the request line's `plain=` trailer is the body's own full 208 hex
chars, not the `UNHANDLED` notes' 96-byte cap.
"""
from __future__ import annotations

import asyncio
import io
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401
import _save

from uslocalserver import paths
from uslocalserver.game.data import load
from uslocalserver.game.item import refresh
from uslocalserver.game.shop import sell
from uslocalserver.persistence import accounts, items, schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

CHARACTER = 2
#: 2026-09-27 23:15:16 +08:00 -- the capture's own second.
NOW_SELL = 1_790_522_116

REQ = bytes.fromhex(
    "3f01000060000000080009000100000014000000000a000100000016000000000b000100"
    "000018000000000c00010000001a000000000d00010000001c000000000e00010000001e"
    "000000000f000100000020000000001100010000002400000000000000000000")
ACK = bytes.fromhex(
    "016abc00000800000000090000000000000a0000000000000b0000000000000c0000000000"
    "000d0000000000000e0000000000000f00000000000011000000000000000000000000")
SLOT_1488 = bytes.fromhex(
    "0009000000000000006abc0000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000900ffffffff0000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000a00ffffffff000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000b00ffffffff00000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000c00ffffffff0000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000d00ffffffff000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000e00ffffffff00"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000f00"
    "ffffffff000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000001100ffffffff00000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000")
BOARD = refresh.BOARD_AFTER_WRITE_BODY

#: The eight sold rows, in the request's order: (slot, item, value, each).
SOLD = ((9, 13264, 18720, 3744), (10, 100170173, 27440, 5488),
        (11, 100220166, 23520, 4704), (12, 100270170, 25920, 5184),
        (13, 117020057, 31680, 6336), (14, 100310851, 38880, 7776),
        (15, 100320655, 33840, 6768), (17, 29127, 32760, 6552))
#: 48234 after minus the eight rows = what the same session's 22:54 buy left.
GOLD_BEFORE = 1682
GOLD_AFTER = 48234

REQUEST_LINE = (
    "conn=2 npc=319 shop=96 (weapon shop) rows=8 tail=20: list 0 slot 9 ×1, "
    "list 0 slot 10 ×1, list 0 slot 11 ×1, list 0 slot 12 ×1, list 0 slot 13 "
    "×1, list 0 slot 14 ×1, list 0 slot 15 ×1, list 0 slot 17 ×1 "
    "plain=" + REQ.hex().upper())
OUTCOME_LINE = (
    "conn=2 sold item 13264 ×1 from list 0 slot 9 for 3744 gold (3744 each), "
    "0 left; item 100170173 ×1 from list 0 slot 10 for 5488 gold (5488 "
    "each), 0 left; item 100220166 ×1 from list 0 slot 11 for 4704 gold "
    "(4704 each), 0 left; item 100270170 ×1 from list 0 slot 12 for 5184 "
    "gold (5184 each), 0 left; item 117020057 ×1 from list 0 slot 13 for "
    "6336 gold (6336 each), 0 left; item 100310851 ×1 from list 0 slot 14 "
    "for 7776 gold (7776 each), 0 left; item 100320655 ×1 from list 0 slot "
    "15 for 6768 gold (6768 each), 0 left; item 29127 ×1 from list 0 slot 17 "
    "for 6552 gold (6552 each), 0 left; 48234 gold; answered with the ack + "
    "(0,14)×1")

#: The `(1,143)` request, verbatim from the probe log (`test_town_move`).
ENTRY_REQUEST = bytes.fromhex("00240000000100000000000000000000")


def _save_copy() -> Path:
    # The 0.4.4 save ships one character; the ids this module names
    # are cloned from it so the foreign keys resolve.
    return _save.fresh(CHARACTER, 1, 2, 3)


def _row(character_id: int, slot: int, item_id: int, count: int = 1
         ) -> items.ItemStack:
    return items.ItemStack(
        character_id=character_id, list_type=0, slot_index=slot,
        item_id=item_id, count=count, durability=33, instance_value=0,
        random_options=b"", avatar_sockets=b"", clone_appearance_id=0,
        reinforcement=0, refinement=0, fusion_item="", bakal_state="",
        transferred_option_mask=0, enchant_card_id=0, enchant_upgrade=0,
        mist_imbued=0, updated_at=1, expires_at=0, custom_option_ids=0,
        growth_experience=0, amplify_type=0, amplify_value=0)


def _stock(conn, character_id: int) -> None:
    """The 23:15:16 pre-state: 1682 gold and the eight rows back in place."""
    for slot, item_id, _value, _each in SOLD:
        if items.load(conn, character_id, 0, slot) is not None:
            items.delete(conn, character_id, 0, slot)
        items.insert(conn, _row(character_id, slot, item_id))
    gold = items.load(conn, character_id, 0, 0)
    items.set_count(conn, gold, GOLD_BEFORE, 1)


def _request(body: bytes) -> sell.SellRequest:
    return sell.SellRequest.parse(body)


class RequestTest(unittest.TestCase):
    def test_the_reference_body_parses_field_for_field(self):
        req = _request(REQ)
        self.assertEqual((req.npc, req.shop), (319, 96))
        self.assertEqual([(row.slot, row.count, row.cell) for row in req.rows],
                         [(slot, 1, 2 * slot + 2) for slot, *_ in SOLD])
        self.assertEqual(req.tail, 20)

    def test_the_request_line_is_the_reference_one(self):
        self.assertEqual(_request(REQ).request_line(2, sell.shop_type(96), REQ),
                         REQUEST_LINE)
        # The capture's line, its 49-char log prefix included.
        self.assertEqual(len("2026-09-27 23:15:16.055 +08:00 INFO  "
                             "NPC-SELL-22 " + REQUEST_LINE), 466)

    def test_a_body_of_another_size_is_refused(self):
        for body in (REQ[:-1], REQ + b"\x00", b"", bytes(96)):
            with self.subTest(size=len(body)):
                with self.assertRaises(ValueError):
                    _request(body)

    def test_more_rows_than_the_body_holds_is_refused(self):
        body = bytearray(REQ)
        struct.pack_into("<H", body, 8, 9)
        with self.assertRaises(ValueError):
            _request(bytes(body))


class CatalogueTest(unittest.TestCase):
    """The shop and the price rule, as the capture reads them."""

    def test_shop_96_is_the_weapon_shop_the_line_names(self):
        self.assertEqual(sell.shop_type(96), "weapon shop")
        self.assertEqual(sell.shop(96)["npc"], 319)
        self.assertEqual(sell.shop_type(9999999), "")

    def test_every_sold_price_is_the_catalogue_value_over_five(self):
        for _slot, item_id, value, each in SOLD:
            with self.subTest(item=item_id):
                self.assertEqual(each * sell.VALUE_DIVISOR, value)
                self.assertEqual(
                    sell.content.definition(item_id).value, value)

    def test_the_body_has_no_field_the_catalogues_do_not_read(self):
        """`cell` is `2 * slot + 2` on all eight rows -- read for the line's
        `tail` only; the address this module sells is the u16 slot."""
        req = _request(REQ)
        self.assertEqual([row.cell - 2 * row.slot for row in req.rows],
                         [2] * 8)


class FrameTest(unittest.TestCase):
    """`ack`/`frames` over the outcome the capture's sale produces."""

    def _sale(self) -> sell.Outcome:
        conn = schema.connect(_save_copy())
        self.addCleanup(conn.close)
        _stock(conn, CHARACTER)
        conn.commit()
        return sell.execute(conn, accounts.sole_account(conn), CHARACTER,
                            _request(REQ), now=NOW_SELL)

    def test_the_ack_is_the_captures(self):
        self.assertEqual(sell.ack(self._sale()), ACK)

    def test_the_three_frames_are_the_captures(self):
        outcome = self._sale()
        self.assertEqual(sell.frames(outcome),
                         [(sell.OPCODE, ACK),
                          (refresh.OPCODE_SLOT, SLOT_1488),
                          (refresh.OPCODE_BOARD, BOARD)])

    def test_the_ack_pads_to_eight(self):
        """n rows of 7B after a 10B header: 72B at the capture's eight."""
        self.assertEqual(len(ACK) % 8, 0)
        self.assertEqual(len(ACK), 10 + 8 * 7 + 6)


class SaveTest(unittest.TestCase):
    """`execute` against a copy of the real save: the effects and the pins."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        self.account = accounts.sole_account(self.conn)
        _stock(self.conn, CHARACTER)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _gold(self) -> tuple[int, int]:
        row = items.load(self.conn, CHARACTER, 0, 0)
        return row.count, row.updated_at

    def test_the_sale_pays_48234_and_empties_the_eight_slots(self):
        out = sell.execute(self.conn, self.account, CHARACTER, _request(REQ),
                           now=NOW_SELL)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual(out.gold_after, GOLD_AFTER)
        self.assertEqual(self._gold(), (GOLD_AFTER, NOW_SELL))
        for slot, item_id, _value, each in SOLD:
            with self.subTest(slot=slot):
                self.assertIsNone(items.load(self.conn, CHARACTER, 0, slot))
        self.assertEqual([(s.slot, s.item_id, s.count, s.price, s.each, s.left)
                          for s in out.sales],
                         [(slot, item_id, 1, each, each, 0)
                          for slot, item_id, _value, each in SOLD])

    def test_the_records_are_the_gold_row_then_the_eight_cells(self):
        out = sell.execute(self.conn, self.account, CHARACTER, _request(REQ),
                           now=NOW_SELL)
        self.assertEqual(
            [(r.slot_index, r.item_id, r.value) for r in out.records],
            [(0, 0, GOLD_AFTER)]
            + [(slot, refresh.EMPTY_ITEM_ID, 0) for slot, *_ in SOLD])
        self.assertEqual(refresh.slot_frame(0, out.records), SLOT_1488)

    def test_the_two_lines_are_the_reference_ones(self):
        out = sell.execute(self.conn, self.account, CHARACTER, _request(REQ),
                           now=NOW_SELL)
        self.assertEqual(_request(REQ).request_line(2, sell.shop_type(96), REQ),
                         REQUEST_LINE)
        self.assertEqual(sell.outcome_line(2, out), OUTCOME_LINE)
        self.assertEqual(len("2026-09-27 23:15:16.063 +08:00 INFO  "
                             "NPC-SELL-22 " + OUTCOME_LINE), 680)

    def test_a_partial_sale_leaves_the_row_and_carries_what_is_left(self):
        """No capture sells a stack short; the grammar is the ack's own
        `count-after`, so the row stays with its remaining units."""
        items.insert(self.conn, _row(CHARACTER, 30, 1106, count=5))
        body = bytearray(REQ)
        struct.pack_into("<H", body, 8, 1)
        struct.pack_into("<HII", body, 10, 30, 3, 62)
        out = sell.execute(self.conn, self.account, CHARACTER,
                           sell.SellRequest.parse(bytes(body)), now=NOW_SELL)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual(out.sales[0].left, 2)
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 30).count, 2)
        self.assertEqual(sell.ack(out)[10:17],
                         struct.pack("<HIB", 30, 2, 0))
        self.assertEqual(out.records[1].value, 2)

    def test_every_refusal_writes_nothing(self):
        """Shop, rows, slots, counts, the catalogue -- all checked before the
        first write, so a refusal leaves the save as it was."""
        def body(rows, rows_field=None):
            out = bytearray(REQ)
            struct.pack_into("<H", out, 8, len(rows) if rows_field is None
                             else rows_field)
            for i, (slot, count, cell) in enumerate(rows):
                struct.pack_into("<HII", out, 10 + i * 11, slot, count, cell)
            return bytes(out)

        cases = {
            "unknown shop": bytes.fromhex("3f010000") + struct.pack("<I", 9999999)
                            + REQ[8:],
            "no rows": body([], rows_field=0),
            "repeated slot": body([(9, 1, 20), (9, 1, 20)]),
            "zero count": body([(9, 0, 20)]),
            "count past the row": body([(9, 2, 20)]),
            "empty slot": body([(100, 1, 202)]),
            "gold row": body([(0, 1, 2)]),
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                before = self._gold()
                out = sell.execute(self.conn, self.account, CHARACTER,
                                   sell.SellRequest.parse(payload),
                                   now=NOW_SELL)
                self.assertFalse(out.ok, name)
                self.assertEqual(out.reason != "", True)
                self.assertEqual(self._gold(), before)
                self.assertIsNotNone(items.load(self.conn, CHARACTER, 0, 9))

    def test_a_character_without_a_gold_row_is_refused(self):
        items.delete(self.conn, CHARACTER, 0, 0)
        out = sell.execute(self.conn, self.account, CHARACTER, _request(REQ),
                           now=NOW_SELL)
        self.assertFalse(out.ok)
        self.assertEqual(out.reason, "no gold row")


class SocketTest(unittest.TestCase):
    """The wiring: the request in, the capture's three frames out."""

    def setUp(self):
        self.save = _save_copy()
        conn = schema.connect(self.save)
        self.account = accounts.sole_account(conn)
        _stock(conn, 1)
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

    def test_the_sale_answers_with_the_captured_three_frames(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log,
                            (1, 4, bytes(16)),
                            (1, 143, ENTRY_REQUEST),
                            (1, 22, REQ))
        got = self._decode(raw)
        self.assertEqual([str(op) for op, _ in got[-3:]],
                         ["(1,22)", "(0,14)", "(0,1361)"])
        self.assertEqual([body for _, body in got[-3:]],
                         [ACK, SLOT_1488, BOARD])
        text = log._fh.getvalue()
        self.assertIn("NPC-SELL-22 conn=1 npc=319 shop=96 (weapon shop) "
                      "rows=8 tail=20: list 0 slot 9 ×1", text)
        self.assertIn("NPC-SELL-22 conn=1 sold item 13264 ×1 from list 0 slot "
                      "9 for 3744 gold (3744 each), 0 left;", text)
        self.assertIn("48234 gold; answered with the ack + (0,14)×1", text)
        self.assertIn("DISPATCH   conn=1 (1,22) -> 3 frame(s) 1624B", text)

    def test_a_body_of_the_wrong_size_is_logged_and_answers_nothing(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log, (1, 4, bytes(16)), (1, 22, REQ[:-1]))
        got = self._decode(raw)
        self.assertFalse([o for o, _ in got
                          if o.key() in ((1, 22), (0, 14), (0, 1361))])
        self.assertIn("NPC-SELL-22 conn=1 rejected=malformed request error=250",
                      log._fh.getvalue())

    def test_a_sale_the_catalogue_does_not_know_is_refused_silently(self):
        body = bytearray(REQ)
        struct.pack_into("<I", body, 4, 9999999)
        log = Log(stream=io.StringIO())
        raw = self._session(log, (1, 4, bytes(16)), (1, 22, bytes(body)))
        got = self._decode(raw)
        self.assertFalse([o for o, _ in got
                          if o.key() in ((1, 22), (0, 14), (0, 1361))])
        self.assertIn("refused: shop is not in the catalogue; not stored",
                      log._fh.getvalue())


if __name__ == "__main__":
    unittest.main()
