"""`(1,64)`/`(1,63)` cera shop: the reference's own runs, byte for byte.

Measured 2026-09-27 23:16 from the live reference (`conn=2`, account 0,
character 2, `DFO110-0.3.6/Server/Logs/server-20260927.log`): a balance poll
at 23:16:24, then two buys --

    23:16:30  commodity 3400255  item 590713930 x1    25 cera  -> slot 66
    23:16:37  commodity 3000112  item 1         x100 900 cera  -> slot 1

Each buy answers four frames -- the 56B ack, the `(0,53)`, the `(0,14)` and
the `(0,1361)` board, 320B over 72+32+184+32 -- and every ack, balance and
slot body below is the capture's own plaintext, dumped with the project's
`tools/dump_frames.py`.

The other three families are pinned from the older logs and the save they
left (09-25/09-26):

* a **ticket** -- commodity 3000148 (item 2660297) sets the character's
  expansion to 16, `expansion=8->16` on the line, nothing delivered;
* a **warehouse kit** -- commodity 3000134 (item 61) writes 104 into
  `character_cargo_state` and nothing else, under its own `CARGO-BUY` tag;
* a **contract** -- commodity 3000678 (item 10000389) moves
  `account_premium_contracts.expires_at` to `max(standing, now) + 604800`,
  the rule the 09-25 chain of 18 consecutive buys pins (1790315704 ->
  1790920504 -> ... -> 1801202104, the save's own final row).

The save's pre-state every run needs is *set*, never assumed: the two rows
the buys left (`character_items` list 0 at slots 66 and 1) are cleared, the
balance is put back to 96500 with a sentinel `updated_at`, and cell 65 is
kept occupied so the event item lands at 66 the way it did.  The stamps the
two 09-27 runs wrote are the captures' own seconds (23:16:30 -> 1790522190,
23:16:37 -> 1790522197, both in the save).
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
from unittest import mock

import _bootstrap  # noqa: F401
import _save

from uslocalserver import paths
from uslocalserver.game.data import load
from uslocalserver.game.item import refresh
from uslocalserver.game.shop import cera
from uslocalserver.persistence import accounts, capacity, items, schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

CHARACTER = 2
NOW_EVENT = 1_790_522_190          # 2026-09-27 23:16:30 +08:00 -- the save's own stamp
NOW_COIN = 1_790_522_197           # 23:16:37
NOW_TICKET = 1_790_298_697         # 2026-09-25 09:11:37
NOW_KIT = 1_790_390_768            # 2026-09-26 10:46:08
NOW_CONTRACT = 1_790_315_704       # 2026-09-25 13:55:04

REQ_EVENT = bytes.fromhex("00000100003fe2330001000000000000")
REQ_COIN = bytes.fromhex("000001000030c72d0001000000000000")
#: `(1,63)` takes an empty body -- 0B on both 09-27 polls.
REQ_POLL = b""

ACK_EVENT = bytes.fromhex(
    "0100ffffffff3fe233000000000000000000000000000000ffffffff0000000000000000000000000000"
    "0000010000000000000000000000"
)
ACK_COIN = bytes.fromhex(
    "0100ffffffff30c72d000000000000000000000000000000ffffffff0000000000000000000000000000"
    "0000010000000000000000000000"
)
BAL_96500 = bytes.fromhex("01f47801000100000000000000000000")
BAL_96475 = bytes.fromhex("01db7801000100000000000000000000")
BAL_95575 = bytes.fromhex("01577501000100000000000000000000")
SLOT_EVENT = bytes.fromhex(
    "00010042004a943523010000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)
SLOT_COIN = bytes.fromhex(
    "000100010001000000640000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)
BOARD = bytes.fromhex("32000000000000000000000000000000")

BOARD_OPCODE = refresh.OPCODE_BOARD
SLOT_OPCODE = refresh.OPCODE_SLOT

#: The `(1,143)` request, verbatim from the probe log (`test_town_move`).
ENTRY_REQUEST = bytes.fromhex("00240000000100000000000000000000")
#: Where the `(0,53)` sits in the 33-frame town burst.
TOWN_AT = 14


def _save_copy() -> Path:
    # The 0.4.4 save ships one character; the ids this module names
    # are cloned from it so the foreign keys resolve.
    return _save.fresh(CHARACTER, 1, 2, 3)


def _request(body: bytes) -> cera.BuyRequest:
    return cera.BuyRequest.parse(body)


class RequestTest(unittest.TestCase):
    def test_the_two_reference_bodies_parse_field_for_field(self):
        for body, commodity, quantity in ((REQ_EVENT, 3400255, 1),
                                          (REQ_COIN, 3000112, 1)):
            with self.subTest(body=body.hex()):
                req = _request(body)
                self.assertEqual((req.prefix, req.cart, req.row, req.col,
                                  req.commodity, req.quantity),
                                 ((0, 0), 1, 0, 0, commodity, quantity))

    def test_the_request_line_is_the_reference_one(self):
        self.assertEqual(
            _request(REQ_EVENT).request_line(2, REQ_EVENT),
            "conn=2 prefix=(0,0) cart=1: commodity=3400255 sel=(0,0) "
            "quantity=1 plain=00000100003FE2330001000000000000")
        self.assertEqual(
            _request(REQ_COIN).request_line(2, REQ_COIN),
            "conn=2 prefix=(0,0) cart=1: commodity=3000112 sel=(0,0) "
            "quantity=1 plain=000001000030C72D0001000000000000")

    def test_a_body_of_another_size_is_refused(self):
        for body in (REQ_EVENT[:-1], REQ_EVENT + b"\x00", REQ_POLL):
            with self.subTest(size=len(body)):
                with self.assertRaises(ValueError):
                    _request(body)


class CatalogueTest(unittest.TestCase):
    """The four family tables, as the captures read them."""

    def test_the_two_bought_commodities_are_their_save_rows(self):
        event = cera.product(3400255)
        self.assertEqual((event.item_id, event.count, event.price,
                          event.section), (590713930, 1, 25, "item event"))
        coin = cera.product(3000112)
        self.assertEqual((coin.item_id, coin.count, coin.price,
                          coin.section), (1, 100, 900, "item second"))
        self.assertIsNone(cera.product(999999999))

    def test_the_catalogue_cap_is_the_one_the_line_prints(self):
        self.assertEqual(cera.purchase_limit(3400255), 0)
        self.assertIsNone(cera.purchase_limit(3000112))

    def test_only_the_two_measured_tickets_have_a_target(self):
        """92 tickets, 90 of them target 0 -- which is why `execute` refuses
        the zero ones instead of writing a bag *down*."""
        targets = {int(k): v["target"]
                   for k, v in load("inventory_tickets")["tickets"].items()}
        self.assertEqual(len(targets), 92)
        self.assertEqual({k: v for k, v in targets.items() if v},
                         {2660296: 8, 2660297: 16})
        self.assertEqual(sum(1 for v in targets.values() if not v), 90)
        self.assertEqual(cera.ticket_target(2660297), 16)
        self.assertEqual(cera.ticket_target(10152158), 0)
        self.assertIsNone(cera.ticket_target(1))

    def test_the_warehouse_kits_are_the_cargo_table(self):
        kit = cera.cargo_kit(61)
        self.assertEqual((kit.capacity, kit.second), (104, False))
        self.assertEqual(cera.cargo_kit(50).capacity, 24)
        self.assertEqual(cera.cargo_kit(10333724).second, True)
        self.assertIsNone(cera.cargo_kit(1))

    def test_the_contract_terms_are_the_premium_table(self):
        self.assertEqual(cera.contract_rule(10000389), (92, 604800))
        self.assertIsNone(cera.contract_rule(1))


class FrameTest(unittest.TestCase):
    """`ack`/`frames`/`balance_body` over constructed outcomes."""

    def _event_outcome(self) -> cera.Outcome:
        return cera.Outcome(
            True, family=cera.ITEM_FAMILY, product=cera.product(3400255),
            item_id=590713930, units=1, price=25, cera_after=96475, slots=(66,),
            expansion_before=16, expansion_after=16,
            records=(refresh.SlotRecord(slot_index=66, item_id=590713930,
                                        value=1),))

    def test_the_two_acks_are_the_captures(self):
        self.assertEqual(cera.ack(self._event_outcome()), ACK_EVENT)
        coin = replace(self._event_outcome(), product=cera.product(3000112),
                       item_id=1, units=100, price=900, cera_after=95575,
                       slots=(1,),
                       records=(refresh.SlotRecord(slot_index=1, item_id=1,
                                                   value=100),))
        self.assertEqual(cera.ack(coin), ACK_COIN)

    def test_the_four_frames_are_the_captures(self):
        self.assertEqual(
            cera.frames(self._event_outcome()),
            [(cera.OPCODE, ACK_EVENT),
             (cera.BALANCE_OPCODE, BAL_96475),
             (SLOT_OPCODE, SLOT_EVENT),
             (BOARD_OPCODE, BOARD)])

    def test_a_landed_nothing_outcome_has_no_slot_frame(self):
        """The three families that deliver no row: ack, balance, board."""
        ticket = cera.Outcome(True, family=cera.EXPANSION_FAMILY,
                              product=cera.product(3000148), item_id=2660297,
                              units=1, price=90, cera_after=99870,
                              expansion_before=8, expansion_after=16)
        self.assertEqual([op.key() for op, _ in cera.frames(ticket)],
                         [(1, 64), (0, 53), (0, 1361)])

    def test_the_balance_body_is_the_captures_three_frames(self):
        self.assertEqual(cera.balance_body(96500), BAL_96500)
        self.assertEqual(cera.balance_body(96475), BAL_96475)
        self.assertEqual(cera.balance_body(95575), BAL_95575)


class SaveTest(unittest.TestCase):
    """`execute` against a copy of the real save: the effects and the pins."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        self.account = accounts.sole_account(self.conn)
        self._clear(0, 66)
        self._clear(0, 1)
        if items.load(self.conn, CHARACTER, 0, 65) is None:
            items.insert(self.conn, _filler(CHARACTER, 65))
        accounts.set_cera(self.conn, self.account, 96500, 1)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _clear(self, list_type: int, slot: int) -> None:
        if items.load(self.conn, CHARACTER, list_type, slot) is not None:
            items.delete(self.conn, CHARACTER, list_type, slot)

    def _cera(self) -> tuple[int, int]:
        row = self.conn.execute(
            "select cera, updated_at from accounts where account_id = ?",
            (self.account,)).fetchone()
        return row[0], row[1]

    # ------------------------------------------------------- the two runs

    def test_the_event_buy_spends_25_and_lands_at_66(self):
        out = cera.execute(self.conn, self.account, CHARACTER,
                           _request(REQ_EVENT), now=NOW_EVENT)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual((out.family, out.price, out.cera_after, out.slots),
                         (cera.ITEM_FAMILY, 25, 96475, (66,)))
        row = items.load(self.conn, CHARACTER, 0, 66)
        self.assertEqual((row.item_id, row.count, row.instance_value,
                          row.durability, row.updated_at),
                         (590713930, 1, 0, 0, NOW_EVENT))
        self.assertEqual(self._cera(), (96475, NOW_EVENT))
        self.assertEqual(cera.frames(out),
                         [(cera.OPCODE, ACK_EVENT),
                          (cera.BALANCE_OPCODE, BAL_96475),
                          (SLOT_OPCODE, SLOT_EVENT),
                          (BOARD_OPCODE, BOARD)])
        self.assertEqual(
            cera.item_line(2, out),
            "conn=2 commodity 3400255 (item event) -> item 590713930 ×1 into "
            "Consumable slot(s) [66] for 25 cera; expansion=16->16; the "
            "catalogue caps this one at 0 (not enforced)")
        self.assertEqual(
            cera.delivered_line(2, out),
            "conn=2 delivered 1 of 1 item(s); spent 25 cera, 96475 left; "
            "answered with the per-item acks + (0,53) + (0,14)×1")

    def test_the_coin_buy_spends_900_and_takes_cell_1(self):
        # The capture's own pre-state: the event buy's 25 were already gone
        # when the coin buy answered 95575.
        accounts.set_cera(self.conn, self.account, 96475, 1)
        self.conn.commit()
        out = cera.execute(self.conn, self.account, CHARACTER,
                           _request(REQ_COIN), now=NOW_COIN)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual((out.price, out.cera_after, out.slots),
                         (900, 95575, (1,)))
        row = items.load(self.conn, CHARACTER, 0, 1)
        self.assertEqual((row.item_id, row.count, row.updated_at),
                         (1, 100, NOW_COIN))
        self.assertEqual(self._cera(), (95575, NOW_COIN))
        self.assertEqual(cera.frames(out),
                         [(cera.OPCODE, ACK_COIN),
                          (cera.BALANCE_OPCODE, BAL_95575),
                          (SLOT_OPCODE, SLOT_COIN),
                          (BOARD_OPCODE, BOARD)])
        self.assertEqual(
            cera.item_line(2, out),
            "conn=2 commodity 3000112 (item second) -> item 1 ×100 into "
            "Consumable slot(s) [1] for 900 cera; expansion=16->16")

    def test_the_coin_the_catalogue_sells_merges_into_a_row_already_there(self):
        """The unmeasured merge, pinned to the model: cell 1 held, so the
        buy moves the row's count and takes no cell of its own."""
        items.insert(self.conn, _filler(CHARACTER, 1, item_id=1, count=7))
        self.conn.commit()
        out = cera.execute(self.conn, self.account, CHARACTER,
                           _request(REQ_COIN), now=NOW_COIN)
        self.assertTrue(out.ok, out.reason)
        row = items.load(self.conn, CHARACTER, 0, 1)
        self.assertEqual((row.item_id, row.count, row.updated_at),
                         (1, 107, NOW_COIN))
        self.assertEqual(out.slots, (1,))
        self.assertIsNone(items.load(self.conn, CHARACTER, 0, 2))

    # --------------------------------------------------------- the families

    def test_a_ticket_raises_the_expansion_and_delivers_nothing(self):
        capacity.set_expansion(self.conn, CHARACTER, 8)
        self.conn.commit()
        out = cera.execute(self.conn, self.account, CHARACTER,
                           _request(bytes.fromhex("000001000054c72d0001000000000000")),
                           now=NOW_TICKET)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual((out.family, out.price, out.cera_after, out.slots,
                          out.expansion_before, out.expansion_after),
                         (cera.EXPANSION_FAMILY, 90, 96410, (), 8, 16))
        self.assertEqual(capacity.expansion(self.conn, CHARACTER), 16)
        self.assertEqual(self._cera(), (96410, NOW_TICKET))
        self.assertIn("expansion=8->16", cera.item_line(2, out))
        self.assertIn("slot(s) []", cera.item_line(2, out))
        self.assertIn("(0,14)×0", cera.delivered_line(2, out))
        self.assertEqual([op.key() for op, _ in cera.frames(out)],
                         [(1, 64), (0, 53), (0, 1361)])

    def test_a_zero_target_ticket_is_refused_rather_than_written(self):
        """No commodity sells one and a write would take an upgraded bag
        *down*; the guard is against the 90 zero rows, not a capture."""
        capacity.set_expansion(self.conn, CHARACTER, 16)
        self.conn.commit()
        zero = cera.Product(commodity=3000000, item_id=10152158, count=1,
                            price=10, bag=1, stack=0, section="item")
        with mock.patch.object(cera, "product", return_value=zero):
            out = cera.execute(self.conn, self.account, CHARACTER,
                               replace(_request(REQ_EVENT), commodity=3000000),
                               now=NOW_TICKET)
        self.assertEqual((out.ok, out.reason),
                         (False, "ticket target 0 is not an expansion"))
        self.assertEqual(capacity.expansion(self.conn, CHARACTER), 16)
        self.assertEqual(self._cera(), (96500, 1))

    def test_a_warehouse_kit_writes_the_capacity_and_nothing_else(self):
        capacity.set_cargo_capacity(self.conn, CHARACTER, 8)
        self.conn.commit()
        out = cera.execute(self.conn, self.account, CHARACTER,
                           _request(bytes.fromhex("000001000046c72d0001000000000000")),
                           now=NOW_KIT)
        self.assertTrue(out.ok, out.reason)
        self.assertEqual((out.family, out.price, out.cera_after, out.slots),
                         (cera.CARGO_FAMILY, 400, 96100, ()))
        self.assertEqual(capacity.cargo_capacity(self.conn, CHARACTER), 104)
        self.assertEqual(capacity.cargo_capacity(self.conn, CHARACTER,
                                                 second=True), 8)
        self.assertEqual(self._cera(), (96100, NOW_KIT))
        self.assertEqual(cera.cargo_line(2, out),
                         "conn=2 item=61 price=400; upgraded and persisted")
        self.assertEqual([op.key() for op, _ in cera.frames(out)],
                         [(1, 64), (0, 53), (0, 1361)])

    def test_a_contract_extends_from_wherever_the_row_stood(self):
        """The 18-buy chain: `max(standing, now) + 604800` each time, so the
        second buy 0.6s later adds a whole week on top of the first."""
        accounts.set_contract(self.conn, self.account, 92, 1_790_315_704,
                              1_790_315_711)
        self.conn.commit()
        body = bytes.fromhex("000001000066c92d0001000000000000")
        first = cera.execute(self.conn, self.account, CHARACTER,
                             _request(body), now=NOW_CONTRACT)
        self.assertTrue(first.ok, first.reason)
        self.assertEqual((first.family, first.price, first.premium_type,
                          first.expires_at), (cera.CONTRACT_FAMILY, 0, 92,
                                              1_790_920_504))
        self.assertEqual(accounts.premium_contracts(self.conn, self.account),
                         ((92, 1_790_920_504),))
        self.assertEqual(
            cera.contract_line(2, first),
            "conn=2 commodity 3000678 activated account contract type=92 "
            "expiresAt=1790920504 for 0 cera; no inventory item")
        second = cera.execute(self.conn, self.account, CHARACTER,
                              _request(body), now=NOW_CONTRACT + 1)
        self.assertEqual(second.expires_at, 1_791_525_304)
        self.assertEqual(accounts.premium_contracts(self.conn, self.account),
                         ((92, 1_791_525_304),))
        self.assertEqual([op.key() for op, _ in cera.frames(second)],
                         [(1, 64), (0, 53), (0, 1361)])

    # ------------------------------------------------------------ refusals

    def test_every_refusal_writes_nothing(self):
        cases = (
            (replace(_request(REQ_EVENT), commodity=999999999),
             "commodity is not in the catalogue"),
            (replace(_request(REQ_EVENT), cart=2), "cart is not 1"),
            (replace(_request(REQ_EVENT), quantity=0),
             "quantity is not positive"),
        )
        for request, reason in cases:
            with self.subTest(reason=reason):
                out = cera.execute(self.conn, self.account, CHARACTER,
                                   request, now=NOW_EVENT)
                self.assertEqual((out.ok, out.reason), (False, reason))
                self.assertEqual(self._cera(), (96500, 1))
                self.assertIsNone(items.load(self.conn, CHARACTER, 0, 66))

    def test_a_balance_short_of_the_price_writes_nothing(self):
        accounts.set_cera(self.conn, self.account, 899, 1)
        self.conn.commit()
        out = cera.execute(self.conn, self.account, CHARACTER,
                           _request(REQ_COIN), now=NOW_COIN)
        self.assertEqual((out.ok, out.reason), (False, "not enough cera"))
        self.assertEqual(self._cera(), (899, 1))
        self.assertIsNone(items.load(self.conn, CHARACTER, 0, 1))


def _filler(character_id: int, slot: int, item_id: int = 22053,
            count: int = 1) -> items.ItemStack:
    return items.ItemStack(
        character_id=character_id, list_type=0, slot_index=slot,
        item_id=item_id, count=count, durability=0, instance_value=0,
        random_options=b"", avatar_sockets=b"", clone_appearance_id=0,
        reinforcement=0, refinement=0, fusion_item="", bakal_state="",
        transferred_option_mask=0, enchant_card_id=0, enchant_upgrade=0,
        mist_imbued=0, updated_at=1, expires_at=0, custom_option_ids=0,
        growth_experience=0, amplify_type=0, amplify_value=0)


class SocketTest(unittest.TestCase):
    """The wiring, in the capture's own order: entry, poll, both buys."""

    def setUp(self):
        self.save = _save_copy()
        conn = schema.connect(self.save)
        self.account = accounts.sole_account(conn)
        for slot in (66, 1):
            if items.load(conn, 1, 0, slot) is not None:
                items.delete(conn, 1, 0, slot)
        if items.load(conn, 1, 0, 65) is None:
            items.insert(conn, _filler(1, 65))
        accounts.set_cera(conn, self.account, 96500, 1)
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

    def test_entry_poll_and_both_buys_are_the_captured_frames(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log,
                            (1, 4, bytes(16)),
                            (1, 143, ENTRY_REQUEST),
                            (1, 63, REQ_POLL),
                            (1, 64, REQ_EVENT),
                            (1, 64, REQ_COIN))
        frames = self._decode(raw)
        start = next(i for i, (o, _) in enumerate(frames)
                     if (o.main, o.sub) == (1, 143))
        burst = frames[start:start + 33]
        self.assertEqual(len(burst), 33)
        # The entry's own `(0,53)` now reads the account row, not the 96500
        # the capture happened to carry in that session.
        self.assertEqual(burst[TOWN_AT],
                         (cera.BALANCE_OPCODE, BAL_96500))

        tail = frames[start + 33:]
        self.assertEqual(tail[0], (cera.BALANCE_OPCODE, BAL_96500))
        self.assertEqual(tail[1:], [(cera.OPCODE, ACK_EVENT),
                                    (cera.BALANCE_OPCODE, BAL_96475),
                                    (SLOT_OPCODE, SLOT_EVENT),
                                    (BOARD_OPCODE, BOARD),
                                    (cera.OPCODE, ACK_COIN),
                                    (cera.BALANCE_OPCODE, BAL_95575),
                                    (SLOT_OPCODE, SLOT_COIN),
                                    (BOARD_OPCODE, BOARD)])

        conn = schema.connect(self.save, readonly=True)
        try:
            event = items.load(conn, 1, 0, 66)
            self.assertEqual((event.item_id, event.count), (590713930, 1))
            self.assertEqual(items.load(conn, 1, 0, 1).count, 100)
            self.assertEqual(accounts.cera(conn, self.account), 95575)
        finally:
            conn.close()

        text = log._fh.getvalue()
        # The tag is padded to ten columns, so `TOWN-CERA` takes two spaces.
        self.assertIn("TOWN-CERA  conn=1 account 0 cera=96500; sent as (0,53)",
                      text)
        self.assertIn("CERA-REQUEST-63 conn=1 account 0 cera=96500; "
                      "answered with (0,53)", text)
        self.assertIn("SHOP-BUY-64 conn=1 prefix=(0,0) cart=1: commodity=3400255 "
                      "sel=(0,0) quantity=1 plain=00000100003FE2330001000000000000",
                      text)
        self.assertIn("SHOP-BUY-64 conn=1 delivered 1 of 1 item(s); spent 25 "
                      "cera, 96475 left; answered with the per-item acks + "
                      "(0,53) + (0,14)×1", text)
        self.assertIn("conn=1 (1,63) -> 1 frame(s) 32B state=InTown->InTown",
                      text)
        self.assertIn("conn=1 (1,64) -> 4 frame(s) 320B state=InTown->InTown",
                      text)

    def test_a_poll_after_a_buy_reads_the_new_balance(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log, (1, 4, bytes(16)), (1, 64, REQ_EVENT),
                            (1, 63, REQ_POLL))
        tail = self._decode(raw)[-1]
        self.assertEqual(tail, (cera.BALANCE_OPCODE, BAL_96475))
        self.assertIn("CERA-REQUEST-63 conn=1 account 0 cera=96475",
                      log._fh.getvalue())

    def test_an_unknown_commodity_is_refused_silently(self):
        log = Log(stream=io.StringIO())
        body = struct.pack("<HBBBIH", 0, 1, 0, 0, 999999999, 1) + bytes(5)
        raw = self._session(log, (1, 4, bytes(16)), (1, 64, body))
        got = self._decode(raw)
        self.assertFalse([o for o, _ in got
                          if o.key() in ((1, 64), (0, 53), (0, 14))])
        self.assertIn("commodity=999999999 refused: commodity is not in the "
                      "catalogue; not stored", log._fh.getvalue())

    def test_a_body_of_the_wrong_size_is_logged_and_answers_nothing(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log, (1, 4, bytes(16)), (1, 64, bytes(15)))
        got = self._decode(raw)
        self.assertFalse([o for o, _ in got if o.key() in ((1, 64), (0, 53))])
        self.assertIn("SHOP-BUY-64 conn=1 rejected=malformed request error=250",
                      log._fh.getvalue())


if __name__ == "__main__":
    unittest.main()
