"""`(1,19)` CARGO-MOVE: the reference's own line and the four frames.

The three runs are the 09-27 probe's own (22:56:04/06/08, `conn=2`, account 0,
character 2), embedded verbatim: the request `plain=` each `ITEM-MOVE-19` line
recorded, the ack, both `(0,14)` bodies and the 16B board.  The third is the
split -- one unit out of move 2's two-stack -- and its frames carry the
2 -> 1 + 1 the save still holds: `(2,5)` and `(0,83)` both count 1, both
stamped 22:56:08.

Move 1's whole-move rule is pinned to the save too: `(0,65)` moved item 1001
whole with `count=4` and the destination row at `(2,4)` is a 4-stack.

The refusals (empty source, filled destination) and the same-container frame
shape have no sample; the tests pin what the module documents as inferred.
"""
from __future__ import annotations

import asyncio
import io
import shutil
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.game.item import cargo, inventory, refresh
from uslocalserver.persistence import accounts, items, schema
from uslocalserver.persistence import cargo as cargo_rows
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

CHARACTER = 1
#: The second the split landed in (22:56:08 +08:00).
NOW = 1_790_520_968

#: Move 1, `0/65 -> 2/4 count=4` (item 1001): the source ends empty.
MOVE_1001 = bytes.fromhex("004100e9030000040000000204000000000000000000ffffffff000000000000")
ACK_1001 = bytes.fromhex("01004100040000000204000000000000")
SLOT_0_65_EMPTY = bytes.fromhex("0001004100ffffffff" + "00" * 159)
SLOT_2_4_1001 = bytes.fromhex("0201000400e903000004000000" + "00" * 155)

#: Move 2, `0/66 -> 2/5 count=2` (item 1047): whole, both units.
MOVE_1047 = bytes.fromhex("00420017040000020000000205000000000000000000ffffffff000000000000")
ACK_1047 = bytes.fromhex("01004200020000000205000000000000")
SLOT_0_66_EMPTY = bytes.fromhex("0001004200ffffffff" + "00" * 159)
SLOT_2_5_1047_TWO = bytes.fromhex("02010005001704000002000000" + "00" * 155)

#: Move 3, `2/5 -> 0/83 count=1`: the split out of move 2's stack.
MOVE_SPLIT = bytes.fromhex("02050017040000010000000053000000000000000000ffffffff000000000000")
ACK_SPLIT = bytes.fromhex("01020500010000000053000000000000")
SLOT_2_5_1047_ONE = bytes.fromhex("02010005001704000001000000" + "00" * 155)
SLOT_0_83_1047_ONE = bytes.fromhex("00010053001704000001000000" + "00" * 155)

#: The `(0,1361)` that closes the run.
BOARD_AFTER_WRITE = bytes.fromhex("32" + "00" * 15)


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-cargo-move-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


def _row(list_type, slot_index, item_id, *, character_id=CHARACTER, count=1,
         instance_value=0, updated_at=1) -> items.ItemStack:
    return items.ItemStack(
        character_id=character_id, list_type=list_type, slot_index=slot_index,
        item_id=item_id, count=count, durability=0, instance_value=instance_value,
        random_options=b"", avatar_sockets=b"", clone_appearance_id=0, reinforcement=0,
        refinement=0, fusion_item="", bakal_state="", transferred_option_mask=0,
        enchant_card_id=0, enchant_upgrade=0, mist_imbued=0, updated_at=updated_at,
        expires_at=0, custom_option_ids=0, growth_experience=0, amplify_type=0,
        amplify_value=0)


def _stack(conn, list_type, slot_index, item_id, **kw):
    _clear(conn, list_type, slot_index)
    items.insert(conn, _row(list_type, slot_index, item_id, **kw))


def _clear(conn, list_type, slot_index):
    if items.load(conn, CHARACTER, list_type, slot_index) is not None:
        items.delete(conn, CHARACTER, list_type, slot_index)


def _request(body: bytes) -> inventory.MoveRequest:
    return inventory.MoveRequest.parse(body)


class RequestTest(unittest.TestCase):
    def test_the_three_reference_bodies_parse_field_for_field(self):
        for body, src, dst, count in (
                (MOVE_1001, (0, 65, 1001), (2, 4, 0), 4),
                (MOVE_1047, (0, 66, 1047), (2, 5, 0), 2),
                (MOVE_SPLIT, (2, 5, 1047), (0, 83, 0), 1)):
            with self.subTest(body=body.hex()):
                req = _request(body)
                self.assertEqual((req.src.list_type, req.src.slot_index,
                                  req.src.instance_value), src)
                self.assertEqual((req.dst.list_type, req.dst.slot_index,
                                  req.dst.instance_value), dst)
                self.assertEqual(req.count, count)
                self.assertTrue(cargo.is_cargo(req))

    def test_the_ack_is_the_captured_echo(self):
        for body, ack in ((MOVE_1001, ACK_1001), (MOVE_1047, ACK_1047),
                          (MOVE_SPLIT, ACK_SPLIT)):
            with self.subTest(body=body.hex()):
                self.assertEqual(_request(body).ack(ok=True), ack)

    def test_a_plain_move_is_not_cargo(self):
        self.assertFalse(cargo.is_cargo(
            inventory.MoveRequest(src=inventory.Slot(0, 6, 0),
                                  dst=inventory.Slot(0, 9, 0), count=0)))


class FrameTest(unittest.TestCase):
    def test_the_four_frame_runs_are_the_captured_ones(self):
        runs = (
            (MOVE_1001, cargo.Outcome(True, "moved",
                                      dst_after=_row(2, 4, 1001, count=4)),
             [SLOT_0_65_EMPTY, SLOT_2_4_1001], ACK_1001),
            (MOVE_1047, cargo.Outcome(True, "moved",
                                      dst_after=_row(2, 5, 1047, count=2)),
             [SLOT_0_66_EMPTY, SLOT_2_5_1047_TWO], ACK_1047),
            (MOVE_SPLIT, cargo.Outcome(True, "split",
                                       src_after=_row(2, 5, 1047, count=1),
                                       dst_after=_row(0, 83, 1047, count=1)),
             [SLOT_2_5_1047_ONE, SLOT_0_83_1047_ONE], ACK_SPLIT),
        )
        for body, outcome, slots, ack in runs:
            with self.subTest(body=body.hex()):
                self.assertEqual(
                    cargo.frames(_request(body), outcome),
                    [(cargo.OPCODE, ack),
                     (refresh.OPCODE_SLOT, slots[0]),
                     (refresh.OPCODE_SLOT, slots[1]),
                     (refresh.OPCODE_BOARD, BOARD_AFTER_WRITE)])
        self.assertEqual(refresh.BOARD_AFTER_WRITE_BODY, BOARD_AFTER_WRITE)

    def test_a_same_container_move_draws_no_slot_pair(self):
        """2 -> 2 has no sample; the module keeps the plain path's measured
        rule -- no `(0,14)` pair when both ends share a list."""
        request = inventory.MoveRequest(src=inventory.Slot(2, 4, 0),
                                        dst=inventory.Slot(2, 9, 0), count=0)
        outcome = cargo.Outcome(True, "moved",
                                dst_after=_row(2, 9, 1001, count=4))
        self.assertEqual(cargo.frames(request, outcome),
                         [(cargo.OPCODE, request.ack(ok=True)),
                          (refresh.OPCODE_BOARD, BOARD_AFTER_WRITE)])


class SaveTest(unittest.TestCase):
    """The write path, against a copy of the real save and its triggers."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        self.account = accounts.sole_account(self.conn)
        _stack(self.conn, 0, 65, 1001, count=4)
        _stack(self.conn, 2, 5, 1047, count=2)
        _clear(self.conn, 2, 4)
        _clear(self.conn, 0, 83)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def test_a_whole_move_relocates_the_row_and_stamps_the_second(self):
        out = cargo.execute(self.conn, self.account, CHARACTER,
                            _request(MOVE_1001), now=NOW)
        self.assertEqual(out.action, "moved")
        self.assertEqual(out.dst_after.count, 4)
        self.assertIsNone(items.load(self.conn, CHARACTER, 0, 65))
        row = items.load(self.conn, CHARACTER, 2, 4)
        self.assertEqual((row.item_id, row.count, row.updated_at),
                         (1001, 4, NOW))

    def test_a_split_leaves_the_rest_and_creates_the_row(self):
        out = cargo.execute(self.conn, self.account, CHARACTER,
                            _request(MOVE_SPLIT), now=NOW)
        self.assertEqual(out.action, "split")
        self.assertEqual((out.src_after.count, out.dst_after.count), (1, 1))
        left = items.load(self.conn, CHARACTER, 2, 5)
        self.assertEqual((left.item_id, left.count, left.updated_at),
                         (1047, 1, NOW))
        made = items.load(self.conn, CHARACTER, 0, 83)
        self.assertEqual((made.item_id, made.count, made.updated_at),
                         (1047, 1, NOW))

    def test_the_account_warehouse_lives_in_its_own_table(self):
        cargo_rows.delete(self.conn, self.account, cargo.ACCOUNT_LIST, 3)
        out = cargo.execute(self.conn, self.account, CHARACTER,
                            inventory.MoveRequest(
                                src=inventory.Slot(0, 65, 0),
                                dst=inventory.Slot(cargo.ACCOUNT_LIST, 3, 0),
                                count=4), now=NOW)
        self.assertTrue(out.ok)
        self.assertIsNone(items.load(self.conn, CHARACTER, 0, 65))
        row = cargo_rows.load(self.conn, self.account, cargo.ACCOUNT_LIST, 3)
        self.assertEqual((row.item_id, row.count, row.updated_at),
                         (1001, 4, NOW))
        # A list 12 row's `character_id` column holds the account id.
        self.assertEqual(row.character_id, self.account)

    def test_a_move_out_of_the_account_warehouse_comes_back(self):
        cargo_rows.insert(self.conn, _row(cargo.ACCOUNT_LIST, 3, 590701706,
                                          character_id=self.account, count=44))
        out = cargo.execute(self.conn, self.account, CHARACTER,
                            inventory.MoveRequest(
                                src=inventory.Slot(cargo.ACCOUNT_LIST, 3, 0),
                                dst=inventory.Slot(0, 83, 0), count=0),
                            now=NOW)
        self.assertTrue(out.ok)
        self.assertIsNone(cargo_rows.load(self.conn, self.account,
                                          cargo.ACCOUNT_LIST, 3))
        row = items.load(self.conn, CHARACTER, 0, 83)
        self.assertEqual((row.item_id, row.count), (590701706, 44))

    def test_the_refusals_write_nothing(self):
        _clear(self.conn, 0, 81)
        empty = cargo.execute(self.conn, self.account, CHARACTER,
                              inventory.MoveRequest(
                                  src=inventory.Slot(0, 81, 0),
                                  dst=inventory.Slot(2, 4, 0), count=0),
                              now=NOW)
        self.assertEqual((empty.ok, empty.reason), (False, "nothing to move"))
        self.assertIsNone(items.load(self.conn, CHARACTER, 2, 4))
        filled = cargo.execute(self.conn, self.account, CHARACTER,
                               inventory.MoveRequest(
                                   src=inventory.Slot(2, 5, 0),
                                   dst=inventory.Slot(0, 65, 0), count=0),
                               now=NOW)
        self.assertEqual((filled.ok, filled.reason), (False,
                                                      "destination is filled"))
        self.assertEqual(items.load(self.conn, CHARACTER, 2, 5).count, 2)
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 65).count, 4)


class SocketTest(unittest.TestCase):
    """The wiring: a constructed split on a real socket, four frames back."""

    def setUp(self):
        self.save = _save_copy()
        conn = schema.connect(self.save)
        self.account = accounts.sole_account(conn)
        _stack(conn, 2, 5, 1047, count=2)
        _clear(conn, 0, 83)
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

    def test_the_split_draws_the_four_captured_frames_and_persists(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log, (1, 4, bytes(16)), (1, 19, MOVE_SPLIT))
        frames = self._decode(raw)[-4:]
        self.assertEqual([o.key() for o, _ in frames],
                         [(1, 19), (0, 14), (0, 14), (0, 1361)])
        self.assertEqual([b for _, b in frames],
                         [ACK_SPLIT, SLOT_2_5_1047_ONE, SLOT_0_83_1047_ONE,
                          BOARD_AFTER_WRITE])

        conn = schema.connect(self.save, readonly=True)
        try:
            self.assertEqual(items.load(conn, CHARACTER, 2, 5).count, 1)
            self.assertEqual(items.load(conn, CHARACTER, 0, 83).count, 1)
        finally:
            conn.close()
        text = log._fh.getvalue()
        self.assertIn("ITEM-MOVE-19 conn=1 src=(list=2,slot=5,iv=1047) "
                      "dst=(list=0,slot=83,iv=0) count=1 "
                      "plain=02050017040000010000000053000000000000000000"
                      "ffffffff000000000000", text)
        self.assertIn(f"CARGO-MOVE conn=1 account={self.account} character=1 "
                      f"2/5->0/83 count=1; committed", text)
        self.assertIn("conn=1 (1,19) -> 4 frame(s) 432B", text)
        self.assertNotIn("EQUIPMENT-SPECIFICITY", text)

    def test_an_empty_source_is_refused_with_a_warning_and_no_frames(self):
        log = Log(stream=io.StringIO())
        conn = schema.connect(self.save)
        _clear(conn, 2, 5)
        conn.commit()
        conn.close()

        raw = self._session(log, (1, 4, bytes(16)), (1, 19, MOVE_SPLIT))
        got = self._decode(raw)
        self.assertFalse([o for o, _ in got if o.key() in ((1, 19), (0, 14))])
        text = log._fh.getvalue()
        self.assertIn("refused: nothing to move; not stored", text)


if __name__ == "__main__":
    unittest.main()
