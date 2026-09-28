"""`(1,44)` ITEM-USE: the request, the three frames, the count decrement.

The two request/ack/slot-frame triples are the 09-27 probe login's own
(22:55:39 and 22:55:43, `_csprobe/c2s-1-44.hex`), embedded verbatim.  The
decrement's `updated_at` is pinned against the save: the rows behind the
09-25 and 09-26 uses carry the second their last use landed in.

The count-to-zero branch is unmeasured (no corpus use empties a stack), so
its test asserts the refusal rather than a guessed frame.
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
from uslocalserver.game.item import refresh, use
from uslocalserver.persistence import items, schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

CHARACTER = 1
#: The second the second capture's use landed in (22:55:43 +08:00).
NOW = 1_790_520_943

#: The reference's `plain=` bodies and its answers, verbatim.
USE_1047 = bytes.fromhex("42000072120000170400000000000000")   # slot 66, 3 -> 2
USE_1001 = bytes.fromhex("410000334c0000e90300000000000000")   # slot 65, 5 -> 4
ACK_1047 = bytes.fromhex("01420000721200001704000000000000")
ACK_1001 = bytes.fromhex("01410000334c0000e903000000000000")

Z = "00" * 155
#: The `(0,14)` frame each use drew: the slot after the use, count included.
SLOT_AFTER_1047 = bytes.fromhex("00010042001704000002000000" + Z)
SLOT_AFTER_1001 = bytes.fromhex("0001004100e903000004000000" + Z)
#: The `(0,1361)` that closes every write run in that session.
BOARD_AFTER_WRITE = bytes.fromhex("32" + "00" * 15)


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-item-use-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


def _row(list_type, slot_index, item_id, *, count=1, instance_value=0,
         updated_at=1) -> items.ItemStack:
    return items.ItemStack(
        character_id=CHARACTER, list_type=list_type, slot_index=slot_index,
        item_id=item_id, count=count, durability=0, instance_value=instance_value,
        random_options=b"", avatar_sockets=b"", clone_appearance_id=0, reinforcement=0,
        refinement=0, fusion_item="", bakal_state="", transferred_option_mask=0,
        enchant_card_id=0, enchant_upgrade=0, mist_imbued=0, updated_at=updated_at,
        expires_at=0, custom_option_ids=0, growth_experience=0, amplify_type=0,
        amplify_value=0)


def _stack(conn, list_type, slot_index, item_id, **kw):
    if items.load(conn, CHARACTER, list_type, slot_index) is not None:
        items.delete(conn, CHARACTER, list_type, slot_index)
    items.insert(conn, _row(list_type, slot_index, item_id, **kw))


class RequestTest(unittest.TestCase):
    def test_the_reference_bodies_parse_field_for_field(self):
        first = use.UseRequest.parse(USE_1047)
        self.assertEqual((first.slot_index, first.list_type, first.item_id,
                          first.instance_value), (66, 0, 1047, 4722))
        second = use.UseRequest.parse(USE_1001)
        self.assertEqual((second.slot_index, second.list_type, second.item_id,
                          second.instance_value), (65, 0, 1001, 19507))

    def test_tail_is_the_captured_constant(self):
        self.assertEqual(USE_1047[11:], use.TAIL)

    def test_short_body_is_rejected(self):
        with self.assertRaises(ValueError):
            use.UseRequest.parse(USE_1047[:15])

    def test_the_ack_is_the_captured_echo(self):
        for body, ack in ((USE_1047, ACK_1047), (USE_1001, ACK_1001)):
            with self.subTest(body=body.hex()):
                self.assertEqual(use.UseRequest.parse(body).ack(body), ack)

    def test_the_lines_read_like_the_reference_ones(self):
        request = use.UseRequest.parse(USE_1047)
        self.assertEqual(
            request.request_line(2, USE_1047),
            "conn=2 slot=66 list=0 item=1047 iv=4722 plain=42000072120000170400000000000000")
        self.assertEqual(request.outcome_line(2, 3, 2),
                         "conn=2 item 1047 at slot 66: 3 -> 2")


class FrameTest(unittest.TestCase):
    def test_the_slot_frame_reproduces_the_captured_168b(self):
        """`[9:13]` is the count here, not the zero `instance_value` -- the
        `instance_value or count` fallback, pinned by these two frames."""
        for body, want, item_id, count in ((USE_1047, SLOT_AFTER_1047, 1047, 2),
                                           (USE_1001, SLOT_AFTER_1001, 1001, 4)):
            with self.subTest(item=item_id):
                request = use.UseRequest.parse(body)
                after = _row(0, request.slot_index, item_id, count=count,
                             updated_at=NOW)
                self.assertEqual(refresh.slot_body(after, 0, request.slot_index),
                                 want)

    def test_the_frame_run_is_the_captured_one(self):
        request = use.UseRequest.parse(USE_1047)
        after = _row(0, 66, 1047, count=2, updated_at=NOW)
        self.assertEqual(use.frames(request, USE_1047, after),
                         [(use.OPCODE, ACK_1047),
                          (refresh.OPCODE_SLOT, SLOT_AFTER_1047),
                          (refresh.OPCODE_BOARD, BOARD_AFTER_WRITE)])
        self.assertEqual(refresh.BOARD_AFTER_WRITE_BODY, BOARD_AFTER_WRITE)


class SaveTest(unittest.TestCase):
    """The write path, against a copy of the real save and its triggers."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        _stack(self.conn, 0, 3, 2660671, count=500)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _request(self, item_id, *, slot=3, iv=7994):
        return use.UseRequest(slot_index=slot, list_type=0,
                              instance_value=iv, item_id=item_id)

    def revision(self):
        row = self.conn.execute(
            "select revision from gm_inventory_revisions where character_id = ? "
            "and list_type = 0 and slot_index = 3", (CHARACTER,)).fetchone()
        return row[0] if row else 0

    def test_a_use_takes_one_off_and_stamps_the_second(self):
        before = self.revision()
        out = use.execute(self.conn, CHARACTER, self._request(2660671), now=NOW)
        self.assertTrue(out.ok)
        self.assertEqual(out.before, 500)
        self.assertEqual(out.after.count, 499)
        row = items.load(self.conn, CHARACTER, 0, 3)
        self.assertEqual((row.count, row.updated_at), (499, NOW))
        # One update, so the trigger's revision counter moves once.
        self.assertEqual(self.revision() - before, 1)

    def test_the_instance_value_in_the_request_is_never_checked(self):
        out = use.execute(self.conn, CHARACTER, self._request(2660671, iv=12345),
                          now=NOW)
        self.assertTrue(out.ok)

    def test_another_item_in_the_slot_is_refused(self):
        before = items.load(self.conn, CHARACTER, 0, 3)
        out = use.execute(self.conn, CHARACTER, self._request(424242), now=NOW)
        self.assertEqual((out.ok, out.reason), (False, "missing"))
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 3), before)

    def test_using_the_last_unit_is_refused_not_guessed(self):
        _stack(self.conn, 0, 3, 2660671, count=1)
        self.conn.commit()
        before = items.load(self.conn, CHARACTER, 0, 3)
        out = use.execute(self.conn, CHARACTER, self._request(2660671), now=NOW)
        self.assertEqual((out.ok, out.reason), (False, "last-unit"))
        self.assertEqual(out.before, 1)
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 3), before)


class SocketTest(unittest.TestCase):
    """The wiring: a constructed `(1,44)` on a real socket, three frames back."""

    def setUp(self):
        self.save = _save_copy()
        conn = schema.connect(self.save)
        _stack(conn, 0, 66, 1047, count=3)
        _stack(conn, 0, 83, 1047, count=1)
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

    def test_the_use_draws_the_three_captured_frames_and_persists(self):
        log = Log(stream=io.StringIO())
        raw = self._session(log, (1, 4, bytes(16)), (1, 44, USE_1047))
        # the connection greeting, the (1,4) run, then our three -- the run is
        # the last three frames.
        frames = self._decode(raw)[-3:]
        self.assertEqual([o.key() for o, _ in frames],
                         [(1, 44), (0, 14), (0, 1361)])
        self.assertEqual(frames[0][1], ACK_1047)
        self.assertEqual(frames[1][1], SLOT_AFTER_1047)
        self.assertEqual(frames[2][1], BOARD_AFTER_WRITE)

        conn = schema.connect(self.save, readonly=True)
        try:
            self.assertEqual(items.load(conn, CHARACTER, 0, 66).count, 2)
        finally:
            conn.close()
        text = log._fh.getvalue()
        self.assertIn("ITEM-USE-44 conn=1 slot=66 list=0 item=1047 iv=4722 "
                      "plain=42000072120000170400000000000000", text)
        self.assertIn("ITEM-USE-44 conn=1 item 1047 at slot 66: 3 -> 2", text)
        self.assertIn("conn=1 (1,44) -> 3 frame(s) 248B", text)

    def test_the_last_unit_is_refused_with_a_warning_and_no_frames(self):
        log = Log(stream=io.StringIO())
        last_unit = bytes.fromhex("530000") + USE_1047[3:]
        raw = self._session(log, (1, 4, bytes(16)), (1, 44, last_unit))
        # only the greeting and the (1,4) run come back; the use answers nothing
        got = self._decode(raw)
        self.assertFalse([o for o, _ in got if o.key() in ((1, 44), (0, 14))])
        conn = schema.connect(self.save, readonly=True)
        try:
            self.assertEqual(items.load(conn, CHARACTER, 0, 83).count, 1)
        finally:
            conn.close()
        text = log._fh.getvalue()
        self.assertIn("refused: last-unit; not stored", text)


if __name__ == "__main__":
    unittest.main()
