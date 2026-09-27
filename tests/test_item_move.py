"""`(1,19)` ITEM-MOVE: the handler, its acks, and what it writes.

Everything pinned here was measured off the reference on 2026-09-27 by driving
it with constructed frames (`tools/probe_m2_item_move.py`, corpora in
`dfo-server/Logs-m2oracle/`): the 29 moves it answered, the two ack forms it
sent, and the way its own `gm_inventory_revisions` counters moved.  The
hard-coded hex strings below are copied out of that corpus, not invented.

The database tests run against a *copy* of the real save -- the triggers that
record the write shapes only exist there -- so the row fixtures overwrite the
few slots they use.
"""
from __future__ import annotations

import asyncio
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.game.item import giant, inventory, refresh
from uslocalserver.persistence import items, schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game

CHARACTER = 1
NOW = 1_790_491_735            # the second the oracle run's last move landed in

#: `plain=` bodies out of the reference log, verbatim.
SAMPLE_MOVE_INTO_EMPTY = bytes.fromhex("00060000000000000000000009002FE7D32700000000FFFFFFFF000000000000")
SAMPLE_COUNT_1 = bytes.fromhex("00060000000000010000000003000000000000000000FFFFFFFF000000000000")
SAMPLE_EQUIP = bytes.fromhex("00060000000000000000000313000000000000000000FFFFFFFF000000000000")

#: The reference's answers to those three, and to the empty/empty move.
ACK_MOVE_INTO_EMPTY = bytes.fromhex("01000600000000000009000000000000")
ACK_COUNT_1 = bytes.fromhex("01000600010000000003000000000000")
ACK_EQUIP = bytes.fromhex("01000600000000000313000000000000")
ACK_EMPTY = bytes.fromhex("00040000000000000000000000000000")
ACK_EMPTY_CROSS = bytes.fromhex("00040000030000000000000000000000")
ACK_VIRTUAL_SAME = bytes.fromhex("00040000000000000000000000000000")
#: The sealed-slot reject, `dst=(3,35)`: the reference's 32B wire frame for it
#: (S->C hex `01130020000000e568da...` in the oracle) decrypts to this.
ACK_SEALED = bytes.fromhex("00130000030000000000000000000000")


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-item-move-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


def _stack(conn, character_id, list_type, slot_index, item_id, *, count=1,
           instance_value=0, updated_at=1):
    row = items.load(conn, character_id, list_type, slot_index)
    if row is not None:
        items.delete(conn, character_id, list_type, slot_index)
    items.insert(conn, items.ItemStack(
        character_id=character_id, list_type=list_type, slot_index=slot_index,
        item_id=item_id, count=count, durability=0, instance_value=instance_value,
        random_options=b"", avatar_sockets=b"", clone_appearance_id=0, reinforcement=0,
        refinement=0, fusion_item="", bakal_state="", transferred_option_mask=0,
        enchant_card_id=0, enchant_upgrade=0, mist_imbued=0, updated_at=updated_at,
        expires_at=0, custom_option_ids=0, growth_experience=0, amplify_type=0,
        amplify_value=0))


def _request(src, dst, count=0) -> inventory.MoveRequest:
    return inventory.MoveRequest(
        src=inventory.Slot(src[0], src[1], src[2]),
        dst=inventory.Slot(dst[0], dst[1], dst[2]), count=count)


class RequestTest(unittest.TestCase):
    def test_reference_bodies_parse_back_field_for_field(self):
        req = inventory.MoveRequest.parse(SAMPLE_MOVE_INTO_EMPTY)
        self.assertEqual(req.src.address, (0, 6))
        self.assertEqual(req.src.instance_value, 0)
        self.assertEqual(req.dst.address, (0, 9))
        self.assertEqual(req.dst.instance_value, 668198703)
        self.assertEqual(req.count, 0)
        self.assertEqual(inventory.MoveRequest.parse(SAMPLE_COUNT_1).count, 1)
        self.assertEqual(inventory.MoveRequest.parse(SAMPLE_EQUIP).dst.address, (3, 19))

    def test_tail_is_the_captured_constant(self):
        self.assertEqual(SAMPLE_MOVE_INTO_EMPTY[18:], inventory.TAIL)

    def test_short_body_is_rejected(self):
        with self.assertRaises(ValueError):
            inventory.MoveRequest.parse(SAMPLE_MOVE_INTO_EMPTY[:31])

    def test_success_ack_echoes_the_reference(self):
        for body, ack in ((SAMPLE_MOVE_INTO_EMPTY, ACK_MOVE_INTO_EMPTY),
                          (SAMPLE_COUNT_1, ACK_COUNT_1),
                          (SAMPLE_EQUIP, ACK_EQUIP)):
            with self.subTest(body=body.hex()):
                self.assertEqual(inventory.MoveRequest.parse(body).ack(ok=True), ack)

    def test_failure_ack_carries_the_two_lists(self):
        empty = _request((0, 7, 0), (0, 8, 0))
        self.assertEqual(empty.ack(ok=False), ACK_EMPTY)
        cross = _request((0, 7, 0), (3, 11, 0))
        self.assertEqual(cross.ack(ok=False), ACK_EMPTY_CROSS)
        self.assertEqual(_request((3, 11, 0), (0, 7, 0)).ack(ok=False),
                         bytes.fromhex("00040003000000000000000000000000"))
        virtual = _request((0, 1, 0), (0, 1, 0))
        self.assertEqual(virtual.ack(ok=False), ACK_VIRTUAL_SAME)

    def test_sealed_reject_ack_uses_code_0x13(self):
        sealed = _request((0, 7, 0), (3, 35, 0))
        self.assertEqual(sealed.ack(ok=False, code=inventory.REJECT_CODE_SEALED),
                         ACK_SEALED)
        # ... and the code is what plan() hands the handler.
        out = inventory.plan(sealed, None, None)
        self.assertEqual(sealed.ack(ok=False, code=out.code), ACK_SEALED)
        self.assertEqual(out.code, 0x13)


class PlanTest(unittest.TestCase):
    def test_branch_order_matches_the_oracle(self):
        filled = object()      # `plan` only tests for None
        cases = [
            # virtual slots are tested first: a virtual src == dst is rejected
            (_request((0, 1, 0), (0, 1, 0)), None, None, False, "rejected"),
            (_request((0, 9, 0), (0, 1, 0)), filled, None, False, "rejected"),
            # ... then same-slot: an *empty* src == dst still succeeds
            (_request((0, 7, 0), (0, 7, 0)), None, None, True, "noop"),
            (_request((0, 9, 668198703), (0, 9, 668198703), 5), filled, filled, True, "noop"),
            # ... then the sealed worn slots, on the dst side
            (_request((0, 7, 0), (3, 35, 0)), None, None, False, "rejected"),
            # both ends empty
            (_request((0, 7, 0), (0, 8, 0)), None, None, False, "rejected"),
            (_request((0, 7, 0), (3, 11, 0)), None, None, False, "rejected"),
            # the moving branches, same-container and cross alike
            (_request((0, 6, 0), (0, 9, 668198703)), None, filled, True, "moved"),
            (_request((0, 6, 668198703), (0, 9, 0)), filled, None, True, "moved"),
            (_request((0, 9, 668198703), (0, 10, 704166429)), filled, filled, True, "swapped"),
            (_request((0, 6, 0), (3, 19, 0)), None, filled, True, "moved"),
            (_request((0, 6, 668198703), (3, 19, 0)), filled, None, True, "moved"),
            (_request((0, 6, 668198703), (3, 19, 0)), filled, filled, True, "swapped"),
        ]
        for request, src, dst, ok, action in cases:
            with self.subTest(src=request.src.address, dst=request.dst.address):
                out = inventory.plan(request, src, dst)
                self.assertEqual((out.ok, out.action), (ok, action))

    def test_notes_are_the_reference_prose(self):
        out = inventory.plan(_request((0, 7, 0), (0, 8, 0)), None, None)
        self.assertEqual(out.note, inventory.NOTE_EMPTY)
        out = inventory.plan(_request((0, 6, 0), (0, 9, 0)), None, object())
        self.assertEqual(out.note, inventory.NOTE_MOVED_FROM_EMPTY)
        out = inventory.plan(_request((0, 9, 0), (0, 9, 0)), object(), object())
        self.assertEqual(out.note, inventory.NOTE_SAME_SLOT)

    def test_cross_notes_say_two_refresh_frames(self):
        """The oracle's own continuation for an accepted cross move:
        `...; answered with the (1,19) ack + 2 (0,14) refresh frame(s)`."""
        out = inventory.plan(_request((0, 6, 0), (3, 19, 0)), None, object())
        self.assertEqual(out.note, inventory.NOTE_CROSS_MOVED_FROM_EMPTY)
        self.assertTrue(out.note.endswith("ack + 2 (0,14) refresh frame(s)"))
        out = inventory.plan(_request((0, 6, 668198703), (3, 19, 0)), object(), None)
        self.assertEqual(out.note, inventory.NOTE_CROSS_MOVED)

    def test_sealed_note_is_the_talisman_line(self):
        out = inventory.plan(_request((0, 7, 0), (3, 35, 0)), None, None)
        self.assertEqual(out.note,
                         "rejected: disabled, invalid state, count or address; 0/7 -> 3/35")
        self.assertEqual(out.tag, inventory.TAG_TALISMAN)
        self.assertEqual(out.code, inventory.REJECT_CODE_SEALED)
        # every other branch keeps the ITEM-MOVE-19 tag and code 4
        other = inventory.plan(_request((0, 7, 0), (0, 8, 0)), None, None)
        self.assertEqual((other.tag, other.code),
                         (inventory.TAG_ITEM_MOVE, inventory.REJECT_CODE))


class SaveTest(unittest.TestCase):
    """The write path, against a copy of the real save and its triggers."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)
        for slot in (6, 7, 8, 9, 10):
            _stack(self.conn, CHARACTER, 0, slot, 0)   # delete whatever is there
        self.conn.execute("delete from character_items where character_id = ? "
                          "and list_type = 0 and slot_index in (6, 7, 8, 9, 10)",
                          (CHARACTER,))
        self.conn.execute("delete from gm_inventory_revisions where character_id = ? "
                          "and list_type = 0 and slot_index in (6, 7, 8, 9, 10)",
                          (CHARACTER,))
        _stack(self.conn, CHARACTER, 0, 9, 101011203, instance_value=668198703)
        _stack(self.conn, CHARACTER, 0, 10, 101011025, instance_value=704166429)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def revisions(self):
        """Only addresses that an item has touched carry a counter -- an empty
        slot has no row in either table, so `before` looks up with `.get`."""
        return {(r[1], r[2]): r[3] for r in self.conn.execute(
            "select character_id, list_type, slot_index, revision "
            "from gm_inventory_revisions where character_id = ?", (CHARACTER,))}

    def test_move_into_empty_slot_relocates_the_row(self):
        before = self.revisions()
        out = inventory.execute(self.conn, CHARACTER, _request((0, 6, 0), (0, 9, 668198703)),
                                now=NOW)
        self.assertEqual((out.ok, out.action), (True, "moved"))
        self.assertIsNone(items.load(self.conn, CHARACTER, 0, 9))
        moved = items.load(self.conn, CHARACTER, 0, 6)
        self.assertEqual(moved.item_id, 101011203)
        self.assertEqual(moved.instance_value, 668198703)
        self.assertEqual(moved.updated_at, NOW)
        after = self.revisions()
        self.assertEqual(after[(0, 6)] - before.get((0, 6), 0), 1)
        self.assertEqual(after[(0, 9)] - before.get((0, 9), 0), 1)

    def test_move_out_of_a_filled_source(self):
        inventory.execute(self.conn, CHARACTER, _request((0, 9, 668198703), (0, 6, 0)),
                          now=NOW)
        self.assertIsNone(items.load(self.conn, CHARACTER, 0, 9))
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 6).item_id, 101011203)

    def test_cross_move_relocates_between_lists(self):
        """The oracle's unequip: `src=(0,6) dst=(3,19)` with slot 19 worn takes
        the worn row out of list 3 and into list 0, revision counters and all."""
        _stack(self.conn, CHARACTER, 3, 19, 112541253, instance_value=555)
        self.conn.commit()
        before = self.revisions()
        out = inventory.execute(self.conn, CHARACTER, _request((0, 6, 0), (3, 19, 0)),
                                now=NOW)
        self.assertEqual((out.ok, out.action), (True, "moved"))
        self.assertIsNone(items.load(self.conn, CHARACTER, 3, 19))
        moved = items.load(self.conn, CHARACTER, 0, 6)
        self.assertEqual((moved.item_id, moved.instance_value), (112541253, 555))
        self.assertEqual(moved.updated_at, NOW)
        after = self.revisions()
        self.assertEqual(after[(3, 19)] - before.get((3, 19), 0), 1)
        self.assertEqual(after[(0, 6)] - before.get((0, 6), 0), 1)

    def test_the_instance_value_is_never_checked(self):
        inventory.execute(self.conn, CHARACTER, _request((0, 9, 12345), (0, 6, 0)), now=NOW)
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 6).item_id, 101011203)

    def test_swap_crosses_the_two_rows(self):
        before = self.revisions()
        out = inventory.execute(self.conn, CHARACTER,
                                _request((0, 9, 668198703), (0, 10, 704166429)), now=NOW)
        self.assertEqual(out.action, "swapped")
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 9).item_id, 101011025)
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 10).item_id, 101011203)
        after = self.revisions()
        # two per address: the reference deletes and inserts rather than
        # updating in place, which is what its revision counters show.
        self.assertEqual(after[(0, 9)] - before.get((0, 9), 0), 2)
        self.assertEqual(after[(0, 10)] - before.get((0, 10), 0), 2)

    def test_rejections_write_nothing(self):
        before = self.revisions()
        cases = [(_request((0, 7, 0), (0, 8, 0)), "rejected"),      # both empty
                 (_request((0, 7, 0), (0, 7, 0)), "noop"),          # same empty slot
                 (_request((0, 9, 0), (0, 1, 0)), "rejected"),      # virtual slot
                 (_request((0, 7, 0), (3, 35, 0)), "rejected")]     # sealed worn slot
        for request, action in cases:
            with self.subTest(action=action, dst=request.dst.address):
                self.assertEqual(inventory.execute(self.conn, CHARACTER, request,
                                                   now=NOW).action, action)
        self.assertEqual(self.revisions(), before)
        self.assertEqual(items.load(self.conn, CHARACTER, 0, 9).item_id, 101011203)
        self.assertEqual(items.load(self.conn, CHARACTER, 3, 19).item_id
                         if items.load(self.conn, CHARACTER, 3, 19) else None,
                         self.conn.execute("select item_id from character_items where "
                                           "character_id=? and list_type=3 and slot_index=19",
                                           (CHARACTER,)).fetchone()[0])
        self.assertIsNone(items.load(self.conn, CHARACTER, 0, 6))


class SocketTest(unittest.TestCase):
    """The wiring: a constructed `(1,19)` on a real socket, ack and all."""

    def setUp(self):
        self.save = _save_copy()
        conn = schema.connect(self.save)
        for slot in (6, 7, 8, 9, 10):
            conn.execute("delete from character_items where character_id = ? and "
                         "list_type = 0 and slot_index = ?", (CHARACTER, slot))
        _stack(conn, CHARACTER, 0, 9, 101011203, instance_value=668198703)
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _c2s(self, main, sub, body, seq):
        return frame.build(frame.Link.GAME_C2S,
                           frame.Opcode(main, sub, frame.OpcodeEncoding.U8_U16LE, True),
                           tiles.encrypt_body(tiles.algo_id(sub), body),
                           seq=seq)

    def test_a_constructed_move_is_answered_and_persisted(self):
        import io

        from uslocalserver.server.logfile import Log

        log = Log(stream=io.StringIO())
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 save_db=self.save, unix_seconds=1_789_824_022)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(self._c2s(1, 4, bytes(16), 0))
                writer.write(self._c2s(1, 19, SAMPLE_MOVE_INTO_EMPTY, 1))
                await writer.drain()
                got = bytearray()
                while True:
                    try:
                        chunk = await asyncio.wait_for(reader.read(65536), timeout=2.0)
                    except asyncio.TimeoutError:
                        break
                    if not chunk:
                        break
                    got += chunk
                writer.close()
                return bytes(got)
            finally:
                server.close()

        stream = frame.FrameStream(frame.Link.GAME_S2C)
        stream.feed(asyncio.run(run()))
        acks = []
        while (f := stream.next_frame()) is not None:
            if (f.opcode.main, f.opcode.sub) == (1, 19):
                acks.append(tiles.decrypt_body(tiles.algo_id(19), f.body))
        self.assertEqual(acks, [ACK_MOVE_INTO_EMPTY])

        conn = schema.connect(self.save, readonly=True)
        try:
            self.assertIsNone(items.load(conn, CHARACTER, 0, 9))
            self.assertEqual(items.load(conn, CHARACTER, 0, 6).item_id, 101011203)
        finally:
            conn.close()

        text = log._fh.getvalue()
        self.assertIn("ITEM-MOVE-19", text)
        self.assertIn("source was empty, moved the destination into it", text)

    def test_a_cross_move_draws_the_eight_frame_refresh(self):
        """The oracle's conn=2 unequip, end to end: `SAMPLE_EQUIP` is its own
        `plain=` line.  Every byte below is pinned to the corpus where it can
        be; the giant's tail sits past the log's 4096B dump cut, so the
        landmark it is pinned by -- the rune array and the creature level --
        is checked against the save the way `giant.py` reads them."""
        import io

        from uslocalserver.server.logfile import Log

        conn = schema.connect(self.save)
        _stack(conn, CHARACTER, 3, 19, 112541253, instance_value=555)
        conn.commit()
        # The move below unequips slot 19, so every count-dependent expectation
        # derives from the save's own worn set: the copy comes from the live
        # save, whose worn set grows and shrinks with real gameplay (a session
        # that equipped a piece on 2026-09-27 turned a pinned 31 into a red test).
        worn_after = len(refresh.equipment(conn, CHARACTER)) - 1
        self.assertGreater(worn_after, 0, "the save copy's worn set is empty")
        small_len = (refresh.USERINFO_HEADER_SIZE + refresh.RECORD_SIZE * worn_after
                     + len(refresh.TAIL))
        small_len += -small_len % 16
        conn.close()

        log = Log(stream=io.StringIO())
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 save_db=self.save, unix_seconds=1_789_824_022)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(self._c2s(1, 4, bytes(16), 0))
                writer.write(self._c2s(1, 19, SAMPLE_EQUIP, 1))
                await writer.drain()
                got = bytearray()
                while True:
                    try:
                        chunk = await asyncio.wait_for(reader.read(65536), timeout=2.0)
                    except asyncio.TimeoutError:
                        break
                    if not chunk:
                        break
                    got += chunk
                writer.close()
                return bytes(got)
            finally:
                server.close()

        stream = frame.FrameStream(frame.Link.GAME_S2C)
        stream.feed(asyncio.run(run()))
        frames = []
        while (f := stream.next_frame()) is not None:
            if (f.opcode.main, f.opcode.sub) == (1, 19) or frames:
                # skip CHANNELINFO and the (1,4) selection's scripted reply
                frames.append((f.opcode,
                               tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)))
        self.assertEqual([(o.main, o.sub) for o, _ in frames],
                         [(1, 19), (0, 14), (0, 14), (0, 2), (0, 2), (0, 2265),
                          (0, 2432), (0, 1361)])
        sizes = [len(b) for _, b in frames]
        # The giant's size is per-item and is checked by its own tail below;
        # the rest are fixed or, for the small USERINFO, its layout formula.
        self.assertEqual(sizes[:3] + sizes[5:], [16, 168, 168, 16, 208, 96])
        self.assertEqual(sizes[3], small_len)
        self.assertEqual(frames[0][1], ACK_EQUIP)

        # the two slot frames carry the state *after* the move
        src, dst = frames[1][1], frames[2][1]
        self.assertEqual((src[0], src[1]), (0, 0x01))
        self.assertEqual(struct.unpack_from(">H", src, 2)[0], 6)
        self.assertEqual(struct.unpack_from("<I", src, 5)[0], 112541253)
        self.assertEqual(struct.unpack_from("<I", src, 9)[0], 555)
        self.assertEqual((dst[0], struct.unpack_from(">H", dst, 2)[0]), (3, 19))
        self.assertEqual(struct.unpack_from("<I", dst, 5)[0], 0xFFFFFFFF)

        # the small USERINFO: one fewer worn now, version is the (0,2265) one
        userinfo = frames[3][1]
        self.assertEqual(userinfo[refresh.COUNT_AT], worn_after)
        self.assertEqual(userinfo[refresh.NAME_AT:refresh.NAME_AT + 8], b"XRenYing")
        version = struct.unpack_from("<H", userinfo, refresh.VERSION_AT)[0]
        self.assertEqual(version, struct.unpack_from("<H", frames[5][1], 4)[0])
        self.assertEqual(frames[5][1][:4], bytes.fromhex("01000000"))
        self.assertEqual((frames[6][1], frames[7][1]),
                         (refresh.STATE_BODY, refresh.BOARD_BODY))

        # the giant: same worn count and version, and its tail from the save
        big = frames[4][1]
        self.assertEqual(big[:8], bytes.fromhex("010100010a000000"))
        self.assertEqual(big[giant.CHAR_AT + giant.CHAR_SIZE - 1], worn_after)
        self.assertEqual(struct.unpack_from("<H", big, giant.VERSION_AT)[0], version)

        conn = schema.connect(self.save, readonly=True)
        try:
            self.assertIsNone(items.load(conn, CHARACTER, 3, 19))
            self.assertEqual(items.load(conn, CHARACTER, 0, 6).item_id, 112541253)
            worn = refresh.equipment(conn, CHARACTER)
            levels = giant.creature_levels(conn, CHARACTER)
            runes = giant.runes(conn, CHARACTER)
            self.assertEqual(len(worn), worn_after)
        finally:
            conn.close()
        end = giant.ITEMS_AT + sum(len(giant.item_block(s, frozenset(levels)))
                                   for s in worn)
        self.assertEqual(big[end:end + 5], bytes(4) + b"\x09")
        self.assertEqual(
            big[end + 5:end + 41],
            b"".join(struct.pack("<I", runes.get(slot, 0xFFFFFFFF))
                     for slot in giant.RUNE_SLOTS))
        self.assertEqual(big[end + 60:end + 65], b"\xff\x00\x00\x01\x00")
        self.assertEqual(big[end + 65:], bytes(len(big) - end - 65))

        text = log._fh.getvalue()
        self.assertIn("ack + 2 (0,14) refresh frame(s)", text)
        self.assertIn(f"re-sent both USERINFO frames with {worn_after} worn item(s)", text)
        self.assertIn("EQUIPMENT-SPECIFICITY conn=", text)
        self.assertNotIn("TALISMAN", text)


if __name__ == "__main__":
    unittest.main()
