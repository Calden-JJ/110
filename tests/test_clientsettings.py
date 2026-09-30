"""`(0,173)` CLIENT-SETTINGS: the row, the 504B push, the `(1,197)` save.

Pinned 2026-09-27 against the one captured push (09-26 22:16:34.470, conn=2)
and the reference's own 40 `S0/173` + 264 `saved C1/197` lines, and the save
re-pinned 2026-09-28 against the one dumped `(1,197)` (09-27 22:55:34.753,
conn=2) and its `(0,343)` reply.  No test crosses the captured body with the
live row -- the row is what the client edits, so the capture only pins the
*shape* (`u32le(492)` + blob + 8 zero bytes) and the socket test pins
body == f(row) for whatever the row holds.

`recommendedGuideShown` reads the blob's `[396:398]` signed -- the slot the
reference's own two line builders (`0x4458e0`, `0x3d21d0`) load with `movsx`.
The CLASS-AVATAR step reads a *different* slot, `[2:4]`, through `0x597b10`:
the `0x7fff` sentinel maps to 4, 0..4 pass through, the rest read 0.
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

from uslocalserver import paths
from uslocalserver.game.account import clientsettings
from uslocalserver.persistence import schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

ACCOUNT = 0


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-clientsettings-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


def _captured_selection_run():
    return game.GameScript.load().match(1, 4).run(0)


class BodyTest(unittest.TestCase):
    def test_push_body_is_the_row_between_prefix_and_trailer(self):
        options = bytes(range(256)) + bytes(492 - 256)
        body = clientsettings.push_body(options)
        self.assertEqual(len(body), 504)
        self.assertEqual(struct.unpack("<I", body[:4])[0], clientsettings.ROW_SIZE)
        self.assertEqual(body[4:496], options)
        self.assertEqual(body[496:], bytes(8))

    def test_opcodes_and_position(self):
        self.assertEqual(clientsettings.PUSH_OPCODE.key(), (0, 173))
        self.assertEqual(clientsettings.SAVE_OPCODE.key(), (1, 197))
        self.assertEqual(clientsettings.SELECTION_AT, 0)
        self.assertEqual(clientsettings.ROW_SIZE, 492)

    def test_parse_save_takes_the_row_out_of_the_496b_request(self):
        # The dumped request: `u32le(492)` + the row, and the reference logged
        # `saved C1/197 492B` for it.
        blob = bytes(range(256)) + bytes(clientsettings.ROW_SIZE - 256)
        self.assertEqual(clientsettings.parse_save(struct.pack("<I", 492) + blob),
                         blob)
        self.assertEqual(clientsettings.parse_save(blob), blob)
        for length in (0, 491, 504):
            self.assertIsNone(clientsettings.parse_save(bytes(length)))
        # A head that is not the row size is not this request.
        self.assertIsNone(clientsettings.parse_save(struct.pack("<I", 504) + blob))

    def test_the_save_reply_is_the_key_and_the_flags(self):
        # `0x597bb0`: `u16le(key)` + the flags byte, zero-padded to 8 -- the
        # 09-27 dump for character 2 (`02 00 02 ...`), and character 3 for
        # every 09-28 send (`03 00 02 ...`).
        self.assertEqual(clientsettings.SAVE_REPLY_OPCODE.key(), (0, 343))
        self.assertEqual(clientsettings.avatar_reply_body(2, 2),
                         bytes.fromhex("0200020000000000"))
        self.assertEqual(clientsettings.avatar_reply_body(3, 0x20),
                         bytes.fromhex("0300200000000000"))

    def test_recommended_guide_shown_reads_the_pinned_slot(self):
        options = bytearray(clientsettings.ROW_SIZE)
        self.assertEqual(clientsettings.GUIDE_SHOWN_AT, 396)
        struct.pack_into("<H", options, 396, 1)
        self.assertEqual(clientsettings.recommended_guide_shown(bytes(options)), 1)
        # The `movsx` read, visible above 0x7fff only: 0xffff is -1, not 65535.
        struct.pack_into("<H", options, 396, 0xFFFF)
        self.assertEqual(clientsettings.recommended_guide_shown(bytes(options)), -1)

    def test_preference_maps_the_sentinel_and_runs_off_size_to_zero(self):
        options = bytearray(clientsettings.ROW_SIZE)
        for raw, want in ((1, 1), (3, 3), (4, 4), (clientsettings.PREFERENCE_UNSET,
                          clientsettings.PREFERENCE_UNSET_VALUE), (5, 0), (0, 0)):
            struct.pack_into("<H", options, clientsettings.PREFERENCE_AT, raw)
            self.assertEqual(clientsettings.preference(bytes(options)), want)
        self.assertEqual(clientsettings.preference(bytes(491)), 0)

    def test_flags_look_up_the_clamped_preference(self):
        self.assertEqual(clientsettings.flags(1), 2)
        self.assertEqual(clientsettings.flags(2), 0x10)
        self.assertEqual(clientsettings.flags(0), 0)

    def test_the_lines_read_like_the_reference_ones(self):
        options = bytearray(clientsettings.ROW_SIZE)
        struct.pack_into("<H", options, clientsettings.GUIDE_SHOWN_AT, 1)
        self.assertEqual(clientsettings.push_line(bytes(options), 504),
                         "S0/173 504B recommendedGuideShown=1")
        self.assertEqual(clientsettings.save_line(bytes(options)),
                         "saved C1/197 492B recommendedGuideShown=1")
        struct.pack_into("<H", options, clientsettings.GUIDE_SHOWN_AT, 0)
        self.assertEqual(clientsettings.push_line(bytes(options), 504),
                         "S0/173 504B recommendedGuideShown=0")
        self.assertEqual(clientsettings.avatar_line(3, 1, 2),
                         "key=3 preference=1 flags=2; N343")

    def test_the_captured_push_has_the_shape(self):
        body = _captured_selection_run().replies[clientsettings.SELECTION_AT].plain
        self.assertEqual(len(body), 504)
        self.assertEqual(struct.unpack("<I", body[:4])[0], 492)
        self.assertEqual(body[496:], bytes(8))


class SaveTest(unittest.TestCase):
    """`load` / `save` against a copy of the real save."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def test_load_returns_the_only_row(self):
        options = clientsettings.load(self.conn, ACCOUNT)
        self.assertEqual(len(options), clientsettings.ROW_SIZE)

    def test_load_of_an_unknown_account_is_none(self):
        self.assertIsNone(clientsettings.load(self.conn, 999))

    def test_save_round_trips_without_adding_a_row(self):
        options = bytearray(clientsettings.load(self.conn, ACCOUNT))
        options[0] ^= 0xFF
        clientsettings.save(self.conn, ACCOUNT, bytes(options))
        self.assertEqual(clientsettings.load(self.conn, ACCOUNT), bytes(options))
        self.assertEqual(self.conn.execute(
            "select count(*) from account_client_settings").fetchone()[0], 1)


class SocketTest(unittest.TestCase):
    """The `(1,4)` slot and the `(1,197)` write, end to end."""

    def setUp(self):
        self.save = _save_copy()

    def tearDown(self):
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _c2s(self, main, sub, body, seq):
        return frame.build(frame.Link.GAME_C2S,
                           frame.Opcode(main, sub, frame.OpcodeEncoding.U8_U16LE, True),
                           tiles.encrypt_body(tiles.algo_id(sub), body),
                           seq=seq)

    def _session(self, log, *frames):
        """Send `frames` on one connection; return each burst of S2C frames.

        One burst per request: read until the 2s quiet period the server's
        write gap leaves behind.
        """
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 save_db=self.save, unix_seconds=1_789_824_022)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                bursts = []
                for seq, (main, sub, body) in enumerate(frames):
                    writer.write(self._c2s(main, sub, body, seq))
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
                    bursts.append(bytes(got))
                writer.close()
                return bursts
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

    def row_options(self) -> bytes:
        conn = schema.connect(self.save, readonly=True)
        try:
            return clientsettings.load(conn, ACCOUNT)
        finally:
            conn.close()

    def test_frame_zero_is_the_row_between_prefix_and_trailer(self):
        log = Log(stream=io.StringIO())
        [selection] = self._session(log, (1, 4, bytes(16)))
        # the connection greeting (0,1) comes first; the run is the last four
        frames = self._decode(selection)[-4:]
        self.assertEqual(frames[0][0].key(), (0, 173))
        self.assertEqual(len(frames[0][1]), 504)
        self.assertEqual(frames[0][1],
                         clientsettings.push_body(self.row_options()))
        self.assertNotEqual(frames[0][1][4:496], bytes(492))
        text = log._fh.getvalue()
        self.assertIn("CLIENT-SETTINGS conn=", text)
        shown = clientsettings.recommended_guide_shown(self.row_options())
        self.assertIn(f"S0/173 504B recommendedGuideShown={shown}", text)

    def test_the_save_writes_the_row_and_answers_the_343_ack(self):
        log = Log(stream=io.StringIO())
        changed = bytearray(self.row_options())
        changed[7] ^= 0xFF
        [_, after_save] = self._session(
            log, (1, 4, bytes(16)), (1, 197, self.wire_save(bytes(changed))))
        # The ack's key is the selected slot's own character key, and the flags
        # byte is the row's preference mapped through `flags()` -- both read
        # from the save, whose preference the 0.4.4 fixture holds as 3.
        shown = clientsettings.recommended_guide_shown(bytes(changed))
        flags = clientsettings.flags(clientsettings.preference(bytes(changed)))
        self.assertEqual(self._decode(after_save),
                         [(clientsettings.SAVE_REPLY_OPCODE,
                           clientsettings.avatar_reply_body(1, flags))])
        self.assertEqual(self.row_options(), bytes(changed))
        text = log._fh.getvalue()
        self.assertIn(f"saved C1/197 492B recommendedGuideShown={shown}", text)
        self.assertIn(f"CLASS-AVATAR conn=1 key=1 preference="
                      f"{clientsettings.preference(bytes(changed))} "
                      f"flags={flags}; N343", text)
        self.assertIn("conn=1 (1,197) -> 1 frame(s) 24B", text)

    def wire_save(self, options: bytes) -> bytes:
        """The `(1,197)` body the client actually sends: 496B, head included."""
        return struct.pack("<I", clientsettings.ROW_SIZE) + options

    def test_a_body_that_is_not_the_blob_is_refused(self):
        log = Log(stream=io.StringIO())
        before = self.row_options()
        not_the_blob = clientsettings.push_body(before)
        self._session(log, (1, 4, bytes(16)), (1, 197, not_the_blob))
        self.assertEqual(self.row_options(), before)
        text = log._fh.getvalue()
        self.assertIn("is not the 492B blob; not stored", text)
        self.assertNotIn("saved C1/197", text)


if __name__ == "__main__":
    unittest.main()
