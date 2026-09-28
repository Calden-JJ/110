"""`(0,376)` TOWN-QUICKSLOT: the row, the 1040B push, the burst slot.

Pinned 2026-09-27 against the reference's own dumps: five `(0,376)` frames
(09-26 22:16:37, 09-27 12:51/13:01/13:05/13:23) all equal the save's
`character_quickslots.payload` for the selected character plus 12 zero bytes.

The save-side assertions read the copy's row and check its *shape* rather
than its bytes -- the blob is edited by the client and re-saved, so nothing
here may pin a quickbar entry's value.
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
from uslocalserver.game.town import charsettings
from uslocalserver.persistence import schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

CHARACTER = 1
#: The `(1,143)` request, verbatim from the town probe log (see
#: `test_town_move`), and the zero body `(1,4)` selection uses.
ENTRY_REQUEST = bytes.fromhex("00240000000100000000000000000000")


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-charsettings-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


class BodyTest(unittest.TestCase):
    def test_push_body_is_the_row_plus_twelve_zero_bytes(self):
        payload = bytes(range(256)) * 4 + b"\xab" * 4
        body = charsettings.push_body(payload)
        self.assertEqual(len(body), 1040)
        self.assertEqual(body[:1028], payload)
        self.assertEqual(body[1028:], bytes(12))

    def test_opcodes_are_the_ones_the_corpus_dumped(self):
        self.assertEqual(charsettings.PUSH_OPCODE.key(), (0, 376))
        self.assertEqual(charsettings.SAVE_OPCODE.key(), (1, 439))
        self.assertEqual(charsettings.ENTRY_AT, 15)

    def test_default_payload_keeps_the_blob_shape(self):
        payload = charsettings.default_payload()
        self.assertEqual(len(payload), charsettings.PAYLOAD_SIZE)
        self.assertEqual(struct.unpack("<I", payload[:4])[0], 1024)
        self.assertEqual(payload[4:], b"\xff" * 1024)

    def test_awakening_links_reads_the_two_signed_fields(self):
        payload = bytearray(1028)
        struct.pack_into("<hh", payload, 212, 291, -1)
        self.assertEqual(charsettings.awakening_links(bytes(payload)), (291, -1))


class SaveTest(unittest.TestCase):
    """`load` against a copy of the real save."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def test_load_returns_the_row_and_it_self_describes(self):
        payload = charsettings.load(self.conn, CHARACTER)
        self.assertIsNotNone(payload)
        self.assertEqual(len(payload), charsettings.PAYLOAD_SIZE)
        # its first u32 counts the rest -- the reference's `head=` lines start
        # 00040000 for exactly this reason
        self.assertEqual(struct.unpack("<I", payload[:4])[0], len(payload) - 4)

    def test_load_of_an_unknown_character_is_none(self):
        self.assertIsNone(charsettings.load(self.conn, 999))


class SocketTest(unittest.TestCase):
    """The burst slot, end to end."""

    def setUp(self):
        self.save = _save_copy()

    def tearDown(self):
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _c2s(self, main, sub, body, seq):
        return frame.build(frame.Link.GAME_C2S,
                           frame.Opcode(main, sub, frame.OpcodeEncoding.U8_U16LE, True),
                           tiles.encrypt_body(tiles.algo_id(sub), body),
                           seq=seq)

    def _entry_burst(self, log):
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 save_db=self.save, unix_seconds=1_789_824_022)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(self._c2s(1, 4, bytes(16), 0))
                writer.write(self._c2s(1, 143, ENTRY_REQUEST, 1))
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
            frames.append((f.opcode,
                           tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)))
        start = next(i for i, (o, _) in enumerate(frames)
                     if (o.main, o.sub) == (1, 143))
        return frames[start:start + 33]

    def row_payload(self) -> bytes:
        conn = schema.connect(self.save, readonly=True)
        try:
            return conn.execute("select payload from character_quickslots "
                                "where character_id = ?", (CHARACTER,)).fetchone()[0]
        finally:
            conn.close()

    def test_frame_fifteen_is_the_row_plus_twelve_zeros(self):
        log = Log(stream=io.StringIO())
        burst = self._entry_burst(log)
        self.assertEqual(len(burst), 33)
        opcode, plain = burst[charsettings.ENTRY_AT]
        self.assertEqual(opcode.key(), (0, 376))
        self.assertEqual(len(plain), 1040)
        self.assertEqual(plain, charsettings.push_body(self.row_payload()))

    def test_a_missing_row_still_pushes_a_well_formed_blob(self):
        conn = schema.connect(self.save)
        conn.execute("delete from character_quickslots where character_id = ?",
                     (CHARACTER,))
        conn.commit()
        conn.close()

        log = Log(stream=io.StringIO())
        burst = self._entry_burst(log)
        opcode, plain = burst[charsettings.ENTRY_AT]
        self.assertEqual(opcode.key(), (0, 376))
        self.assertEqual(len(plain), 1040)
        self.assertEqual(plain[:1028], charsettings.default_payload())
        self.assertIn("no character_quickslots row; pushing defaults",
                      log._fh.getvalue())


if __name__ == "__main__":
    unittest.main()
