"""`(1,35)` TOWN-MOVE / `(1,36)` TOWN-AREA: the bodies, the pair, the write.

Everything pinned here was measured off the reference on 2026-09-27 by driving
it with constructed frames (`tools/probe_town.py`, logs in
`dfo-server/Logs-townprobe/`).  The hard-coded hex strings are copied out of
the probe output and the reference's own log lines, not invented.
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.game.town import movement
from uslocalserver.persistence import schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game

CHARACTER = 1
NOW = 1_790_506_519            # the second the oracle's `area` run landed in

#: Probe bodies, verbatim (`move_body` / `area_body` frames the reference
#: accepted; the `signed` and `edge` ones are what pinned the signed parse).
MOVE_A = bytes.fromhex("5704de0006be0000")          # (1111, 222, dir 6, 190)
MOVE_H = bytes.fromhex("ffffffffffff0000")          # (65535, 65535, 255, 255)
AREA_E = bytes.fromhex("de0000000300000009037803040b00000016000000210000")
AREA_G = bytes(24)                                   # town/area 0 at (0,0)
AREA_I = bytes.fromhex("0100000001000000ffff409cc8") + bytes(11)

#: The reference's answers, from the probe's own S->C dump.
PAIR_E = ["0100de00000003000000090378030401",
          "de00000003000000010001000903780304010100"]
PAIR_G = ["01000000000000000000000000000001",
          "0000000000000000010001000000000000010100"]
PAIR_I = ["01000100000001000000ffff409cc801",
          "010000000100000001000100ffff409cc8010100"]
#: The town-entry push, same shape: conn=2's `(1,143)` burst carried the row
#: town=38 area=1 pos=(5555,666), and `town_state` 2 as the direction.
PAIR_ENTRY = ["01002600000001000000b3159a020201",
              "260000000100000001000100b3159a0202010100"]
#: The `(0,22)` that follows the entry pair, one per driven session.
SPAWN_BODIES = [("0100f401d60005640000000000000000", (168, 5, 500, 214, 5)),
                ("0100b3159a0202640000000000000000", (38, 1, 5555, 666, 2)),
                ("01000903780304640000000000000000", (222, 3, 777, 888, 4)),
                ("0100ffffffffff640000000000000000", (0, 0, -1, -1, 255)),
                ("01000080010000640000000000000000", (1, 1, -32768, 1, 0))]
#: The `(1,143)` request, verbatim from the probe log (algo 3, 16B body).
ENTRY_REQUEST = bytes.fromhex("00240000000100000000000000000000")


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-town-move-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


class ParseTest(unittest.TestCase):
    def test_move_body_parses_field_for_field(self):
        move = movement.Move.parse(MOVE_A)
        self.assertEqual((move.x, move.y), (1111, 222))
        self.assertEqual((move.direction, move.param), (6, 190))

    def test_move_coordinates_are_signed(self):
        """x=y=65535 is the oracle's `pos=(-1,-1) dir=255 param=255` line."""
        move = movement.Move.parse(MOVE_H)
        self.assertEqual((move.x, move.y), (-1, -1))
        self.assertEqual((move.direction, move.param), (255, 255))

    def test_move_short_body_is_rejected(self):
        with self.assertRaises(ValueError):
            movement.Move.parse(MOVE_A[:7])

    def test_area_body_parses_field_for_field(self):
        move = movement.AreaMove.parse(AREA_E)
        self.assertEqual((move.town, move.area), (222, 3))
        self.assertEqual((move.x, move.y), (777, 888))
        self.assertEqual(move.direction, 4)
        self.assertEqual(move.trailer.hex(), "0b00000016000000210000")
        self.assertEqual(len(move.trailer), 11)

    def test_area_coordinates_are_signed_too(self):
        """x=65535 y=40000 is the oracle's `pos=(-1,-25536)` line -- and the
        reply still carries the request's raw bits."""
        move = movement.AreaMove.parse(AREA_I)
        self.assertEqual((move.x, move.y), (-1, -25536))
        self.assertEqual(movement.area_pair(move.town, move.area, move.x, move.y,
                                            move.direction),
                         [(movement.AREA_ACK_OPCODE, bytes.fromhex(PAIR_I[0])),
                          (movement.AREA_ACK_2_OPCODE, bytes.fromhex(PAIR_I[1]))])

    def test_area_short_body_is_rejected(self):
        with self.assertRaises(ValueError):
            movement.AreaMove.parse(AREA_E[:23])


class PairTest(unittest.TestCase):
    def test_pairs_match_the_oracle(self):
        cases = [
            (movement.AreaMove.parse(AREA_E), PAIR_E),
            (movement.AreaMove.parse(AREA_G), PAIR_G),
            (movement.AreaMove.parse(AREA_I), PAIR_I),
            # and the entry push, which is the same builder on a row
            (None, PAIR_ENTRY),
        ]
        for move, expected in cases:
            with self.subTest(expected=expected[0]):
                if move is None:
                    got = movement.area_pair(38, 1, 5555, 666, 2)
                else:
                    got = movement.area_pair(move.town, move.area, move.x, move.y,
                                             move.direction)
                self.assertEqual([op for op, _ in got],
                                 [movement.AREA_ACK_OPCODE,
                                  movement.AREA_ACK_2_OPCODE])
                self.assertEqual([body.hex() for _, body in got], expected)
                self.assertEqual([len(body) for _, body in got], [16, 20])


class EntryTest(unittest.TestCase):
    """The three row-built frames of the `(1,143)` burst."""
    _row = type("S", (), {"town_id": 38, "area_id": 1, "position_x": 5555,
                          "position_y": 666, "town_state": 2, "slot_index": 0})

    def test_location_reads_the_row(self):
        loc = movement.Location.of(self._row)
        self.assertEqual((loc.town, loc.area, loc.x, loc.y, loc.direction),
                         (38, 1, 5555, 666, 2))
        self.assertEqual(loc.describe(), "town=38 area=1 pos=(5555,666)")

    def test_spawn_bodies_match_the_oracle(self):
        for want, values in SPAWN_BODIES:
            with self.subTest(values=values):
                self.assertEqual(movement.spawn_body(movement.Location(*values)).hex(),
                                 want)


class SessionTest(unittest.TestCase):
    def _session(self, **kw):
        return movement.TownSession(character_id=CHARACTER, town=38, area=1,
                                    key=1, **kw)

    def test_first_move_is_always_due(self):
        self.assertTrue(self._session().persist_due(100.0))

    def test_the_window_is_half_open_at_two_seconds(self):
        s = self._session(last_persist=100.0)
        self.assertFalse(s.persist_due(101.9))
        self.assertTrue(s.persist_due(102.0))

    def test_persisting_rearms_the_timer(self):
        s = self._session()
        s.persisted(100.0)
        self.assertFalse(s.persist_due(101.0))
        s.persisted(101.0)
        self.assertFalse(s.persist_due(102.5))
        self.assertTrue(s.persist_due(103.0))

    def test_of_reads_the_character_row(self):
        summary = type("S", (), {"character_id": 7, "town_id": 40, "area_id": 0,
                                 "slot_index": 1})()
        s = movement.TownSession.of(summary)
        self.assertEqual((s.character_id, s.town, s.area, s.key), (7, 40, 0, 2))
        self.assertIsNone(s.last_persist)


class SaveTest(unittest.TestCase):
    """The write path, against a copy of the real save."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def row(self):
        return tuple(self.conn.execute(
            "select town_id, area_id, position_x, position_y, town_state, "
            "updated_at from characters where character_id = ?",
            (CHARACTER,)).fetchone())

    def test_move_writes_position_facing_and_time_only(self):
        before = self.row()
        movement.write_move(self.conn, CHARACTER, movement.Move.parse(MOVE_A),
                            now=NOW)
        self.assertEqual(self.row(), (before[0], before[1], 1111, 222, 6, NOW))

    def test_move_stores_the_signed_value(self):
        movement.write_move(self.conn, CHARACTER, movement.Move.parse(MOVE_H),
                            now=NOW)
        after = self.row()
        self.assertEqual((after[2], after[3], after[4]), (-1, -1, 255))

    def test_area_writes_the_whole_location(self):
        movement.write_area(self.conn, CHARACTER,
                            movement.AreaMove.parse(AREA_E), now=NOW)
        self.assertEqual(self.row(), (222, 3, 777, 888, 4, NOW))

    def test_area_at_zero_is_written_as_sent(self):
        movement.write_area(self.conn, CHARACTER,
                            movement.AreaMove.parse(AREA_G), now=NOW)
        self.assertEqual(self.row(), (0, 0, 0, 0, 0, NOW))


class SocketTest(unittest.TestCase):
    """The wiring: the oracle's own `area` scenario, end to end.

    conn=2 of the probe: a move (persists), a second move 0.3s later
    (throttled), then `(1,36)` to (222,3) -- which answers and re-arms the
    timer -- and a move right after, throttled again.  All four land inside
    one connection and inside two seconds, so the timer, not the clock, is
    what the assertions read.

    The two INFO lines carry the *save's* town/area (the probe's conn=2 read
    `from=(38,1)` because the reference's save sat there that day), so the
    test reads the row first and expects what the row says.
    """

    def setUp(self):
        self.save = _save_copy()

    def tearDown(self):
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _c2s(self, main, sub, body, seq):
        return frame.build(frame.Link.GAME_C2S,
                           frame.Opcode(main, sub, frame.OpcodeEncoding.U8_U16LE, True),
                           tiles.encrypt_body(tiles.algo_id(sub), body),
                           seq=seq)

    def test_town_entry_spawns_where_the_row_stands(self):
        """The oracle's conn=2 entry: the row is put where conn=1's last write
        left it, and the burst's three row-built frames come back off it."""
        conn = schema.connect(self.save)
        conn.execute("update characters set town_id = 38, area_id = 1, "
                     "position_x = 5555, position_y = 666, town_state = 2 "
                     "where character_id = ?", (CHARACTER,))
        conn.commit()
        conn.close()

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
        # the burst opens with its own (1,143) echo; frames 20..22 are the ones
        # the reference builds from the row
        start = next(i for i, (o, _) in enumerate(frames)
                     if (o.main, o.sub) == (1, 143))
        burst = frames[start:start + 33]
        self.assertEqual(len(burst), 33)
        self.assertEqual(burst[20][1].hex(), PAIR_ENTRY[0])
        self.assertEqual(burst[21][1].hex(), PAIR_ENTRY[1])
        self.assertEqual(burst[22][1].hex(), SPAWN_BODIES[1][0])

        text = log._fh.getvalue()
        self.assertIn("TOWN-SPAWN conn=1 town=38 area=1 pos=(5555,666) key=1", text)

    def test_move_throttle_and_area_answer(self):
        import io

        from uslocalserver.server.logfile import Log

        conn = schema.connect(self.save, readonly=True)
        try:
            seeded = tuple(conn.execute(
                "select town_id, area_id from characters where character_id = ?",
                (CHARACTER,)).fetchone())
        finally:
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
                writer.write(self._c2s(1, 35, MOVE_A, 1))          # persists
                writer.write(self._c2s(1, 35, MOVE_H, 2))          # throttled
                writer.write(self._c2s(1, 36, AREA_E, 3))          # answered
                writer.write(self._c2s(1, 35, MOVE_H, 4))          # throttled
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
        pairs = []
        while (f := stream.next_frame()) is not None:
            if f.opcode.sub in (23, 24) and f.opcode.main == 0:
                pairs.append(tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body))
        self.assertEqual([b.hex() for b in pairs], PAIR_E)

        conn = schema.connect(self.save, readonly=True)
        try:
            row = conn.execute(
                "select town_id, area_id, position_x, position_y, town_state "
                "from characters where character_id = ?", (CHARACTER,)).fetchone()
        finally:
            conn.close()
        # the last write is the (1,36); neither later move got through
        self.assertEqual(tuple(row), (222, 3, 777, 888, 4))

        text = log._fh.getvalue()
        self.assertEqual(text.count("TOWN-MOVE-35"), 1)
        self.assertIn(f"town={seeded[0]} area={seeded[1]} "
                      "pos=(1111,222) dir=6 param=190 persisted", text)
        self.assertIn("TOWN-AREA-36 conn=", text)
        self.assertIn(f"key=1 from=({seeded[0]},{seeded[1]}) "
                      "to=(222,3) pos=(777,888) dir=4", text)
        self.assertIn("trailer=0b00000016000000210000 persisted; "
                      "answered with (0,23) + (0,24)", text)
        self.assertIn("(1,36) -> 2 frame(s) 68B state=", text)
        self.assertNotIn("(1,35) ->", text)


if __name__ == "__main__":
    unittest.main()
