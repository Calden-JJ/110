"""M3.1's door chain: the `(1,16)` request, the run's lifecycle, the writes.

The six `(1,16)` bodies are the 09-28 capture's own, decrypted off its
`request_wire_hex`; the `(0,28)`/`(0,29)` plaintexts are its `plain_hex`
verbatim.  The lifecycle rules come from the three `SETTLEMENT-42` lines --
settled True after the tutorial's clear, False for both abandoned dungeon-6
runs -- and the no-op `(1,35)` skip from the run the reference left
unwritten at offset 239.765 against the one it wrote at 312.814.

A `(0,29)` carries the run's four seed bytes, so the byte-exact cases below
hand `room_body` the reference's own seed, read out of the captured frame.
"""
from __future__ import annotations

import asyncio
import io
import shutil
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.game.dungeon import blocks, entry, settle
from uslocalserver.game.dungeon import maze as maze_data
from uslocalserver.game.dungeon.run import DungeonRun, DungeonSession
from uslocalserver.game.town import movement
from uslocalserver.persistence import characters, schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

CHARACTER = 3

#: The `(1,4)` and `(1,143)` bodies the socket tests drive, verbatim from the
#: town probe (see `test_town_move`).
SELECT_BODY = bytes(16)
ENTRY_REQUEST = bytes.fromhex("00240000000100000000000000000000")


def _save_copy(prefix: str) -> Path:
    dst = Path(tempfile.mkdtemp(prefix=prefix)) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst

#: The six `(1,16)` plaintext bodies, in capture order: `(dungeon, quest)`.
ENTER_BODIES = [
    ("cb1b00000000000000ffff000000000000000000000000000000000000000000", 7115, 0),
    ("030000000000000000ffff0000000000490c0000000000000000000000000000", 3, 3145),
    ("050000000000000000ffff00000000004a0c0000000000000000000000000000", 5, 3146),
    ("050000000000000000ffff000000000000000000000000000000000000000000", 5, 0),
    ("060000000000000000ffff00000000004b0c0000000000000000000000000000", 6, 3147),
]

#: The tutorial run's pair (`(1,16)` line 508, session's first so base 1) and
#: a normal one's (`(1,16)` line 1042, base 17 -- the tutorial's maze_total).
MAP_TUTORIAL = ("cb1b0000000000000300ffff000000000c0000ffffffff"
                + "00" * 25)
SPAWN_TUTORIAL = (
    "000000d5fb486100000100000000000000ffffffffffffffff0000000000000187cf"
    "0000030000000000000100f9f50000010000000000000000000100010000000200f9"
    "f50000010000000000000000000200020000000300f9f50000010000000000000000"
    "00000000ff0000000000")
MAP_THREE = ("03000000000000010300ffff000000000c0000ffffffff"
             + "00" * 25)
SPAWN_THREE = (
    "0001007edee36400000100000000000000ffffffffffffffff000000000000015929"
    "01000400000000000011004a6f7f060300000000000000000001000100000012004a"
    "6f7f060300000000000000000002000200000013004a6f7f06030000000000000000"
    "0003000300000014004a6f7f0603000000000000000000000000ff00000000000000")
#: The dungeon-6 run whose start room is empty: 43 bytes of frame, padded to
#: 48, and the `(0,29)` is the whole answer.
MAP_SIX = ("06000000000000010400ffff000000000c0000ffffffff"
           + "00" * 25)
SPAWN_SIX = ("0000000cff160a00000100000000000000ffffffffffffffff00000000000001"
             "6d29010000000000ff00000000000000")

#: `map=` and `monsters=` from the same runs' `DUNGEON-ENTRY` lines.
START_ROOMS = [(53127, 3), (76121, 4), (76131, 1), (76141, 0)]


def _run(dungeon: int, maze: int, cell: tuple[int, int], map_id: int,
         seed: str, base: int) -> DungeonRun:
    return DungeonRun(dungeon=dungeon, maze=maze, cell=cell, map_id=map_id,
                      seed=bytes.fromhex(seed), base=base)


class EntryRequestTest(unittest.TestCase):
    def test_the_captured_bodies_parse(self):
        for body, dungeon, quest in ENTER_BODIES:
            with self.subTest(dungeon=dungeon, quest=quest):
                request = entry.Request.parse(bytes.fromhex(body))
                self.assertEqual((request.dungeon, request.quest),
                                 (dungeon, quest))
                self.assertEqual((request.difficulty, request.entry_option),
                                 (0, 0))

    def test_short_body_is_rejected(self):
        with self.assertRaises(ValueError):
            entry.Request.parse(bytes.fromhex(ENTER_BODIES[0][0])[:31])

    def test_describe_matches_the_reference_line(self):
        request = entry.Request.parse(bytes.fromhex(ENTER_BODIES[1][0]))
        self.assertEqual(
            request.describe(),
            "SelectDungeonRequest { DungeonId = 3, Difficulty = 0, "
            "EntryOption = 0, Mode = 0, HellDifficulty = 0 }")


class StartRoomTest(unittest.TestCase):
    """`monsters=` is the start map's table rows, and so is the frame."""

    def test_captured_monster_counts(self):
        for map_id, count in START_ROOMS:
            with self.subTest(map=map_id):
                self.assertEqual(
                    entry.monster_count(_run(0, 0, (0, 0), map_id, "00" * 4, 1)),
                    count)

    def test_tutorial_pair_is_the_captured_bytes(self):
        run = _run(7115, 0, (0, 0), 53127, "d5fb4861", 1)
        self.assertEqual(entry.map_body(run).hex(), MAP_TUTORIAL)
        self.assertEqual(entry.room_body(run, revisit=False).hex(), SPAWN_TUTORIAL)
        self.assertEqual(len(entry.room_body(run, revisit=False)), 112)

    def test_populated_room_reproduces_four_records(self):
        """Dungeon 3 maze 1, base 17: ids 17..20, basis 3, the last record's
        final two bytes dropped and the frame padded to 136."""
        run = _run(3, 1, (0, 1), 76121, "7edee364", 17)
        self.assertEqual(entry.map_body(run).hex(), MAP_THREE)
        self.assertEqual(entry.room_body(run, revisit=False).hex(), SPAWN_THREE)

    def test_empty_room_keeps_the_ff_marker(self):
        run = _run(6, 1, (0, 0), 76141, "0cff160a", 0)
        self.assertEqual(entry.map_body(run).hex(), MAP_SIX)
        self.assertEqual(entry.room_body(run, revisit=False).hex(), SPAWN_SIX)


class MazeChoiceTest(unittest.TestCase):
    """Which maze a `(1,16)` enters: the request's own quest when it names
    one, the native retry, then the dungeon's own first maze.

    Both tables are the reference's own `DUNGEON-ENTRY` lines.  The fallback
    dungeons are the ones whose maze 0 carries no `questConnection` -- so
    neither a quest match nor the retry, which both return a
    connection-carrying row, can produce their `maze=0`; the fallback is the
    only producer left.  All 200 entry lines the five corpus logs hold match
    their maze's own `startMap`/`mapId`/`bossMap`, cell for cell.
    """

    QUEST_MAZES = [
        (3, 3145, 1, (0, 1), 76121),
        (5, 3146, 0, (0, 0), 76131),
        (6, 3147, 1, (0, 0), 76141),
        (14, 3178, 1, (1, 2), 57935),
        (14, 3179, 2, (3, 2), 57944),
    ]

    FALLBACK_MAZES = [
        (410, (0, 0), 44600),
        (1000, (4, 1), 58590),
        (5000, (0, 0), 36250),
        (7150, (0, 0), 311121),
        (7322, (0, 0), 311393),
        (8523, (0, 1), 550040),
        (100000002, (1, 0), 100000030),
        (100000151, (0, 0), 100000221),
        (100002627, (0, 3), 100003695),
        (100003043, (0, 1), 100007059),
        (291100268, (0, 0), 292103105),
    ]

    def test_a_quest_names_the_maze_that_carries_it(self):
        for dungeon, quest, index, cell, map_id in self.QUEST_MAZES:
            with self.subTest(dungeon=dungeon, quest=quest):
                self.assertEqual(entry.maze_for(dungeon, quest), index)
                self.assertEqual(
                    maze_data.start(maze_data.mazes(dungeon)[index]),
                    (cell, map_id))

    def test_a_bare_pick_names_no_maze(self):
        """Quest 0, which is what a gate click with no quest behind it sends;
        no maze in table 045 carries a connection on it."""
        for dungeon in (3, 5, 6, 7115):
            with self.subTest(dungeon=dungeon):
                self.assertIsNone(entry.maze_for(dungeon, 0))

    def test_a_bare_pick_gets_the_dungeons_first_maze(self):
        for dungeon, cell, map_id in self.FALLBACK_MAZES:
            with self.subTest(dungeon=dungeon):
                index = entry.default_maze(dungeon)
                self.assertEqual(index, 0)
                self.assertEqual(
                    maze_data.start(maze_data.mazes(dungeon)[index]),
                    (cell, map_id))

    def test_the_fallback_rows_carry_no_connection(self):
        """Why `maze=0` in those lines can only be the fallback."""
        for dungeon, _, _ in self.FALLBACK_MAZES:
            with self.subTest(dungeon=dungeon):
                self.assertIsNone(
                    maze_data.mazes(dungeon)[0].get("questConnection"))

    def test_the_09_29_pick_of_dungeon_3(self):
        """The failing session: dungeon 3 asked with quest 0, which the
        reference answers from dungeon 3's own maze 0 -- and which was
        ignored, with no frames, before the fallback existed."""
        self.assertIsNone(entry.maze_for(3, 0))
        self.assertEqual(entry.default_maze(3), 0)
        self.assertEqual(maze_data.start(maze_data.mazes(3)[0]),
                         ((0, 1), 58548))
        self.assertEqual(maze_data.boss(maze_data.mazes(3)[0]), (3, 0))

    def test_a_dungeon_the_table_lacks_gets_no_maze(self):
        for dungeon in (0, 999999):
            with self.subTest(dungeon=dungeon):
                self.assertIsNone(entry.default_maze(dungeon))


class RunLifecycleTest(unittest.TestCase):
    def _session(self) -> DungeonSession:
        return DungeonSession(character_id=CHARACTER, key=3, town=None)

    def test_a_fresh_session_has_no_run(self):
        self.assertFalse(self._session().in_progress)

    def test_clear_retires_the_run_in_place(self):
        """`(1,15)` draws again and `(1,16)` enters again after a `(1,46)`,
        while `(1,42)` still names the run it left behind."""
        session = self._session()
        run = session.begin(7115, 0)
        self.assertTrue(session.in_progress)
        session.settled = True                              # (1,46)
        self.assertFalse(session.in_progress)
        self.assertIs(session.run, run)
        self.assertIs(session.leave(), run)                 # (1,42)

    def test_begin_resets_settled(self):
        session = self._session()
        session.begin(7115, 0)
        session.settled = True
        session.begin(6, 1)
        self.assertFalse(session.settled)
        self.assertTrue(session.in_progress)

    def test_leave_clears_the_flags(self):
        session = self._session()
        session.begin(7115, 0)
        session.selected = True
        session.settled = True
        session.leave()
        self.assertIsNone(session.run)
        self.assertFalse(session.selected)
        self.assertFalse(session.settled)

    def test_the_counter_advances_by_the_maze_total(self):
        """The capture's entries start at 1, 17, 44 and 71: the tutorial's
        maze holds 16 table monsters, so the next run takes 17."""
        session = self._session()
        self.assertEqual(session.begin(7115, 0).base, 1)
        self.assertEqual(session.next_id, 17)
        self.assertEqual(session.begin(3, 1).base, 17)
        self.assertEqual(session.next_id, 44)


class MoveChangeTest(unittest.TestCase):
    """`(1,35)` skips writes that would not change the row -- and skipped
    writes do not arm the timer either."""

    _row = type("R", (), {"position_x": 191, "position_y": 249,
                          "town_state": 5})

    def test_identical_move_is_no_change(self):
        self.assertFalse(movement.changed(self._row,
                                          movement.Move(191, 249, 5, 100)))

    def test_direction_only_change_counts(self):
        self.assertTrue(movement.changed(self._row,
                                         movement.Move(191, 249, 4, 100)))

    def test_position_change_counts(self):
        self.assertTrue(movement.changed(self._row,
                                         movement.Move(192, 249, 5, 100)))


class ProseTest(unittest.TestCase):
    """The M3.1 lines, after the bare `conn=N `."""

    def test_tutorial_lines(self):
        self.assertEqual(
            entry.tutorial_line(3, 7115),
            "tutorial auto-entry: key=3 dungeon=7115 (pending=7115, "
            "client-authoritative, synthetic worldmap)")
        self.assertEqual(entry.pre_frames_line(),
                         "tutorial loading pre-frames: (0,3) 4B + "
                         "(0,27) 35B head=01")
        self.assertEqual(entry.committed_line(True),
                         "tutorial entry committed; pending cleared=True")

    def test_settlement_note(self):
        run = _run(7115, 0, (0, 0), 53127, "00" * 4, 1)
        self.assertEqual(
            settle.note(run, True, 3, movement.Location(38, 1, 561, 234, 5)),
            "leaving dungeon=7115 settled=True; key=3 back to town=(38,1) "
            "pos=(561,234); answered with (1,42) ack + (0,3) + (0,23) + (0,24)")

    def test_leave_replies_are_the_four_captured_frames(self):
        location = movement.Location(38, 1, 561, 234, 5)
        self.assertEqual(
            [(op.key(), len(body)) for op, body in settle.replies(3, location)],
            [((1, 42), 8), (blocks.ACK_OPCODE.key(), 16),
             (movement.AREA_ACK_OPCODE.key(), 16),
             (movement.AREA_ACK_2_OPCODE.key(), 20)])

    def test_the_ack_carries_the_session_key(self):
        """Fifteen reference `(0,3)` sends, four sessions: the u16 is the key.

        LRouDao (slot 2) reads `01 02 00 01` in every one of its own; the 09-28
        and 09-29 XJianHun logs (slot 3) read `01 03 00 01` in all thirteen.
        The old constant was fitted off the slot-3 logs alone, so slot 2 was
        answered with another character's key.
        """
        self.assertEqual(blocks.ack_body(2),
                         bytes.fromhex("01020001") + bytes(12))
        self.assertEqual(blocks.ack_body(3),
                         bytes.fromhex("01030001") + bytes(12))


class PendingTutorialTest(unittest.TestCase):
    def test_clear_writes_zero_and_nothing_else(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("create table characters (character_id integer primary "
                     "key, pending_tutorial_dungeon_id integer, name text)")
        conn.execute("insert into characters values (?, ?, ?)",
                     (CHARACTER, 7115, "XJianHun"))
        characters.clear_pending_tutorial(conn, CHARACTER)
        row = conn.execute("select pending_tutorial_dungeon_id, name from "
                           "characters where character_id = ?",
                           (CHARACTER,)).fetchone()
        self.assertEqual(tuple(row), (0, "XJianHun"))

    def test_other_characters_keep_theirs(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("create table characters (character_id integer primary "
                     "key, pending_tutorial_dungeon_id integer)")
        conn.execute("insert into characters values (1, 7115), (2, 7115)")
        characters.clear_pending_tutorial(conn, 1)
        self.assertEqual(
            conn.execute("select pending_tutorial_dungeon_id from characters "
                         "order by character_id").fetchall(), [(0,), (7115,)])


class BarePickSocketTest(unittest.TestCase):
    """The 09-29 failing session, end to end: character 1 at Seria's room,
    `(1,15)` on its gate, then `(1,16)` for dungeon 3 with quest 0.

    Before the fallback this drew the ignored line and nothing else; now the
    pair goes out for dungeon 3's own maze 0.  The save's quest rows are
    cleared first so the native retry cannot step in and the fallback is what
    the run exercises.
    """

    def setUp(self):
        self.save = _save_copy("dfo-entry-")
        conn = schema.connect(self.save)
        with conn:
            conn.execute("update characters set town_id = 38, area_id = 2, "
                         "position_x = 1085, position_y = 249, town_state = 5, "
                         "pending_tutorial_dungeon_id = 0 "
                         "where character_id = ?", (1,))
            conn.execute("delete from character_quest_progress "
                         "where character_id = ?", (1,))
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _c2s(self, main, sub, body, seq):
        return frame.build(frame.Link.GAME_C2S,
                           frame.Opcode(main, sub, frame.OpcodeEncoding.U8_U16LE, True),
                           tiles.encrypt_body(tiles.algo_id(sub), body),
                           seq=seq)

    def _bare_pick(self) -> bytes:
        """The capture's own dungeon-3 body with its quest zeroed."""
        body = bytearray(bytes.fromhex(ENTER_BODIES[1][0]))
        body[16:18] = bytes(2)
        return bytes(body)

    def _drive(self, log) -> list[tuple[frame.Opcode, bytes]]:
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 save_db=self.save, unix_seconds=1_789_824_022)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(self._c2s(1, 4, SELECT_BODY, 0))
                writer.write(self._c2s(1, 143, ENTRY_REQUEST, 1))
                writer.write(self._c2s(1, 15, bytes(8), 2))
                writer.write(self._c2s(1, 16, self._bare_pick(), 3))
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

        stream = frame.FrameStream(frame.Link.GAME_S2C)
        stream.feed(asyncio.run(run()))
        frames = []
        while (f := stream.next_frame()) is not None:
            frames.append((f.opcode,
                           tiles.decrypt_body(tiles.algo_id(f.opcode.sub),
                                              f.body)))
        return frames

    def test_the_pair_goes_out_for_the_dungeons_own_maze(self):
        log = Log(stream=io.StringIO())
        frames = self._drive(log)
        text = log._fh.getvalue()
        self.assertIn("key=1 dungeon=3 difficulty=0 entryOption=0 maze=0 "
                      "start=(0,1) map=58548 boss=(3,0) monsters=4 "
                      "training=False -> 2 frame(s)", text)
        self.assertNotIn("ignoring", text)

        ((map_op, map_plain), (spawn_op, spawn_plain)) = frames[-2:]
        self.assertEqual(map_op.key(), (0, 28))
        self.assertEqual(spawn_op.key(), (0, 29))
        run = _run(3, 0, (0, 1), 58548, spawn_plain[3:7].hex(), 1)
        self.assertEqual(map_plain, entry.map_body(run))
        self.assertEqual(spawn_plain, entry.room_body(run, revisit=False))
        self.assertEqual(spawn_plain[36:40],
                         struct.pack("<I", len(maze_data.room_monsters(58548))))


if __name__ == "__main__":
    unittest.main()
