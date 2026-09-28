"""`(0,342)` / `(0,291)` / `(0,21)`: the entry burst's three quest frames.

The availability rule is pinned against the captured `(0,21)` frame itself:
its 137 ids reproduce id for id from the `(0,342)` frame's 814 finished ids
plus the save's single in-progress quest and XRenYing's `(at swordman, 5, 3)`
-- no live-save value is asserted anywhere, only internal consistency and
the shipped captures.
"""
from __future__ import annotations

import asyncio
import io
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.game import data
from uslocalserver.game.town import queststate
from uslocalserver.persistence import characters, schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

CHARACTER = 1
#: The `(1,143)` request, verbatim from the town probe log (see
#: `test_town_move`), and the zero body `(1,4)` selection uses.
ENTRY_REQUEST = bytes.fromhex("00240000000100000000000000000000")

#: XRenYing at the capture: class 11 `at swordman`, grow 5/3, level 110.
CAPTURED_SEEKER = queststate.Seeker(110, 11, 5, 3)
CAPTURED_IN_PROGRESS = [(13615, 1)]


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-queststate-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


def _u32(body: bytes, at: int) -> int:
    return struct.unpack_from("<I", body, at)[0]


def _varints(body: bytes) -> list[int]:
    out, pos = [], 0
    while pos < len(body):
        shift = val = 0
        while True:
            b = body[pos]
            pos += 1
            val |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        out.append(val)
    return out


def _finished_of_frame(plain: bytes) -> list[int]:
    n = _u32(plain, 0)
    return [_u32(plain, 4 + 4 * i) for i in range(n)]


def _available_of_frame(plain: bytes) -> list[int]:
    vals = _varints(plain[4:])
    return vals[5::2]


def _captured_entry_run():
    return game.GameScript.load().match(1, 143).run(0)


class BodyTest(unittest.TestCase):
    def test_varint_round_trips(self):
        for value in (0, 1, 127, 128, 300, 16383, 16384, 2 ** 21):
            enc = queststate.varint(value)
            pos, shift, out = 0, 0, 0
            while True:
                b = enc[pos]
                pos += 1
                out |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            self.assertEqual(out, value)
            self.assertEqual(pos, len(enc))

    def test_finished_body_is_count_ids_zero(self):
        self.assertEqual(queststate.finished_body([5, 9]),
                         struct.pack("<III", 2, 5, 9) + bytes(4))
        self.assertEqual(queststate.finished_body([]), struct.pack("<I", 0) + bytes(4))

    def test_in_progress_body_is_the_captured_sixteen_bytes(self):
        # 09-27 13:23, quest 13615 with trigger 1 and ten zero bytes: the only
        # in-progress sample that exists.
        self.assertEqual(queststate.in_progress_body([(13615, 1)]),
                         bytes.fromhex("01002f35010000000000000000000000"))
        self.assertEqual(queststate.in_progress_body([]), bytes(2))

    def test_available_body_self_describes(self):
        body = queststate.available_body(50, [7, 300])
        self.assertEqual(_u32(body, 0), len(body) - 4)
        vals = _varints(body[4:])
        self.assertEqual(vals, [0x10, 50, 0x18, 2, 0x20, 7, 0x20, 300])
        self.assertEqual(_available_of_frame(body), [7, 300])

    def test_opcodes_and_burst_indices(self):
        self.assertEqual(queststate.FINISHED_OPCODE.key(), (0, 342))
        self.assertEqual(queststate.IN_PROGRESS_OPCODE.key(), (0, 291))
        self.assertEqual(queststate.AVAILABLE_OPCODE.key(), (0, 21))
        self.assertEqual((queststate.FINISHED_AT, queststate.IN_PROGRESS_AT,
                          queststate.AVAILABLE_AT), (17, 18, 19))

    def test_class_names_are_the_jobs_table_order(self):
        self.assertEqual(len(queststate.CLASS_NAMES), 17)
        self.assertEqual(len(queststate.CLASS_NAMES),
                         len(data.load("gm_advancements")["jobs"]))

    def test_quest_vocabulary_is_closed(self):
        names = set(queststate.CLASS_NAMES)
        for quest in data.load("quest_content")["quests"].values():
            for job in quest.get("jobs") or ():
                self.assertIn(job, names | {"all"})
            for tchar in quest.get("targetCharacters") or ():
                self.assertIn(tchar.get("job"), names | {"all"})

    def test_worldmap_nodes_matches_the_six_logged_towns(self):
        self.assertEqual({t: queststate.worldmap_nodes(t)
                          for t in (39, 38, 146, 22, 76, 40)},
                         {39: 9, 38: 29, 146: 2, 22: 77, 76: 0, 40: 44})

    def test_state_line_drops_empty_clauses(self):
        self.assertEqual(
            queststate.state_line([], [(3145, 0)], 0),
            "(0,342) finished=0 (0,291) in-progress=1 (of 0 ever accepted); "
            "in-progress=3145")
        self.assertEqual(
            queststate.state_line([1, 2], [], 3),
            "(0,342) finished=2 (0,291) in-progress=0 (of 3 ever accepted); "
            "finished=1,2")

    def test_quests_line_keeps_an_empty_active(self):
        self.assertEqual(
            queststate.quests_line(40, 44, 137, [], 814, 110),
            "town=40 worldmap nodes=44 (0,21) available=137 active=[] "
            "finished=814 level=110")


class CaptureTest(unittest.TestCase):
    """`available_ids` against the captured frames, off shipped data only."""

    def test_finished_frame_ids_and_trailer(self):
        run = _captured_entry_run()
        body = run.replies[queststate.FINISHED_AT].plain
        ids = _finished_of_frame(body)
        self.assertEqual(len(ids), 814)
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(body[4 + 4 * 814:], bytes(4))
        self.assertEqual(queststate.finished_body(ids), body)

    def test_in_progress_frame_is_the_one_entry_body(self):
        run = _captured_entry_run()
        self.assertEqual(run.replies[queststate.IN_PROGRESS_AT].plain,
                         queststate.in_progress_body(CAPTURED_IN_PROGRESS))

    def test_available_frame_reproduces_id_for_id(self):
        run = _captured_entry_run()
        finished = _finished_of_frame(run.replies[queststate.FINISHED_AT].plain)
        captured = _available_of_frame(run.replies[queststate.AVAILABLE_AT].plain)
        self.assertEqual(len(captured), 137)
        self.assertEqual(
            queststate.available_ids(CAPTURED_SEEKER, finished, [13615]),
            captured)
        self.assertEqual(queststate.available_body(110, captured),
                         run.replies[queststate.AVAILABLE_AT].plain)


class SaveTest(unittest.TestCase):
    """`load` against a copy of the real save -- shape, never values."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def test_the_three_readers_agree_with_each_other(self):
        finished = queststate.finished_ids(self.conn, CHARACTER)
        in_progress = queststate.in_progress(self.conn, CHARACTER)
        accepted = queststate.accepted_count(self.conn, CHARACTER)
        self.assertEqual(finished, sorted(finished))
        self.assertEqual(len(finished), len(set(finished)))
        self.assertTrue(set(q for q, _ in in_progress).isdisjoint(finished))
        # in-progress is accepted minus finished, so it cannot outnumber
        # accepted -- which is only the live table, far smaller than finished
        self.assertLessEqual(len(in_progress), accepted)
        self.assertTrue(all(isinstance(t, int) for _, t in in_progress))

    def test_available_body_decodes_back_to_the_ids(self):
        summary = characters.by_id(self.conn, CHARACTER)
        finished = queststate.finished_ids(self.conn, CHARACTER)
        in_progress = queststate.in_progress(self.conn, CHARACTER)
        ids = queststate.available_ids(queststate.Seeker.of(summary), finished,
                                       [q for q, _ in in_progress])
        self.assertEqual(ids, sorted(ids))
        body = queststate.available_body(summary.level, ids)
        self.assertEqual(_u32(body, 0), len(body) - 4)
        self.assertEqual(_available_of_frame(body), ids)


class SocketTest(unittest.TestCase):
    """The burst slots, end to end."""

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

    def test_the_three_slots_are_the_save_derived_bodies(self):
        log = Log(stream=io.StringIO())
        burst = self._entry_burst(log)
        self.assertEqual(len(burst), 33)
        self.assertEqual([burst[at][0].key() for at in
                          (queststate.FINISHED_AT, queststate.IN_PROGRESS_AT,
                           queststate.AVAILABLE_AT)],
                         [(0, 342), (0, 291), (0, 21)])

        conn = schema.connect(self.save, readonly=True)
        try:
            summary = characters.by_id(conn, CHARACTER)
            finished = queststate.finished_ids(conn, CHARACTER)
            in_progress = queststate.in_progress(conn, CHARACTER)
            available = queststate.available_ids(
                queststate.Seeker.of(summary), finished,
                [q for q, _ in in_progress])
            accepted = queststate.accepted_count(conn, CHARACTER)
        finally:
            conn.close()

        self.assertEqual(burst[queststate.FINISHED_AT][1],
                         queststate.finished_body(finished))
        self.assertEqual(burst[queststate.IN_PROGRESS_AT][1],
                         queststate.in_progress_body(in_progress))
        self.assertEqual(burst[queststate.AVAILABLE_AT][1],
                         queststate.available_body(summary.level, available))

        text = log._fh.getvalue()
        self.assertIn(queststate.state_line(finished, in_progress, accepted), text)
        self.assertIn(queststate.quests_line(
            summary.town_id, queststate.worldmap_nodes(summary.town_id),
            len(available), [q for q, _ in in_progress], len(finished),
            summary.level), text)


if __name__ == "__main__":
    unittest.main()
