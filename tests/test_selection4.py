"""`(1,4)`'s 1296B body against its six dumps, and the live rebuild.

`S->C game raw=1312` under opcode `(1,4)` appears six times in the reference
logs -- 09-26 22:16:34 (conn=2, XRenYing slot 0) and five times on 09-27, the
last of them LRouDao slot 1.  Those six are the whole corpus and they pin the
model: the varying offsets are exactly `{5,6,7,9,37,38,39,249}`, all inside
the six regions `roleselection` writes, and each dump is rebuilt byte for byte
from its own `SELECTION-4` line and the frame's own log timestamp.

The dump that needs watching is the timestamp one: `now` is the run's build
second, so the test takes it from the `PACKET` line rather than from the body
it is checking.
"""
from __future__ import annotations

import asyncio
import datetime
import functools
import io
import re
import shutil
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import _bootstrap  # noqa: F401

from uslocalserver import logs, paths
from uslocalserver.game.character import roleselection
from uslocalserver.persistence import accounts, characters, schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

ACCOUNT = 0
WIRE_SIZE = 1312               # 16B header + the 1296B body
NOW = 1_789_824_022            # the socket test's pinned clock

#: The 39 bytes the reference's own line reports ten fewer than it sends:
#: a count byte and the ids `0..88`, the block `TUTORIAL-FLAGS` calls
#: `sent 89 seen flag(s) max=88`.
FLAG_COUNT_AT = 254
FLAG_BLOCK = slice(FLAG_COUNT_AT + 1, FLAG_COUNT_AT + 90)

LINE = re.compile(
    r"conn=(\d+) built (\d+)B role-selection response for account (\d+): "
    r"slot=(\d+) key=(\d+) name='([^']*)' job=(\d+) level=(\d+) cera=(\d+) "
    r"privileges=(\S+?)(?: contracts=(\d+):(\d+))?$")

_LINE_LOGS = ("server-20260926.log", "server-20260927.log")


_REAL_MONOTONIC = time.monotonic


class _Clock:
    """`game.time` with the wall clock pinned and the monotonic side real."""

    time = staticmethod(lambda: float(NOW))
    monotonic = staticmethod(_REAL_MONOTONIC)


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-selection4-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


@functools.lru_cache(maxsize=1)
def _captured_bodies():
    """Every `(1,4)` dump: `(log name, line_no, LogLine, body)`.

    The `SELECTION-4` line that goes with each one is the last before the send
    -- the reference builds the run and logs it in one pass, so the two are a
    few lines apart and no other run intervenes.
    """
    found = []
    for name in _LINE_LOGS:
        path = paths.LOGS_DIR / name
        by_no = {}
        selection_lines = []
        for line in logs.stream(path):
            by_no[line.line_no] = line
            if line.tag == "SELECTION-4":
                selection_lines.append(line)
        for rec in logs.iter_packets(path):
            if rec.direction != "S->C" or rec.wire != WIRE_SIZE:
                continue
            fr = frame.parse(frame.Link.GAME_S2C, rec.frame_bytes)
            if (fr.opcode.main, fr.opcode.sub) != (1, 4):
                continue
            line = max((ln for ln in selection_lines if ln.line_no < rec.line_no),
                       key=lambda ln: ln.line_no)
            body = tiles.decrypt_body(tiles.algo_id(fr.opcode.sub), fr.body)
            found.append((name, rec.line_no, line, body))
    return tuple(found)


def _unix_second(line: logs.LogLine) -> int:
    """The log line's own second, in unix time (the field is whole seconds)."""
    stamp = datetime.datetime.fromisoformat(line.ts.replace(" ", "T") + line.tz)
    return int(stamp.timestamp())


class TemplateTest(unittest.TestCase):
    """The shipped blob, and what the dumps say about it."""

    def test_template_is_the_corpus_body(self):
        run = game.GameScript.load().match(1, 4).run(0)
        reply = run.replies[roleselection.RUN_AT]
        self.assertEqual((reply.main, reply.sub), (1, 4))
        self.assertEqual(len(reply.plain), roleselection.BODY_SIZE)
        template = roleselection.template()
        self.assertEqual(template, reply.plain)
        # Six dumps, the corpus (09-26 22:16:34) the first of them.
        dumps = _captured_bodies()
        self.assertEqual([(n, i) for n, i, _, _ in dumps],
                         [("server-20260926.log", 6466), ("server-20260927.log", 382),
                          ("server-20260927.log", 806), ("server-20260927.log", 1115),
                          ("server-20260927.log", 1769), ("server-20260927.log", 2104)])
        self.assertEqual(template, dumps[0][3])

    def test_the_six_dumps_only_move_inside_the_regions(self):
        bodies = [body for *_, body in _captured_bodies()]
        moved = {at for at in range(roleselection.BODY_SIZE)
                 if len({body[at] for body in bodies}) > 1}
        # Everything else -- 1288 bytes -- is identical across two characters,
        # five levels, two towns and two slots.  (The high bytes of `now`,
        # `remaining` and `cera` happen to be constant too; they are still
        # written as u32s, which is the body's own convention.)
        self.assertEqual(moved, {5, 6, 7, 9, 37, 38, 39, 249})

    def test_the_flag_block_is_the_89_sent_flags(self):
        blob = roleselection.template()
        self.assertEqual(blob[FLAG_COUNT_AT], 89)
        self.assertEqual(blob[FLAG_BLOCK], bytes(range(89)))

    def test_the_record_is_between_the_key_and_the_cera(self):
        # The 9 bytes the line's 1277 -> 1286 step adds: the type byte, the
        # countdown, and four that never differ in any dump.
        self.assertEqual(roleselection.template()[roleselection.CONTRACT_TYPE_AT], 92)
        self.assertEqual(roleselection.template()[roleselection.CONTRACT_END_AT + 4:
                                                  roleselection.CERA_AT], bytes(4))


class DumpTest(unittest.TestCase):
    """Each dump, rebuilt from its own line and its own log timestamp."""

    def test_every_dump_is_rebuilt_byte_for_byte(self):
        for name, line_no, line, body in _captured_bodies():
            with self.subTest(log=name, line=line_no):
                m = LINE.fullmatch(line.msg)
                self.assertIsNotNone(m, line.msg)
                now = _unix_second(line)
                self.assertEqual(now, int.from_bytes(
                    body[roleselection.NOW_AT:roleselection.NOW_AT + 4], "little"),
                    "the body's `now` is not the frame's own log second")
                contracts = (((int(m[11]), now + int(m[12])),) if m[11] else ())
                pick = roleselection.Pick(
                    account=int(m[3]), slot=int(m[4]), name=m[6], job=int(m[7]),
                    level=int(m[8]), cera=int(m[9]), town=body[roleselection.TOWN_AT],
                    contracts=contracts, now=now)
                self.assertEqual(pick.body(), body)
                self.assertEqual(pick.key, int(m[5]))
                self.assertEqual(pick.remaining, int(m[12]) if m[12] else 0)
                self.assertEqual(line.msg, f"conn={m[1]} {pick.note()}")
                self.assertEqual(int(m[2]), roleselection.LOGGED_SIZE)

    def test_the_line_omits_the_contract_tail_when_there_is_none(self):
        pick = roleselection.Pick(account=0, slot=0, name="LRouDao", job=1,
                                  level=1, cera=100000, town=6, contracts=(),
                                  now=NOW)
        self.assertEqual(pick.note(),
                         "built 1286B role-selection response for account 0: "
                         "slot=0 key=1 name='LRouDao' job=1 level=1 cera=100000 "
                         "privileges=5/12")
        self.assertEqual(pick.remaining, roleselection.NO_EXPIRY)
        self.assertEqual(pick.premium_type, 0)

    def test_an_expired_contract_reads_zero_not_negative(self):
        pick = roleselection.Pick(account=0, slot=0, name="LRouDao", job=1,
                                  level=1, cera=0, town=6,
                                  contracts=((92, NOW - 60),), now=NOW)
        self.assertEqual(pick.remaining, 0)
        self.assertEqual(struct.unpack("<I", pick.body()[roleselection.CONTRACT_END_AT:
                                                          roleselection.CONTRACT_END_AT + 4])[0],
                         0)


class SaveTest(unittest.TestCase):
    """`accounts.cera` / `premium_contracts` against a copy of the real save."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def test_cera_reads_the_one_row(self):
        self.assertEqual(accounts.cera(self.conn, ACCOUNT),
                         self.conn.execute("select cera from accounts "
                                           "where account_id = 0").fetchone()[0])
        self.assertIsNone(accounts.cera(self.conn, 999))

    def test_contracts_are_ordered_by_type(self):
        rows = self.conn.execute("select premium_type, expires_at from "
                                 "account_premium_contracts where account_id = 0 "
                                 "order by premium_type").fetchall()
        self.assertEqual(accounts.premium_contracts(self.conn, ACCOUNT),
                         tuple((row[0], row[1]) for row in rows))
        self.assertEqual(accounts.premium_contracts(self.conn, 999), ())


class SocketTest(unittest.TestCase):
    """The run's own `(1,4)` frame, built from the save on the wire."""

    def setUp(self):
        self.save = _save_copy()

    def tearDown(self):
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _c2s(self, main, sub, body, seq):
        return frame.build(frame.Link.GAME_C2S,
                           frame.Opcode(main, sub, frame.OpcodeEncoding.U8_U16LE, True),
                           tiles.encrypt_body(tiles.algo_id(sub), body),
                           seq=seq)

    def _select(self, slot: int):
        """Send `(1,4)` for `slot`; return `(decoded run frames, log text)`."""
        log = Log(stream=io.StringIO())
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 save_db=self.save, unix_seconds=NOW)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(self._c2s(1, 4, bytes([slot]) + bytes(15), 0))
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

        with mock.patch.object(game, "time", _Clock):
            data = asyncio.run(run())
        stream = frame.FrameStream(frame.Link.GAME_S2C)
        stream.feed(data)
        frames = []
        while (f := stream.next_frame()) is not None:
            frames.append((f.opcode,
                           tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)))
        return frames[-4:], log._fh.getvalue()

    def test_the_body_is_built_from_the_save(self):
        conn = schema.connect(self.save, readonly=True)
        try:
            summaries = characters.list_characters(conn, ACCOUNT)
            self.assertTrue(summaries)
            expected = {}
            for summary in summaries:
                expected[summary.slot_index] = (
                    accounts.cera(conn, ACCOUNT),
                    roleselection.Pick.of(conn, ACCOUNT, summary, NOW))
        finally:
            conn.close()

        for slot, (cera, pick) in expected.items():
            with self.subTest(slot=slot):
                frames, text = self._select(slot)
                self.assertEqual(frames[roleselection.RUN_AT][0].key(), (1, 4))
                body = frames[roleselection.RUN_AT][1]
                self.assertEqual(body, pick.body())
                self.assertEqual(len(body), roleselection.BODY_SIZE)
                self.assertEqual(struct.unpack("<I", body[5:9])[0], NOW)
                self.assertEqual(struct.unpack("<I", body[45:49])[0], cera)
                self.assertEqual(body[roleselection.TOWN_AT], pick.town)
                self.assertEqual(body[roleselection.KEY_AT], slot + 1)
                self.assertIn(f"SELECTION-4 conn=1 {pick.note()}", text)

    def test_a_slot_with_no_character_replays_the_capture(self):
        frames, text = self._select(9)
        self.assertEqual(frames[roleselection.RUN_AT][1], roleselection.template())
        self.assertIn("no character in slot 9", text)


if __name__ == "__main__":
    unittest.main()
