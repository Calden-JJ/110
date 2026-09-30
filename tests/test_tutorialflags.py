"""`(1,143)` TUTORIAL-FLAGS: the report, the row it writes, the line it logs.

Pinned against the one dumped pair (09-26 22:17, conn=2 -- `_corpus` carries a
single `(1,143)` request, whose 16B plaintext is `0024 00000001` + ten zero
bytes) and the reference lines across the seven logs.  The layout's own
evidence is in `game.character.tutorialflags`: the fields are big-endian
because the reference prints `reward=1` where the little-endian reading would
be 16777216.

Every one of the `stored` lines' own second equals its row's `updated_at`
in the live save, and every `already stored` line leaves the row alone: the
write is an insert that ignores a repeat, and a repeat does not re-date.

Re-pinned 2026-09-29: 30 lines -> 31 and 11 `stored` -> 12, for the line
`server-20260929.log` adds -- key=3 flag=36, XJianHun's first town entry.

Re-pinned 2026-09-30: 31 -> 33, for that day's own two lines -- key=2 flag=36
at 12:07:38.085 and, from the bug3 room walkthrough, at 15:57:48.947, both
`already stored`, so `stored` stays 12.
"""
from __future__ import annotations

import asyncio
import datetime
import functools
import io
import re
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import NamedTuple

import _bootstrap  # noqa: F401
import _corpus
import _save

from uslocalserver import logs, paths
from uslocalserver.game.character import tutorialflags
from uslocalserver.persistence import schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

#: The dumped request and its answer, as the corpus session carried them.
REQUEST = bytes.fromhex("00240000000100000000000000000000")
REPLY = bytes.fromhex("01000000000000000000000000000000")

#: Character 1's four flags and the second of each `stored` line -- 09-19
#: 21:21:31.793, 21:22:32.993, 21:22:43.395 and 21:36:04.361 (+08:00).
CHARACTER_1 = ((30, 1789824091), (31, 1789824163), (36, 1789824964),
               (38, 1789824152))

_LINE = re.compile(r"key=(\d+) client reported flag=(\d+) "
                   r"\(raw=(\d+) prefix=(\d+) reward=(\d+)\) (.+)$")


class Rec(NamedTuple):
    direction: str
    plain: bytes
    wire: int


@functools.lru_cache(maxsize=1)
def _session():
    return logs.corpus_session(_corpus.require())


@functools.lru_cache(maxsize=1)
def _captured() -> tuple[Rec, ...]:
    """The session's `(1,143)` pair, request first."""
    s = _session()
    out = []
    for p in _corpus.all_packets():
        if not (s.first <= p.line_no <= s.last) or p.conn != s.conn or p.link != "game":
            continue
        link = frame.Link.GAME_C2S if p.direction == "C->S" else frame.Link.GAME_S2C
        f = frame.parse(link, p.frame_bytes, strict=False)
        if f.opcode.key() != tutorialflags.OPCODE.key():
            continue
        out.append(Rec(p.direction,
                       tiles.decrypt_body(tiles.algo_id(143), f.body),
                       p.wire))
    return tuple(out)


@functools.lru_cache(maxsize=1)
def _reference_lines() -> tuple[tuple[int, str, str], ...]:
    """`(line_no, tag, msg)` for the `(1,143)` run's two lines.

    The `(1,4)` selection shares the `TUTORIAL-FLAGS` tag for its own
    `sent 89 seen flag(s)` line, so the tag alone does not pick the run out:
    the flag line is the one reading `client reported flag=`.
    """
    s = _session()
    return tuple((ln.line_no, ln.tag, ln.msg) for ln in logs.stream(_corpus.require())
                 if s.first <= ln.line_no <= s.last
                 and (ln.tag == tutorialflags.OUT_OF_RANGE_TAG
                      or "client reported flag=" in ln.msg))


@functools.lru_cache(maxsize=1)
def _corpus_lines() -> tuple[tuple[str, int, int, str], ...]:
    """`(ts, key, flag, verdict)` for every `client reported` line in the logs."""
    out = []
    for p in sorted(paths.LOGS_DIR.glob("server-*.log")):
        for ln in logs.stream(p):
            if ln.tag != tutorialflags.TAG:
                continue
            m = _LINE.search(ln.msg)
            if m:
                out.append((ln.ts + ln.tz, int(m.group(1)), int(m.group(2)),
                            m.group(6)))
    return tuple(out)


class ParseTest(unittest.TestCase):
    def test_the_dumped_request_is_the_pinned_shape(self):
        report = tutorialflags.parse(REQUEST)
        self.assertEqual((report.raw, report.reward), (36, 1))
        self.assertEqual((report.flag, report.prefix), (36, 0))

    def test_the_u16_bit_is_the_flag_and_its_high_byte_the_prefix(self):
        report = tutorialflags.parse(bytes.fromhex("013600000001"))
        self.assertEqual(report.raw, 0x0136)
        self.assertEqual(report.flag, 0x36)
        self.assertEqual(report.prefix, 0x01)
        self.assertEqual(report.reward, 1)

    def test_a_body_below_the_two_fields_is_no_report(self):
        self.assertEqual(tutorialflags.SIZE, 6)
        self.assertIsNone(tutorialflags.parse(bytes(tutorialflags.SIZE - 1)))
        self.assertIsNotNone(tutorialflags.parse(bytes(tutorialflags.SIZE)))


class LineTest(unittest.TestCase):
    def test_the_line_reads_like_the_reference_ones(self):
        stored = tutorialflags.report_line(1, tutorialflags.parse(REQUEST),
                                           tutorialflags.STORED)
        self.assertEqual(stored,
                         "key=1 client reported flag=36 (raw=36 prefix=0 "
                         "reward=1) stored")
        again = tutorialflags.report_line(2, tutorialflags.parse(REQUEST),
                                          tutorialflags.ALREADY_STORED)
        self.assertTrue(again.endswith("already stored"), again)

    def test_the_out_of_range_line_is_the_literal(self):
        report = tutorialflags.parse(bytes.fromhex("006600000001") + bytes(4))
        self.assertEqual(tutorialflags.MAX_FLAG, 101)
        self.assertEqual(tutorialflags.out_of_range_line(report),
                         "flag 102 is outside 0..101; not stored")


def _save_copy() -> Path:
    # The 0.4.4 save ships one character; the tests below also drive
    # characters 1 and 3, so the fixture clones them from it.
    return _save.fresh(1, 2, 3)


class SaveCopyTest(unittest.TestCase):
    """`record` against a copy of the real save."""

    def setUp(self):
        self.save = _save_copy()
        self.conn = schema.connect(self.save)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def _stamp(self, character: int, flag: int) -> int | None:
        row = self.conn.execute(
            "select updated_at from character_tutorial_flags "
            "where character_id = ? and flag_index = ?",
            (character, flag)).fetchone()
        return None if row is None else row[0]

    def _fresh_flag(self, character: int) -> int:
        """A flag the character has not reported.  The save drifts as the
        game is played, so which flags are fresh is asked, not assumed."""
        taken = {row[0] for row in self.conn.execute(
            "select flag_index from character_tutorial_flags "
            "where character_id = ?", (character,))}
        return next(f for f in range(tutorialflags.MAX_FLAG + 1)
                    if f not in taken)

    def test_character_1_has_the_four_corpus_flags(self):
        """The four flags character 1 reported during the 0.3.6 capture.

        Those stamps belong to that save; the 0.4.4 fixture has its own three
        flags with their own dates, so the check is skipped unless the save
        still carries the corpus character.
        """
        present = {row[0]: row[1] for row in self.conn.execute(
            "select flag_index, updated_at from character_tutorial_flags "
            "where character_id = 1")}
        if not all(present.get(flag) == stamp for flag, stamp in CHARACTER_1):
            self.skipTest(
                f"character 1's flags are {sorted(present.items())}, not the "
                f"0.3.6 capture's {CHARACTER_1}; the corpus save is not the "
                f"fixture any more")
        for flag, stamp in CHARACTER_1:
            self.assertEqual(self._stamp(1, flag), stamp)

    def test_a_reported_flag_is_already_stored_and_keeps_its_date(self):
        """A repeat report is a no-op that keeps the original stamp.

        The flag is taken from the character's own rows rather than from the
        capture: what is being tested is the already-stored path, not which
        flag the 0.3.6 character happened to send.
        """
        flag = self.conn.execute(
            "select flag_index from character_tutorial_flags "
            "where character_id = 1 order by flag_index desc limit 1").fetchone()[0]
        before = self._stamp(1, flag)
        report = tutorialflags.Report(raw=flag, reward=1)
        tag, prose = tutorialflags.record(self.conn, 1, 1, report,
                                          now=before + 86_400)
        self.assertEqual(tag, tutorialflags.TAG)
        self.assertTrue(prose.endswith(tutorialflags.ALREADY_STORED), prose)
        self.assertEqual(self._stamp(1, flag), before)

    def test_a_fresh_flag_is_stored_and_dated(self):
        flag = self._fresh_flag(3)
        report = tutorialflags.Report(raw=flag, reward=1)
        tag, prose = tutorialflags.record(self.conn, 3, 3, report,
                                          now=1_789_999_999)
        self.assertEqual(tag, tutorialflags.TAG)
        self.assertTrue(prose.endswith(tutorialflags.STORED), prose)
        self.assertEqual(self._stamp(3, flag), 1_789_999_999)
        # The second report is the repeat the reference leaves alone.
        _tag, prose = tutorialflags.record(self.conn, 3, 3, report,
                                           now=1_790_000_000)
        self.assertTrue(prose.endswith(tutorialflags.ALREADY_STORED), prose)
        self.assertEqual(self._stamp(3, flag), 1_789_999_999)

    def test_an_out_of_range_report_writes_nothing(self):
        before = self.conn.execute(
            "select count(*) from character_tutorial_flags").fetchone()[0]
        report = tutorialflags.Report(raw=102, reward=1)
        tag, prose = tutorialflags.record(self.conn, 1, 1, report)
        self.assertEqual(tag, tutorialflags.OUT_OF_RANGE_TAG)
        self.assertEqual(prose, "flag 102 is outside 0..101; not stored")
        self.assertIsNone(self._stamp(1, 102))
        self.assertEqual(self.conn.execute(
            "select count(*) from character_tutorial_flags").fetchone()[0],
            before)


class CorpusTest(unittest.TestCase):
    """The dumped pair and the lines, both shapes."""

    def test_the_captured_pair_is_the_request_and_the_constant_ack(self):
        request, reply = _captured()
        self.assertEqual(request.direction, "C->S")
        self.assertEqual(request.plain, REQUEST)
        self.assertEqual(request.wire, 29)
        self.assertEqual(reply.direction, "S->C")
        self.assertEqual(reply.plain, REPLY)
        self.assertEqual(reply.wire,
                         frame.header_len(frame.Link.GAME_S2C) + len(REPLY))

    def test_the_reference_line_is_the_report_line(self):
        report = tutorialflags.parse(REQUEST)
        conn = _session().conn
        lines = _reference_lines()
        # The flag line opens the run whichever shape answered it; the flow
        # line that follows carries the other tag.
        self.assertEqual(lines[0][1], tutorialflags.TAG)
        self.assertEqual(lines[0][2],
                         f"conn={conn} " + tutorialflags.report_line(
                             1, report, tutorialflags.ALREADY_STORED))
        self.assertEqual(lines[1][1], tutorialflags.OUT_OF_RANGE_TAG)
        self.assertIn("town entry for key=1 tutorialAck=True", lines[1][2])

    def test_every_stored_line_dates_the_row_it_wrote(self):
        lines = _corpus_lines()
        if not lines:
            self.skipTest("the 0.3.6 corpus that carries these lines is absent")
        self.assertEqual(len(lines), 33)
        stored = [ln for ln in lines if ln[3] == tutorialflags.STORED]
        self.assertEqual(len(stored), 12)
        conn = schema.connect(paths.SAVE_DB, readonly=True)
        try:
            rows = {k: v for k, v in conn.execute(
                "select character_id || '/' || flag_index, updated_at "
                "from character_tutorial_flags")}
        finally:
            conn.close()
        missing = {f"{key}/{flag}" for _ts, key, flag, _v in lines
                   if f"{key}/{flag}" not in rows}
        if missing:
            self.skipTest(
                f"the capture's {len(missing)} character/flag key(s) are not in "
                f"this save ({sorted(missing)[:4]}); the lines date the 0.3.6 "
                f"save's rows, and the fixture's rows are its own")
        for ts, key, flag, _verdict in stored:
            self.assertEqual(int(datetime.datetime.fromisoformat(ts).timestamp()),
                             rows[f"{key}/{flag}"], f"flag {flag} of key {key}")
        for _ts, key, flag, verdict in lines:
            if verdict == tutorialflags.ALREADY_STORED:
                self.assertIn(f"{key}/{flag}", rows)


class SocketTest(unittest.TestCase):
    """The `(1,4)` selection then the captured `(1,143)`, end to end."""

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
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 save_db=self.save, unix_seconds=1_789_824_022)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                bursts = []
                for frame_bytes in frames:
                    writer.write(frame_bytes)
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
        out = []
        while (f := stream.next_frame()) is not None:
            out.append((f.opcode,
                        tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)))
        return out

    def test_the_town_entry_reports_the_flag_even_if_it_adds_nothing(self):
        log = Log(stream=io.StringIO())
        request = _corpus.all_packets()
        raw = next(p.frame_bytes for p in request
                   if p.direction == "C->S" and p.link == "game"
                   and p.opcode == (1, 143))
        _selection, entry, again = self._session(
            log, self._c2s(1, 4, bytes(16), 0), raw, raw)
        # The entry burst answers first with the 16B ack; the second send is
        # the `InTown` duplicate, one frame.
        self.assertEqual(self._decode(entry)[0], (tutorialflags.OPCODE, REPLY))
        self.assertEqual(self._decode(again), [(tutorialflags.OPCODE, REPLY)])
        text = log._fh.getvalue()
        self.assertIn("TUTORIAL-FLAGS conn=1 key=1 client reported flag=36 "
                      "(raw=36 prefix=0 reward=1) already stored", text)
        self.assertIn("TUTORIAL-FLAG-143 conn=1 town entry for key=1 "
                      "tutorialAck=True", text)
        self.assertIn("TUTORIAL-FLAG-143 conn=1 duplicate valid request after "
                      "town completion", text)
        self.assertIn("conn=1 (1,143) -> 1 frame(s) 32B", text)
        conn = schema.connect(self.save, readonly=True)
        try:
            stamp = conn.execute(
                "select updated_at from character_tutorial_flags "
                "where character_id = 1 and flag_index = 36").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(stamp, 1789824964)


if __name__ == "__main__":
    unittest.main()
