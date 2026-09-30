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
import json
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
import _corpus

from uslocalserver import logs, paths
from uslocalserver.game.character import roleselection
from uslocalserver.persistence import accounts, characters, schema
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

ACCOUNT = 0
WIRE_SIZE = 1312               # 16B header + the 1296B body
DUNGEON = paths.DATA_DIR / "game" / "dungeon-20260928.json"
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


def _line_logs() -> tuple[Path, ...]:
    """Where the `(1,4)` dumps are read from.

    `DFO_CORPUS_LOG` names one capture, so it replaces the pinned pair outright
    -- the point of the override is that a host without the 0.3.6 tree can
    still run these.  Joining the names onto `paths.LOGS_DIR` unconditionally
    (what this used to do) meant the override was honoured by `_corpus.require`
    and then ignored here, so the test raised `FileNotFoundError` instead of
    skipping or running.
    """
    override = paths.corpus_override()
    if override:
        return (override,)
    return tuple(p for p in (paths.LOGS_DIR / n for n in _LINE_LOGS) if p.exists())


#: Every byte `Pick.body()` writes, the flag block included: the seven live
#: regions plus the block that is the template's own copy.  Anything outside
#: this set is corpus data, so a dump that moves outside it is a layout bug.
WRITTEN = frozenset(
    set(range(roleselection.NOW_AT, roleselection.NOW_AT + 4))
    | {roleselection.KEY_AT, roleselection.CONTRACT_TYPE_AT, roleselection.TOWN_AT}
    | set(range(roleselection.CONTRACT_END_AT, roleselection.CONTRACT_END_AT + 4))
    | set(range(roleselection.CERA_AT, roleselection.CERA_AT + 4))
    | set(range(roleselection.FLAG_COUNT_AT, roleselection.FLAG_IDS_END)))


def _pinned_corpus() -> bool:
    """True when what is being read is the pinned 0.3.6 pair itself.

    Two assertions in `TemplateTest` are records of *that* corpus -- which six
    dumps it holds, down to the line number, and which eight bytes they move.
    Nothing else can have them: a substitute capture has its own dumps at its
    own line numbers, with its own set of characters behind them.  So they are
    asserted only when the corpus is the pinned one, and the general claim
    (`moved <= WRITTEN`, every dump rebuilt byte for byte) holds always.
    """
    return _bootstrap.pinned_corpus()


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

    Both source logs are 0.3.6 captures; without them there is nothing to
    compare against and the tests that call this skip.
    """
    _corpus.require()
    sources = _line_logs()
    if not sources:
        raise unittest.SkipTest(
            "no `(1,4)` corpus: set DFO_CORPUS_LOG to a log with `hex=` dumps")
    found = []
    for path in sources:
        name = path.name
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


def _dumps_or_skip() -> tuple:
    """`_captured_bodies()`, skipping when the corpus is simply not about `(1,4)`.

    A log can be a perfectly good corpus and hold no `(1,4)` send at all --
    `Logs-dungeon` is one; it was captured to pin the dungeon channel.  That is
    a corpus the test does not apply to, not a failure.
    """
    dumps = _captured_bodies()
    if not dumps:
        names = ", ".join(p.name for p in _line_logs())
        raise unittest.SkipTest(f"no `(1,4)` dumps in {names}")
    return dumps


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
        # Six dumps against the pinned corpus, the first of them the 09-26
        # 22:16:34 build for conn=2 (XRenYing slot 0), which is the capture the
        # template *is*.  A substituted corpus has its own dumps, at its own
        # line numbers, for characters of its own -- but every one of them is
        # still this template outside the written regions, and that is what is
        # asserted either way.
        dumps = _dumps_or_skip()
        stable = [at for at in range(roleselection.BODY_SIZE) if at not in WRITTEN]
        for name, line_no, _, body in dumps:
            with self.subTest(log=name, line=line_no):
                self.assertEqual([body[at] for at in stable],
                                 [template[at] for at in stable],
                                 "a dump differs from the template")
        if _pinned_corpus():
            self.assertEqual(template, dumps[0][3])
            self.assertEqual([(n, i) for n, i, _, _ in dumps],
                             [("server-20260926.log", 6466),
                              ("server-20260927.log", 382),
                              ("server-20260927.log", 806),
                              ("server-20260927.log", 1115),
                              ("server-20260927.log", 1769),
                              ("server-20260927.log", 2104)])

    def test_the_six_dumps_only_move_inside_the_regions(self):
        """Everything a dump moves is a byte `body()` writes.

        The pinned corpus moves eight of them (`{5,6,7,9,37,38,39,249}`) across
        two characters, five levels, two towns and two slots -- but which
        eight is a fact about *that* corpus, not about the layout, so a
        substituted one is held to the layout claim instead: nothing outside
        `WRITTEN` may differ.  The high bytes of `now`, `remaining` and `cera`
        are among the ones a given corpus may or may not exercise; they are
        written as u32s either way, which is the body's own convention.
        """
        bodies = [body for *_, body in _dumps_or_skip()]
        moved = {at for at in range(roleselection.BODY_SIZE)
                 if len({body[at] for body in bodies}) > 1}
        self.assertEqual(moved - WRITTEN, set(),
                         "a byte outside the written regions changed")
        if _pinned_corpus():
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
        for name, line_no, line, body in _dumps_or_skip():
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
                self.assertEqual(int(m[2]), pick.content_size)

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


class FlaglessTest(unittest.TestCase):
    """The 09-28 dungeon session's new character, whose body is 1200B.

    `data/game/dungeon-20260928.json` holds the only dump of a character with
    no tutorial flags (`XJianHun`, no `character_story_digest` row yet), and
    the reference's own two lines beside it -- `built 1197B` and `sent 0 seen
    flag(s) (baseline 89 + reported 0)`.
    """

    def _run(self) -> dict:
        doc = json.loads(DUNGEON.read_text(encoding="utf-8"))
        return next(s["runs"][0] for s in doc["scripts"]
                    if (s["request_main"], s["request_sub"]) == (1, 4))

    def test_the_body_is_the_template_less_the_block(self):
        run = self._run()
        body = bytes.fromhex(next(f["plain_hex"] for f in run["replies"]
                                  if (f["main"], f["sub"]) == (1, 4)))
        self.assertEqual(len(body), 1200)
        # The block is an insertion: the tail that follows the ids in the
        # template sits 89 bytes earlier here, and the pad is 3 not 10.  The
        # live regions are the dump's, not the template's, so they are skipped.
        template = roleselection.template()
        live = {*range(roleselection.NOW_AT, roleselection.NOW_AT + 4),
                roleselection.KEY_AT, roleselection.CONTRACT_TYPE_AT,
                *range(roleselection.CONTRACT_END_AT,
                       roleselection.CONTRACT_END_AT + 4),
                *range(roleselection.CERA_AT, roleselection.CERA_AT + 4),
                roleselection.TOWN_AT, FLAG_COUNT_AT}
        self.assertEqual(body[FLAG_COUNT_AT], 0)
        self.assertEqual(body[FLAG_COUNT_AT + 1:],
                         template[roleselection.FLAG_IDS_END:
                                  roleselection.CONTENT_SIZE] + bytes(3))
        self.assertEqual(
            [body[at] for at in range(FLAG_COUNT_AT) if at not in live],
            [template[at] for at in range(FLAG_COUNT_AT) if at not in live])

    def test_the_two_lines_are_rebuilt_from_the_pick(self):
        run = self._run()
        body = bytes.fromhex(next(f["plain_hex"] for f in run["replies"]
                                  if (f["main"], f["sub"]) == (1, 4)))
        line = next(n[2] for n in run["notes"] if n[1] == "SELECTION-4")
        m = LINE.fullmatch("conn=4 " + line.replace("conn={conn} ", "", 1))
        now = int.from_bytes(body[roleselection.NOW_AT:roleselection.NOW_AT + 4],
                             "little")
        pick = roleselection.Pick(
            account=int(m[3]), slot=int(m[4]), name=m[6], job=int(m[7]),
            level=int(m[8]), cera=int(m[9]), town=body[roleselection.TOWN_AT],
            contracts=((int(m[11]), now + int(m[12])),), now=now,
            flags=0, reported=0)
        self.assertEqual(pick.body(), body)
        self.assertEqual(int(m[2]), pick.content_size)
        self.assertEqual(line.replace("conn={conn} ", "", 1), pick.note())
        flags = next(n[2] for n in run["notes"] if n[1] == "TUTORIAL-FLAGS")
        self.assertEqual(flags.replace("conn={conn} ", "", 1),
                         pick.flags_note())

    def test_the_gate_is_the_story_digest_row(self):
        """The one fitted rule: `Pick.of` reads the block off that row.

        Both characters in the shipped save have one and send 89; the row is
        deleted here to stand in for a character that has not started the
        story, which is what the 09-28 dump is.
        """
        save = _save_copy()
        try:
            conn = schema.connect(save)
            try:
                summary = characters.by_id(conn, 1)
                self.assertEqual(roleselection.Pick.of(conn, ACCOUNT, summary,
                                                       NOW).flags, 89)
                conn.execute("delete from character_story_digest "
                             "where character_id = 1")
                conn.commit()
                pick = roleselection.Pick.of(conn, ACCOUNT, summary, NOW)
                self.assertEqual(pick.flags, 0)
                self.assertEqual(pick.content_size, roleselection.FLAGLESS_SIZE)
                reported = conn.execute(
                    "select count(*) from character_tutorial_flags "
                    "where character_id = 1").fetchone()[0]
                self.assertEqual(pick.flags_note(),
                                 f"key=1 sent 0 seen flag(s) "
                                 f"(baseline 89 + reported {reported})")
            finally:
                conn.close()
        finally:
            shutil.rmtree(save.parent, ignore_errors=True)


class StoryTest(unittest.TestCase):
    """`(0,1370)`: the run's third frame, the character's story digest.

    Two dumps, both whole frames: 110 for the M2 corpus's XRenYing (its
    `character_story_digest.last_level`) and 0 for the 09-28 session's fresh
    character, whose row does not exist yet.
    """

    def test_the_corpus_frame_is_the_row_level(self):
        doc = json.loads((paths.DATA_DIR / "game" / "replies.json")
                         .read_text(encoding="utf-8"))
        srun = next(s["runs"][0] for s in doc["scripts"]
                    if (s["request_main"], s["request_sub"]) == (1, 4))
        blob = next(f["plain_hex"] for f in srun["replies"]
                    if (f["main"], f["sub"]) == (0, 1370))
        self.assertEqual(blob, "6e000000000000000000000000000000")
        self.assertEqual(roleselection.story_body(110), bytes.fromhex(blob))
        note = next(n[2] for n in srun["notes"] if n[1] == "STORY-DIGEST")
        self.assertEqual(note, "conn={conn} " + roleselection.story_note(1, 110))

    def test_the_dungeon_frame_is_zero_for_a_fresh_character(self):
        doc = json.loads(DUNGEON.read_text(encoding="utf-8"))
        srun = next(s["runs"][0] for s in doc["scripts"]
                    if (s["request_main"], s["request_sub"]) == (1, 4))
        blob = next(f["plain_hex"] for f in srun["replies"]
                    if (f["main"], f["sub"]) == (0, 1370))
        self.assertEqual(blob, "00" * 16)
        self.assertEqual(roleselection.story_body(0), bytes.fromhex(blob))
        note = next(n[2] for n in srun["notes"] if n[1] == "STORY-DIGEST")
        self.assertEqual(note, "conn={conn} " + roleselection.story_note(3, 0))


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
                level = characters.story_level(conn, summary.character_id)
                expected[summary.slot_index] = (
                    accounts.cera(conn, ACCOUNT),
                    roleselection.Pick.of(conn, ACCOUNT, summary, NOW),
                    summary.character_id, level)
        finally:
            conn.close()

        for slot, (cera, pick, character_id, level) in expected.items():
            with self.subTest(slot=slot):
                frames, text = self._select(slot)
                self.assertEqual(frames[roleselection.RUN_AT][0].key(), (1, 4))
                body = frames[roleselection.RUN_AT][1]
                self.assertEqual(body, pick.body())
                # The body is the content padded to the next 16 bytes -- 1296
                # for a character with the flag block, 1200 without it.
                self.assertEqual(len(body) % 16, 0)
                self.assertLess(len(body) - pick.content_size, 16)
                self.assertEqual(struct.unpack("<I", body[5:9])[0], NOW)
                self.assertEqual(struct.unpack("<I", body[45:49])[0], cera)
                self.assertEqual(body[roleselection.TOWN_AT], pick.town)
                self.assertEqual(body[roleselection.KEY_AT], slot + 1)
                self.assertEqual(frames[roleselection.STORY_AT][0].key(), (0, 1370))
                self.assertEqual(frames[roleselection.STORY_AT][1],
                                 roleselection.story_body(level))
                self.assertEqual(frames[3][0].key(), (0, 2082))
                self.assertIn(f"SELECTION-4 conn=1 {pick.note()}", text)
                self.assertIn(f"TUTORIAL-FLAGS conn=1 {pick.flags_note()}", text)
                self.assertIn(f"STORY-DIGEST conn=1 "
                              f"{roleselection.story_note(character_id, level)}",
                              text)

    def test_a_slot_with_no_character_replays_the_capture(self):
        frames, text = self._select(9)
        self.assertEqual(frames[roleselection.RUN_AT][1], roleselection.template())
        self.assertIn("no character in slot 9", text)


if __name__ == "__main__":
    unittest.main()
