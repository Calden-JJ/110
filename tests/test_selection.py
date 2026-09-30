"""`(1,140)`/`(1,433)`/`(1,637)`/`(1,666)`/`(1,707)`/`(1,848)`: the six acks.

The corpus session carries 8 of the family -- `(1,848)`, `(1,433)`, `(1,637)`,
`(1,433)` before the town entry, then `(1,433)`, `(1,140)`, `(1,707)`,
`(1,666)` -- out of 44 requests and 44 replies across the six captured logins
(09-26 22:16 through 09-27 13:23); each opcode's reply decrypts to one
distinct body in every one of them.  The socket test runs the server with a
save attached -- M2 mode, where the family is generated; without one it is
replayed from the capture script like every other opcode, which is what
`test_game_server` covers.
"""
from __future__ import annotations

import asyncio
import functools
import io
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import NamedTuple

import _bootstrap  # noqa: F401
import _corpus

from uslocalserver import logs, paths
from uslocalserver.game.character import selection
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log

SUBS = (140, 433, 637, 666, 707, 848)
FAMILY = {(1, sub) for sub in SUBS}

#: The eight note tails the reference writes, in the order the corpus sends
#: them, paired with the tag each line carries.
NOTE_SEQUENCE = (
    (848, "built S2C (1,848) success"),
    (433, "accepted 6 request entries -> built S2C success with zero entries"),
    (637, "built S2C (1,637) success"),
    (433, "accepted 6 request entries -> built S2C success with zero entries"),
    (433, "accepted 6 request entries -> built S2C success with zero entries"),
    (140, "built S2C (1,140) 1B reply (request body 16B)"),
    (707, "built S2C (1,707) 1B reply (request body 8B)"),
    (666, "built S2C (1,666) 1B reply (request body 0B)"),
)


class Rec(NamedTuple):
    direction: str
    key: tuple[int, int]
    plain: bytes
    wire: int
    raw: bytes
    nonce: bytes


@functools.lru_cache(maxsize=1)
def _session():
    return logs.corpus_session(_corpus.require())


@functools.lru_cache(maxsize=1)
def _captured() -> tuple[Rec, ...]:
    """The family as the corpus session carried it, in wire order."""
    s = _session()
    out = []
    for p in _corpus.all_packets():
        if not (s.first <= p.line_no <= s.last) or p.conn != s.conn or p.link != "game":
            continue
        link = frame.Link.GAME_C2S if p.direction == "C->S" else frame.Link.GAME_S2C
        f = frame.parse(link, p.frame_bytes, strict=False)
        key = f.opcode.key()
        if key not in FAMILY:
            continue
        out.append(Rec(p.direction, key,
                       tiles.decrypt_body(tiles.algo_id(key[1]), f.body),
                       p.wire, p.frame_bytes, f.header[12:15]))
    return tuple(out)


@functools.lru_cache(maxsize=1)
def _reference_lines() -> tuple[tuple[str, str], ...]:
    """The session's own `SELECTION-<sub>` notes, `(tag, msg)` in order."""
    s = _session()
    tags = {f"SELECTION-{sub}" for sub in SUBS}
    return tuple((ln.tag, ln.msg) for ln in logs.stream(_corpus.require())
                 if s.first <= ln.line_no <= s.last and ln.tag in tags)


def _requests() -> list[Rec]:
    return [r for r in _captured() if r.direction == "C->S"]


def _replies() -> list[Rec]:
    return [r for r in _captured() if r.direction == "S->C"]


class CapturedTest(unittest.TestCase):
    def test_the_corpus_holds_the_whole_family(self):
        self.assertEqual([r.key for r in _requests()],
                         [(1, sub) for sub, _tail in NOTE_SEQUENCE])
        self.assertEqual(len(_replies()), 8)
        for key in sorted(FAMILY):
            bodies = {r.plain for r in _replies() if r.key == key}
            self.assertEqual(len(bodies), 1, f"{key} has two reply bodies")

    def test_the_generated_frames_are_the_captured_ones(self):
        for rec in _replies():
            ack = selection.ack(rec.key, b"")
            self.assertEqual(ack.opcode.key(), rec.key)
            self.assertEqual(ack.body, rec.plain)
            self.assertEqual(rec.wire,
                             frame.header_len(frame.Link.GAME_S2C) + len(rec.plain))

    def test_the_notes_are_the_reference_lines(self):
        conn = str(_session().conn)
        got = [selection.ack(r.key, r.plain).note
               .replace("{conn}", conn).replace("{n}", str(len(r.plain)))
               for r in _requests()]
        want = [msg for _tag, msg in _reference_lines()]
        self.assertEqual(len(want), 8)
        self.assertEqual(got, want)
        self.assertEqual([selection.ack(r.key, r.plain).tag for r in _requests()],
                         [tag for tag, _msg in _reference_lines()])

    def test_the_433_note_counts_the_request(self):
        note = selection.ack((1, 433), bytes.fromhex("0301020300")).note
        self.assertEqual(note,
                         "conn={conn} accepted 3 request entries -> built S2C "
                         "success with zero entries")
        self.assertIn("accepted 0 request entries",
                      selection.ack((1, 433), b"").note)

    def test_only_the_six_are_in_the_family(self):
        self.assertTrue(all(selection.handles(k) for k in FAMILY))
        for key in ((1, 4), (1, 143), (1, 141), (0, 433)):
            self.assertFalse(selection.handles(key))
            self.assertIsNone(selection.ack(key, b""))


def _save_copy() -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-selection-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(paths.SAVE_DB) + suffix)
        if src.exists():
            shutil.copy2(src, Path(str(dst) + suffix))
    return dst


class SocketTest(unittest.TestCase):
    """The family generated, not replayed: a save turns the handlers on."""

    def setUp(self):
        self.save = _save_copy()

    def tearDown(self):
        shutil.rmtree(self.save.parent, ignore_errors=True)

    def test_the_eight_requests_draw_their_generated_acks(self):
        log = Log(stream=io.StringIO())
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log, save_db=self.save,
                                 unix_seconds=1_789_824_022)
        given = _requests()

        async def burst(reader):
            got = bytearray()
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=2.0)
                except asyncio.TimeoutError:
                    return bytes(got)
                if not chunk:
                    return bytes(got)
                got += chunk

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                bursts = [await burst(reader)]           # the CHANNELINFO
                for rec in given:
                    writer.write(rec.raw)
                    await writer.drain()
                    bursts.append(await burst(reader))
                writer.close()
                return bursts
            finally:
                server.close()

        bursts = asyncio.run(run())
        got = []
        for raw in bursts[1:]:
            stream = frame.FrameStream(frame.Link.GAME_S2C)
            stream.feed(raw)
            f = stream.next_frame()
            got.append((f.opcode.key(),
                        tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body),
                        len(raw),
                        f.header[12:15]))
        want = [(r.key, r.plain, r.wire, r.nonce) for r in _replies()]
        self.assertEqual([g[:3] for g in got], [w[:3] for w in want])
        # A replayed frame re-sends the captured nonce; a generated one carries
        # three fresh bytes, so any hit here means the handler went missing.
        captured = {w[3] for w in want}
        self.assertFalse([g for g in got if g[3] in captured])

        text = log._fh.getvalue()
        for sub, tail in NOTE_SEQUENCE:
            self.assertIn(f"SELECTION-{sub} conn=", text)
            self.assertIn(tail, text)
        self.assertEqual(text.count("-> 1 frame(s) 24B"), 7)
        self.assertEqual(text.count("-> 1 frame(s) 40B"), 1)
        for m in re.finditer(r"state=(\w+)->(\w+)", text):
            self.assertEqual(m.group(1), m.group(2))


if __name__ == "__main__":
    unittest.main()
