"""End-to-end test of the game server: replay the captured session at it.

The capture is the only ground truth for this link.  The test drives a real
socket with the 221 C->S frames exactly as the client sent them and demands
the S->C stream back byte for byte -- 527B of CHANNELINFO first, then every
captured reply in order.

The one unavoidable difference is the CHANNELINFO body: its field 11 is a unix
timestamp, so the server generates it.  The test therefore rebuilds the
expectation the same way rather than comparing against the capture's day-old
bytes; `test_bodies.py` makes up the strictness by pinning the generator
against the capture at the capture's own timestamp.
"""
from __future__ import annotations

import asyncio
import io
import re
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401
import _corpus

from uslocalserver import logs
from uslocalserver.game.town import movement
from uslocalserver.protocol import channelinfo, frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game

HOST = "10.0.0.7"
PORT = 10013
PROTOCOL_SERVER = 1
CHANNEL = 10

#: Field 11 of the CHANNELINFO is a unix timestamp -- the only input the
#: server picks for itself.  Both sides of the comparison pin it to this
#: second, otherwise the test fails whenever building the expectation and
#: answering the socket land either side of a second boundary (measured:
#: 14/30 runs, because loading the 143KB reply script takes ~200ms).
FROZEN_TS = 1_789_824_022


def _session_frames():
    """`(direction, opcode|None, raw)` for the corpus session, in wire order."""
    s = logs.corpus_session(_corpus.require())
    out = []
    for p in _corpus.all_packets():
        if not (s.first <= p.line_no <= s.last) or p.conn != s.conn or p.link != "game":
            continue
        link = frame.Link.GAME_C2S if p.direction == "C->S" else frame.Link.GAME_S2C
        fr = frame.parse(link, p.frame_bytes, strict=False)
        out.append((p.direction, (fr.opcode.main, fr.opcode.sub), p.frame_bytes))
    return out


SESSION = _session_frames()
C2S = [(op, raw) for d, op, raw in SESSION if d == "C->S"]
S2C_OPCODES = [op for d, op, _r in SESSION if d == "S->C"]


def _selected_runs():
    """`(op, run)` per answered C->S frame, the way the server picks them.

    Most opcodes walk their run list by send count, but the town entry does
    not: `(1,143)`/`(1,666)` are a 33/31-frame burst when sent from
    `CharacterSelected` and a one-frame ack when sent from `InTown`, so the
    run is chosen by the state the connection is in.  The harness runs with a
    character but no save, so the server replays the burst as captured rather
    than rebuilding it from the row -- this test is the log round trip, and
    `test_town_move` covers the row-built frames.
    """
    script = game.GameScript.load()
    cursors: dict = {}
    state = game.INITIAL_STATE
    for op, _raw in C2S:
        s = script.match(*op)
        if s is None:
            continue
        nth = cursors.get(op, 0)
        cursors[op] = nth + 1
        run = s.run(nth, from_state=state if op in movement.ENTRY_KEYS else None)
        if run.state:
            state = run.state[1]
        yield op, run


def _expected() -> bytes:
    """What the server must send for `C2S`, derived from the same script."""
    script = game.GameScript.load()
    out = frame.build_s2c(game.CHANNELINFO_OPCODE,
                          channelinfo.build(PROTOCOL_SERVER, CHANNEL, HOST, FROZEN_TS),
                          nonce=script.connect[0].nonce)
    for _op, run in _selected_runs():
        for reply in run.replies:
            body = tiles.encrypt_body(tiles.algo_id(reply.sub), reply.plain)
            out += frame.build_s2c(reply.opcode, body, nonce=reply.nonce)
    return out


class _Harness:
    """A game server on one port, plus the log it wrote."""

    def __init__(self, write_gap=0.0, advertise=HOST):
        self.write_gap = write_gap
        self.advertise = advertise

    async def __aenter__(self):
        self.buf = io.StringIO()
        self.server = game.GameServer(
            "127.0.0.1", {PORT: game.GAME_PORTS[PORT]}, game.GameScript.load(),
            game.Log(stream=self.buf), write_gap=self.write_gap,
            advertise_host=self.advertise, unix_seconds=FROZEN_TS)
        await self.server.start()
        self.bound = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()

    @property
    def text(self) -> str:
        return self.buf.getvalue()

    async def exchange(self, payloads, expected_len):
        """Send every payload, read until `expected_len` bytes have arrived.

        Reading concurrently with sending is not just speed: the 33-frame town
        burst is 42KB, which can fill the socket buffer and deadlock a
        send-it-all-then-read client against a server blocked in `drain()`.
        """
        reader, writer = await asyncio.open_connection("127.0.0.1", self.bound)
        got = bytearray()

        async def pump():
            for raw in payloads:
                writer.write(raw)
                await writer.drain()

        sender = asyncio.create_task(pump())
        try:
            while len(got) < expected_len:
                chunk = await asyncio.wait_for(reader.read(1 << 16), timeout=10.0)
                if not chunk:
                    break
                got += chunk
            await asyncio.wait_for(sender, timeout=10.0)
        finally:
            if not sender.done():
                sender.cancel()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return bytes(got)


def _run(coro_factory):
    async def main():
        async with _Harness() as h:
            return await coro_factory(h), h.text
    return asyncio.run(main())


class TestGameSession(unittest.TestCase):
    def test_full_session_is_byte_identical(self):
        want = _expected()
        got, _ = _run(lambda h: h.exchange([raw for _op, raw in C2S], len(want)))
        self.assertEqual(len(C2S), 221)
        self.assertEqual(got, want)

    def test_every_captured_reply_parses_back_in_order(self):
        want = _expected()
        got, _ = _run(lambda h: h.exchange([raw for _op, raw in C2S], len(want)))
        stream = frame.FrameStream(frame.Link.GAME_S2C)
        stream.feed(got)
        got_opcodes = [(f.opcode.main, f.opcode.sub) for f in stream.frames()]
        self.assertEqual(got_opcodes, S2C_OPCODES)
        self.assertEqual(len(got_opcodes), 61)
        self.assertEqual(stream.pending, 0, "trailing bytes after the last reply")

    def test_channelinfo_opens_the_connection(self):
        async def go(h):
            reader, writer = await asyncio.open_connection("127.0.0.1", h.bound)
            head = await asyncio.wait_for(reader.read(527), timeout=10.0)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return head

        head, _ = _run(go)
        f = frame.parse(frame.Link.GAME_S2C, head)
        self.assertEqual((f.opcode.main, f.opcode.sub), (0, 1))
        self.assertEqual(len(f.body), 511)
        plain = channelinfo.decode(f.body)
        self.assertEqual(int.from_bytes(plain[:4], "little"), len(plain) - 4)
        self.assertIn(b"ch.10", plain)
        self.assertIn(HOST.encode(), plain)

    def test_unknown_opcode_is_ignored(self):
        junk = frame.build(frame.Link.GAME_C2S,
                           frame.Opcode(1, 60000, frame.OpcodeEncoding.U8_U16LE, True),
                           b"\x00" * 16)
        got, text = _run(lambda h: h.exchange([junk], 527))
        stream = frame.FrameStream(frame.Link.GAME_S2C)
        stream.feed(got)
        self.assertEqual(len(stream.frames()), 1, "only the CHANNELINFO comes back")
        self.assertIn("no script for (1,60000)", text)


class TestGameScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = game.GameScript.load()

    def test_covers_every_request_in_the_capture(self):
        missing = [op for op, _r in C2S if self.script.match(*op) is None]
        self.assertEqual(missing, [], "a captured request with no script")
        self.assertEqual(len(C2S), sum(1 for _ in C2S))

    def test_opcode_count_matches_the_extractor(self):
        self.assertEqual(len(self.script), 35)
        self.assertEqual(len(self.script.unanswered()), 22)
        # 60 frames in the corpus, plus the 09-28 splice (`--town-entry`): the
        # 31-frame `(1,666)` burst and the 1-frame `(1,143)` ack, neither of
        # which that session's character ever drew.
        self.assertEqual(self.script.reply_count, 60 + 31 + 1)

    def test_repeated_requests_keep_their_runs_apart(self):
        s433 = self.script.match(1, 433)
        self.assertEqual(len(s433.runs), 3)
        self.assertEqual(len({r.replies[0].nonce for r in s433.runs}), 3,
                         "the three (1,433) replies must not collapse into one")
        s36 = self.script.match(1, 36)
        self.assertEqual([len(r.replies) for r in s36.runs], [2] * 5)
        self.assertNotEqual(s36.runs[0].replies[1].plain, s36.runs[1].replies[1].plain)

    def test_silent_opcodes_stay_silent_past_the_capture(self):
        s = self.script.match(1, 2126)
        self.assertEqual(len(s.runs), 162)
        self.assertTrue(all(not r.replies for r in s.runs))
        self.assertEqual(s.run(999).replies, (), "a 163rd send is still silence")

    def test_state_machine_is_a_straight_walk_into_town(self):
        # The *selected* runs, not every run in the script: `(1,143)` and
        # `(1,666)` each hold both shapes, and the capture only ever used one
        # of them per opcode.
        walk = [(op, run.state) for op, run in _selected_runs() if run.state]
        self.assertEqual(walk[0], ((1, 1554), ("Connected", "Handshaken")))
        self.assertEqual(walk[-1][1][1], "InTown")
        self.assertEqual([(a, b) for _op, (a, b) in walk if a != b],
                         [("Connected", "Handshaken"), ("Handshaken", "Authenticated"),
                          ("Authenticated", "RosterReady"), ("RosterReady", "CharacterSelected"),
                          ("CharacterSelected", "InTown")])
        self.assertEqual(dict(walk)[(1, 143)], ("CharacterSelected", "InTown"))
        # The corpus's own `(1,666)` is the *ack*: by the time char 1 sent it,
        # the `(1,143)` burst had already landed.  The 31-frame burst is the
        # 09-28 character's shape, spliced in from that session.
        self.assertEqual(dict(walk)[(1, 666)], ("InTown", "InTown"))
        self.assertEqual(len(self.script.match(1, 666).runs), 2)
        self.assertEqual([len(r.replies) for r in self.script.match(1, 666).runs],
                         [31, 1])

    def test_the_town_entry_run_is_the_33_frame_burst(self):
        run = self.script.match(1, 143).runs[0]
        self.assertEqual(len(run.replies), 33)
        # 42464B is the capture's own tally for the burst.  Reaching it needs
        # the playable bytes, not just their count: `missing` used to make up
        # the four bodies the corpus's 4096B dump cap cut, and nothing held
        # those bytes.  They come from a replay log now -- see
        # `extract_game_replies.py --completion` -- so no reply is short.
        self.assertEqual(sum(len(r.plain or b"") for r in run.replies),
                         42464 - 33 * 16)
        self.assertFalse([r for r in run.replies if r.truncated or r.missing])


class TestRemapPorts(unittest.TestCase):
    def test_shifted_block_keeps_the_channel_order(self):
        """The launcher moves the whole block when the defaults are busy --
        measured 2026-09-27: 10011-10021 -> 49322-49329 -- and its own
        `ROUTE ... game port 49324 -> channel=10 (Bel Myre)` line proves the
        Nth port keeps the Nth channel, so position is the whole mapping."""
        block = list(range(49322, 49330))
        self.assertEqual(game.remap_ports(block),
                         {new: game.GAME_PORTS[old] for new, old
                          in zip(block, sorted(game.GAME_PORTS))})
        self.assertEqual(game.remap_ports(block)[49324][2], 10)

    def test_the_default_block_is_the_identity(self):
        self.assertEqual(game.remap_ports(sorted(game.GAME_PORTS)), game.GAME_PORTS)

    def test_wrong_port_count_is_refused(self):
        with self.assertRaises(ValueError):
            game.remap_ports([49322, 49323])


class TestGameLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        want = _expected()
        _got, cls.text = _run(lambda h: h.exchange([raw for _op, raw in C2S], len(want)))

    def test_log_round_trips_through_the_reference_parser(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "server-test.log"
            p.write_text(self.text, encoding="utf-8")
            recs = [r for r in logs.iter_packets(p) if r.hex is not None]
        self.assertEqual(len(recs), 221 + 61)
        self.assertEqual([r.opcode for r in recs if r.direction == "C->S"],
                         [op for op, _r in C2S])
        self.assertTrue(all(r.opcode is None for r in recs if r.direction == "S->C"))
        # Whether a record is cut depends on the frame, not on the reference:
        # the 4096B cap bites only on frames over 4096B, and the rewrite's are
        # short of that until task #16 restores the four cut bodies.  The
        # invariant either way is that the declared size and the dump agree,
        # which is what `tools/diff_packets.py` reads.
        for r in recs:
            with self.subTest(line=r.line_no):
                self.assertEqual(r.hex.full_size, r.wire)

    def test_dispatch_lines_carry_the_captured_states(self):
        # 42464B is the capture's own tally for the town burst, and the rewrite
        # now sends all of it: the four bodies the 4096B `hex=` cap cost their
        # tails (592+8472+792+1504 = 11360B) were completed from a replay log,
        # so this number is the capture's rather than 11360 short of it.
        self.assertIn("(1,143) -> 33 frame(s) 42464B "
                      "state=CharacterSelected->InTown", self.text)
        self.assertIn("(1,1554) -> 1 frame(s) 24B state=Connected->Handshaken", self.text)
        # One DISPATCH per run that changed state, and the capture has 19 of
        # them -- it writes none for the 162 silent `(1,2126)` sends, which
        # get a per-frame WARN instead.  No run reports "0 frame(s)".
        self.assertEqual(self.text.count(" DEBUG DISPATCH "), 19)
        self.assertIn("WARN  UNHANDLED  conn=1 (1,2126) body=80B has no handler", self.text)

    def test_notes_are_replayed_with_the_live_plaintext(self):
        self.assertIn("TOWN-SELF-DATA conn=", self.text)
        self.assertIn("LEGACY-QUERY conn=", self.text)
        self.assertNotIn("STUN", self.text, "no STUN listener means no dropped datagram")
        # The `(1,3)` run's note list also carries the capture's session
        # teardown: `after 438.4s rx=68793B tx=47679B`, a ConnectionReset it
        # never got, and a state-released summary.  Replaying those would
        # report the capture's measured counters as this server's -- and a
        # synthetic `DISCONNECT ... after ` closes the session for
        # `logs.sessions()`, which puts the (1,3) reply that follows it out of
        # the session's line range and hides it from the packet diff.
        self.assertNotIn("438.4s", self.text)
        self.assertNotIn("state released", self.text)
        # `plain=` is this server's own decryption of the frame it just read,
        # dumped in the reference's upper case
        f = frame.parse(frame.Link.GAME_C2S, C2S[2][1])       # the (1,1592) probe
        plain = tiles.decrypt_body(tiles.algo_id(1592), f.body)
        self.assertEqual(len(plain), 32)
        self.assertIn(f"plain={plain[:96].hex().upper()}", self.text)

    def test_port_table_matches_the_reference_listen_lines(self):
        """`GAME_PORTS` is a transcription of the reference's startup log, not
        a reading of its config: `server.reference.json` names nine ports and
        the reference binds eight, because the endpoints come from the save's
        `channels` table."""
        bound = set()
        for ln in logs.stream(_corpus.require()):
            if ln.tag == "LISTEN" and (m := re.search(r"game bound on (\S+):(\d+)", ln.msg)):
                self.assertEqual(m.group(1), "192.168.1.6")
                bound.add(int(m.group(2)))
        self.assertEqual(bound, set(game.GAME_PORTS))
        self.assertEqual(len(bound), 8)

    def test_session_scoping_finds_the_corpus(self):
        s = logs.corpus_session(_corpus.require())
        self.assertEqual((s.conn, s.kind, s.port), (2, "game", 10013))
        self.assertEqual(len(logs.sessions(_corpus.require())), 23)
        # `conn=` restarts at 1 on every server restart, so the file holds six
        # `conn=2` sessions and scoping by `conn=` alone silently concatenates
        # them.  The line range is what separates the corpus from the rest.
        same_conn = [x for x in logs.sessions(_corpus.require())
                     if x.conn == s.conn and x.kind == s.kind]
        self.assertGreater(len(same_conn), 1)
        self.assertEqual([x for x in same_conn if x.is_corpus], [s])


if __name__ == "__main__":
    unittest.main()
