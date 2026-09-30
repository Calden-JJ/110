"""End-to-end test of the channel server: replay the capture at it.

The captured channel session is the only ground truth for this link, so the
test drives the real socket with the three C->S frames exactly as the client
sent them and demands the three S->C frames back byte for byte.

The log is checked too: `tools/diff_packets.py` is what tells M1 apart from
"it seemed to work", and it reads the log rather than the wire.
"""
from __future__ import annotations

import asyncio
import datetime
import io
import re
import unittest

import _bootstrap  # noqa: F401

from uslocalserver import logs
from uslocalserver.protocol import frame
from uslocalserver.server import channel

CHANNEL_C2S = (bytes.fromhex("000b2b0000000000000001f2f7f142f7dea0499f6bf6129fe6184"
                             "fb76651875835f147e7940427c0d0aca3"),
               bytes.fromhex("00090b0000000000000001"),
               bytes.fromhex("00010b0000000000000001"))

REPLIES = channel.ChannelReplies.load()
CONNECT_ACK = next(r for r in REPLIES if r.name == "CONNECT_ACK")

#: CONNECT_ACK's date is the one body byte the server picks for itself: the
#: reference read `DateTime.Now` (the 09-26 capture says 20260926; a replay of
#: the same build the next day answered 20260927).  Pin the replay to the day
#: the capture records, or the byte-for-byte comparison is comparing clocks.
FROZEN_DAY = CONNECT_ACK.plain[4:12].decode("ascii")


def _captured_body(r: channel.Reply) -> bytes:
    """The body the reference would send: re-keyed with the capture's own day.

    Sealing is deterministic, so this is the captured ciphertext byte for byte
    -- `tests/test_channel_seal.py` checks that against the capture's SHA-256.
    """
    return channel.seal(r.plain, FROZEN_DAY) if r.sealed else r.plain


S2C_WIRES = [frame.header_len(frame.Link.CHANNEL_S2C) + len(_captured_body(r))
             for r in REPLIES]


def _exchange(payloads, *, host="127.0.0.1", write_gap=0.0, today=FROZEN_DAY,
              advertise=None):
    """Start the server, send every payload as one write, return what came back."""
    async def run():
        log = channel.Log(stream=io.StringIO())
        server = channel.ChannelServer(host, 0, channel.ChannelReplies.load(), log,
                                       write_gap=write_gap, today=today,
                                       advertise=advertise)
        await server.start()
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection(host, port)
            for p in payloads:
                writer.write(p)
                await writer.drain()
            await asyncio.sleep(0.05)
            got = await asyncio.wait_for(reader.read(65536), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        finally:
            server.close()
        return got, log._fh.getvalue()

    return asyncio.run(run())


class TestChannelExchange(unittest.TestCase):
    def test_the_shipped_bodies_are_for_our_block(self):
        # A body from another block is refused by the client silently, right
        # after the third ACK, so the checked-in copy has to name its block and
        # that block has to be the one this server binds.
        self.assertEqual(REPLIES.block, channel.CHANNEL_PORT)

    def test_block_warning_fires_only_on_a_mismatch(self):
        self.assertIsNone(channel.block_warning(REPLIES, channel.CHANNEL_PORT))
        self.assertIsNone(channel.block_warning(channel.ChannelReplies({}), 7001))
        msg = channel.block_warning(channel.ChannelReplies({}, block=57491), 7001)
        self.assertIn("57491", msg)
        self.assertIn("7001", msg)
        self.assertIn("extract_channel_replies.py", msg)

    def test_replies_are_the_captured_wire_bytes(self):
        got, _ = _exchange(CHANNEL_C2S)
        expect = b"".join(
            frame.build(frame.Link.CHANNEL_S2C, r.opcode, _captured_body(r))
            for r in channel.ChannelReplies.load())
        # the server answers in request order, which is also capture order
        self.assertEqual(got, expect)

    def test_replies_round_trip_through_the_framer(self):
        got, _ = _exchange(CHANNEL_C2S)
        stream = frame.FrameStream(frame.Link.CHANNEL_S2C)
        stream.feed(got)
        got_frames = stream.frames()
        self.assertEqual([(f.opcode.main, f.opcode.sub) for f in got_frames],
                         [(124, 12), (124, 10), (124, 3)])
        self.assertEqual([len(f.body) for f in got_frames],
                         [len(_captured_body(r)) for r in REPLIES])
        self.assertEqual(stream.pending, 0, "trailing bytes after the third reply")

    def test_pipelined_requests_are_still_paced(self):
        """Two replies must not collapse into one client read.

        The real client fires (0,9) and (0,1) back to back, so both requests
        are already in the stream buffer when the first reply is built.  A bare
        `asyncio.sleep(12ms)` did not hold here: this platform's proactor loop
        sweeps timers inside its 15.6ms clock resolution, so the I/O completion
        that wakes the loop dropped the second gap to 0.15ms and the client got
        both ACKs in one `recv()` -- the documented "server row, no endpoint"
        failure.  The deadline form in `pacing.sleep_gap` holds; 5ms is the
        floor that still catches a collapse without flaking on timer granularity.

        The gap is read off the server's own `sent ...` lines, not off the
        client's clock: the client stamps the first read *after* it returns,
        so a loop starved by the rest of the suite records it late and reports
        a collapse the server did not commit (seen under load on 09-28).  Two
        stamps inside one process can only err wide under starvation -- the
        second send waits out its deadline after the first line is written.
        """
        log = channel.Log(stream=io.StringIO())
        sent = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) "
                          r"([+-]\d{2}:\d{2}) INFO\s+CHANNEL\s+conn=\d+ sent (\w+)",
                          re.M)

        async def run():
            server = channel.ChannelServer("127.0.0.1", 0, channel.ChannelReplies.load(), log)
            await server.start()
            port = server.sockets[0].getsockname()[1]
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(CHANNEL_C2S[0])
                await writer.drain()
                await asyncio.wait_for(reader.readexactly(S2C_WIRES[0]), timeout=2.0)
                writer.write(CHANNEL_C2S[1] + CHANNEL_C2S[2])
                await writer.drain()
                await asyncio.wait_for(reader.readexactly(S2C_WIRES[1]), timeout=2.0)
                await asyncio.wait_for(reader.readexactly(S2C_WIRES[2]), timeout=2.0)
                writer.close()
            finally:
                server.close()

        asyncio.run(run())
        stamps = [(datetime.datetime.strptime(f"{a} {b}", "%Y-%m-%d %H:%M:%S.%f %z"),
                   name) for a, b, name in sent.findall(log._fh.getvalue())]
        self.assertEqual([name for _ts, name in stamps],
                         ["CONNECT_ACK", "SCRIPT_ACK", "CHANNEL_ACK"])
        gap = (stamps[2][0] - stamps[1][0]).total_seconds()
        self.assertGreaterEqual(gap, 0.005, f"SCRIPT_ACK -> CHANNEL_ACK gap collapsed to {gap*1000:.2f}ms")

    def test_unknown_opcode_gets_no_reply(self):
        junk = bytes.fromhex("00ff0b0000000000000001")
        got, text = _exchange([CHANNEL_C2S[0], junk])
        self.assertIn("unknown channel message (0,255)", text)
        self.assertEqual(len(got), S2C_WIRES[0], "only CONNECT_ACK should have come back")

    def test_all_three_bodies_follow_the_clock(self):
        """The day is the key: CONNECT_ACK carries it in the clear and the two
        big bodies are sealed under it, so a server that crosses midnight must
        move all three together.  The token in the first body is what the
        client derives the other two's key from -- a stale pair is garbage."""
        got, _ = _exchange(CHANNEL_C2S, today="20270101")
        captured = frame.build(frame.Link.CHANNEL_S2C, CONNECT_ACK.opcode, CONNECT_ACK.plain)
        self.assertEqual(got[:15], captured[:15])
        self.assertEqual(got[15:23], b"20270101")   # 11B header + u32le + body offset 4
        self.assertEqual(got[23:S2C_WIRES[0]], captured[23:],
                         "everything but the date is the capture's, byte for byte")
        self.assertNotEqual(got[S2C_WIRES[0]:],
                            b"".join(frame.build(frame.Link.CHANNEL_S2C, r.opcode,
                                                 _captured_body(r))
                                     for r in REPLIES if r.name != "CONNECT_ACK"),
                            "the sealed bodies must not be the capture's")
        stream = frame.FrameStream(frame.Link.CHANNEL_S2C)
        stream.feed(got)
        for f, r in zip(stream.frames()[1:], [x for x in REPLIES if x.name != "CONNECT_ACK"]):
            self.assertTrue(r.sealed)
            self.assertEqual(channel.unseal(f.body, "20270101"), r.plain,
                             f"{r.name} does not open under the token's day")

    def test_the_default_date_is_the_live_clock(self):
        from datetime import date
        self.assertEqual(channel._today(), date.today().strftime("%Y%m%d"))

    def test_the_directory_can_be_re_addressed_for_this_host(self):
        """The capture names the machine it was taken on; a server on another
        address must re-stamp it or the client dials the old box."""
        got, _ = _exchange(CHANNEL_C2S, advertise="10.0.0.7")
        stream = frame.FrameStream(frame.Link.CHANNEL_S2C)
        stream.feed(got)
        directory = next(f for f in stream.frames() if f.opcode.sub == 3)
        plain = channel.unseal(directory.body, FROZEN_DAY)
        self.assertIn(b"10.0.0.7".ljust(16, b"\0"), plain)
        self.assertNotIn(b"192.168.2.226", plain)
        self.assertEqual(plain, channel.with_advertise(
            next(r for r in REPLIES if r.name == "CHANNEL_ACK").plain, "10.0.0.7"))

    def test_without_an_address_the_capture_is_replayed_verbatim(self):
        got, _ = _exchange(CHANNEL_C2S)
        self.assertEqual(got, b"".join(
            frame.build(frame.Link.CHANNEL_S2C, r.opcode, _captured_body(r))
            for r in REPLIES))


class TestChannelLog(unittest.TestCase):
    def test_log_parses_with_the_reference_parser(self):
        _, text = _exchange(CHANNEL_C2S)
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "server-test.log"
            p.write_text(text, encoding="utf-8")
            recs = [r for r in logs.iter_packets(p) if r.hex is not None]
            kinds = [(r.direction, r.link, r.opcode) for r in recs]
            self.assertEqual(kinds, [("C->S", "channel", (0, 11)),
                                     ("S->C", "channel", None),
                                     ("C->S", "channel", (0, 9)),
                                     ("S->C", "channel", None),
                                     ("C->S", "channel", (0, 1)),
                                     ("S->C", "channel", None)])
            self.assertEqual([r.wire for r in recs],
                             [43, S2C_WIRES[0], 11, S2C_WIRES[1], 11, S2C_WIRES[2]])
            self.assertEqual([r.body_len for r in recs[:2]], [32, None])

    def test_dump_matches_the_reference_truncation_rule(self):
        _, text = _exchange(CHANNEL_C2S)
        line = next(ln for ln in text.splitlines()
                    if f"S->C channel raw={S2C_WIRES[1]}" in ln)
        dump = logs.find_hex_field(line, "hex")
        self.assertFalse(dump.truncated)
        self.assertEqual(len(dump.data), S2C_WIRES[1])


if __name__ == "__main__":
    unittest.main()
