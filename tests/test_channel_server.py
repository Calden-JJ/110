"""End-to-end test of the channel server: replay the capture at it.

The captured channel session is the only ground truth for this link, so the
test drives the real socket with the three C->S frames exactly as the client
sent them and demands the three S->C frames back byte for byte.

The log is checked too: `tools/diff_packets.py` is what tells M1 apart from
"it seemed to work", and it reads the log rather than the wire.
"""
from __future__ import annotations

import asyncio
import io
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

#: Wire sizes derived, not pinned: the two zlib bodies are keyed by day and
#: `replies.json` is refreshed from the day's own reference run, so literals
#: here would have to be re-edited on every refresh (see the extractor).
S2C_WIRES = [frame.header_len(frame.Link.CHANNEL_S2C) + len(r.body) for r in REPLIES]

#: CONNECT_ACK's date is the one body byte the server picks for itself: the
#: reference read `DateTime.Now` (the 09-26 capture says 20260926; a replay of
#: the same build the next day answered 20260927).  Pin the replay to the day
#: the capture records, or the byte-for-byte comparison is comparing clocks.
FROZEN_DAY = CONNECT_ACK.body[4:12].decode("ascii")


def _exchange(payloads, *, host="127.0.0.1", write_gap=0.0, today=FROZEN_DAY):
    """Start the server, send every payload as one write, return what came back."""
    async def run():
        log = channel.Log(stream=io.StringIO())
        server = channel.ChannelServer(host, 0, channel.ChannelReplies.load(), log,
                                       write_gap=write_gap, today=today)
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
            frame.build(frame.Link.CHANNEL_S2C, r.opcode, r.body)
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
                         [len(r.body) for r in REPLIES])
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
        """
        async def run():
            log = channel.Log(stream=io.StringIO())
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
                t2 = asyncio.get_running_loop().time()
                await asyncio.wait_for(reader.readexactly(S2C_WIRES[2]), timeout=2.0)
                gap = asyncio.get_running_loop().time() - t2
                writer.close()
            finally:
                server.close()
            return gap

        gap = asyncio.run(run())
        self.assertGreaterEqual(gap, 0.005, f"SCRIPT_ACK -> CHANNEL_ACK gap collapsed to {gap*1000:.2f}ms")

    def test_unknown_opcode_gets_no_reply(self):
        junk = bytes.fromhex("00ff0b0000000000000001")
        got, text = _exchange([CHANNEL_C2S[0], junk])
        self.assertIn("unknown channel message (0,255)", text)
        self.assertEqual(len(got), S2C_WIRES[0], "only CONNECT_ACK should have come back")

    def test_only_the_connect_ack_date_moves_with_the_clock(self):
        """The reference reads `DateTime.Now` into CONNECT_ACK's date field; a
        replay of the same build the next day answered `20260927`.  Everything
        else in the 36B body is the capture's, byte for byte."""
        got, _ = _exchange(CHANNEL_C2S, today="20270101")
        captured = frame.build(frame.Link.CHANNEL_S2C, CONNECT_ACK.opcode, CONNECT_ACK.body)
        self.assertEqual(got[:15], captured[:15])
        self.assertEqual(got[15:23], b"20270101")   # 11B header + u32le + body offset 4
        self.assertEqual(got[23:S2C_WIRES[0]], captured[23:])
        rest = b"".join(frame.build(frame.Link.CHANNEL_S2C, r.opcode, r.body)
                        for r in REPLIES if r.name != "CONNECT_ACK")
        self.assertEqual(got[S2C_WIRES[0]:], rest, "only CONNECT_ACK is generated")

    def test_the_default_date_is_the_live_clock(self):
        from datetime import date
        self.assertEqual(channel._today(), date.today().strftime("%Y%m%d"))


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
