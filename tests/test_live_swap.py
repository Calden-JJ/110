"""The live-swap watchdog's testable halves: which line is an announcement, how
new lines are pulled out of the newest reference log, and how the fresh
directory is asked for before the reference is killed.

`take()` itself talks to taskkill and real ports, so it is exercised live, not
here.  The probe runs against a real socket too, but one this file starts and
owns: our own channel server stands in for the reference.
"""
from __future__ import annotations

import asyncio
import io
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _bootstrap  # noqa: F401

import live_swap

from uslocalserver.protocol import frame
from uslocalserver.server import channel

#: Verbatim from `server-20260927.log` -- the 13:22:40 launch, the block the
#: client followed.
REAL_START = (
    "2026-09-27 13:22:40.269 +08:00 INFO  START      bind=192.168.1.6 "
    "advertise=192.168.1.6 channel=49321 game=[49322, 49323, 49324, 49325, "
    "49326, 49327, 49328, 49329] login_ok_port=7200 "
    "write_gap=channel:12ms/game:5ms"
)


class TestParseStart(unittest.TestCase):
    def test_reads_the_reference_line(self):
        self.assertEqual(live_swap.parse_start(REAL_START),
                         ("192.168.1.6", 49321, list(range(49322, 49330))))

    def test_reads_the_default_block(self):
        line = ("2026-09-27 12:57:20.578 +08:00 INFO  START      "
                "bind=192.168.1.6 advertise=192.168.1.6 channel=7001 "
                "game=[10011, 10012, 10013, 10017, 10018, 10019, 10020, 10021] "
                "login_ok_port=7200 write_gap=channel:12ms/game:5ms")
        self.assertEqual(live_swap.parse_start(line),
                         ("192.168.1.6", 7001,
                          [10011, 10012, 10013, 10017, 10018, 10019, 10020, 10021]))

    def test_ignores_every_other_line(self):
        for line in (
            "2026-09-27 12:57:20.578 +08:00 INFO  LISTEN     game bound on "
            "192.168.1.6:10013 spec=game-c2s(header=13B, length@3:u32le)",
            "2026-09-27 13:22:41.001 +08:00 DEBUG PACKET     conn=1 C->S game "
            "(1,1554) wire=24 body=11 hex=000000000000000000000000",
            "",
        ):
            self.assertIsNone(live_swap.parse_start(line), line)


class TestLogTail(unittest.TestCase):
    def _armed(self, d: Path) -> live_swap.LogTail:
        tail = live_swap.LogTail(d)
        self.assertEqual(tail.skip_to_end(), sorted(d.glob("server-*.log"))[-1])
        return tail

    def test_attach_skips_to_eof_then_new_lines_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            p = d / "server-20260927.log"
            p.write_text(REAL_START + "\n", encoding="utf-8", newline="\n")
            tail = self._armed(d)
            self.assertEqual(tail.poll(), [], "history predates the swap")
            with p.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write("second\nthird\n")
            self.assertEqual(tail.poll(), ["second", "third"])
            self.assertEqual(tail.poll(), [])

    def test_a_partial_line_waits_for_its_newline(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            p = d / "server-20260927.log"
            p.write_text("", encoding="utf-8", newline="\n")
            tail = self._armed(d)
            with p.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write("half a li")
            self.assertEqual(tail.poll(), [])
            with p.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write("ne\n")
            self.assertEqual(tail.poll(), ["half a line"])

    def test_the_day_roll_starts_a_new_file_from_the_top(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server-20260927.log").write_text("old\n", encoding="utf-8",
                                                   newline="\n")
            tail = self._armed(d)
            (d / "server-20260928.log").write_text(REAL_START + "\n",
                                                   encoding="utf-8", newline="\n")
            self.assertEqual(tail.poll(), [REAL_START])


REPLIES = channel.ChannelReplies.load()
CONNECT_ACK = next(r for r in REPLIES if r.name == "CONNECT_ACK")

#: CONNECT_ACK's date is the one body byte a server picks for itself, so both
#: sides of a byte-for-byte comparison must pin the same day.
FROZEN_DAY = CONNECT_ACK.body[4:12].decode("ascii")


def _probe_frames() -> list[bytes]:
    return [frame.build(frame.Link.CHANNEL_C2S, live_swap._op(*req), body)
            for req, _reply, _name, body in live_swap.PROBE]


class TestProbeRequests(unittest.TestCase):
    def test_the_replayed_requests_are_the_captured_ones(self):
        """Verbatim from the reference log's C->S dumps (server-20260927.log;
        the same three, byte for byte, in every session of 09-26/09-27).
        test_channel_server.py drives the server with the same blobs."""
        self.assertEqual([f.hex() for f in _probe_frames()], [
            "000b2b0000000000000001f2f7f142f7dea0499f6bf6129fe6184fb76651"
            "875835f147e7940427c0d0aca3",
            "00090b0000000000000001",
            "00010b0000000000000001",
        ])


class TestProbeReplies(unittest.TestCase):
    """The capture half: replay the three requests at a live server, keep the
    three bodies it answers with, serve them to the client instead."""

    @staticmethod
    def _stand_in(log: live_swap.Log, today: str | None) -> channel.ChannelServer:
        """Our own channel server in the reference's role, on a free port."""
        return channel.ChannelServer("127.0.0.1", 0, REPLIES, log, write_gap=0.0,
                                     today=today)

    async def _exchange(self, port: int) -> bytes:
        """Send the three requests, read the three frames back."""
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        stream = frame.FrameStream(frame.Link.CHANNEL_S2C)
        got = b""
        try:
            for raw in _probe_frames():
                writer.write(raw)
            await writer.drain()
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=2.0)
                if not chunk:
                    break
                got += chunk
                stream.feed(chunk)
                if sum(1 for _ in iter(stream.next_frame, None)) >= 3:
                    break
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return got

    def test_captures_the_three_bodies_before_the_kill(self):
        buf = io.StringIO()
        log = live_swap.Log(stream=buf)

        async def run():
            ref = self._stand_in(log, FROZEN_DAY)
            await ref.start()
            try:
                return await live_swap.probe_replies(
                    "127.0.0.1", ref.sockets[0].getsockname()[1], log)
            finally:
                ref.close()

        captured = asyncio.run(run())
        self.assertIsNotNone(captured)
        by_name = {r.name: r for r in captured}
        self.assertEqual(sorted(by_name),
                         ["CHANNEL_ACK", "CONNECT_ACK", "SCRIPT_ACK"])
        for reply in REPLIES:
            self.assertEqual(by_name[reply.name].body, reply.body, reply.name)
            self.assertEqual(by_name[reply.name].opcode, reply.opcode, reply.name)
        self.assertIn("handed over CONNECT_ACK", buf.getvalue())

    def test_the_capture_serves_the_client_like_the_reference_did(self):
        """The bytes the client gets from the captured replies must equal the
        bytes the reference's own replies produce -- per server instance, not
        per connection, which is the assumption the whole takeover rests on."""
        async def run():
            log = live_swap.Log(stream=io.StringIO())
            ref = self._stand_in(log, FROZEN_DAY)
            await ref.start()
            try:
                captured = await live_swap.probe_replies(
                    "127.0.0.1", ref.sockets[0].getsockname()[1], log)
                want = await self._exchange(ref.sockets[0].getsockname()[1])
                swap = channel.ChannelServer(
                    "127.0.0.1", 0, captured, log, write_gap=0.0, today=FROZEN_DAY)
                await swap.start()
                try:
                    got = await self._exchange(swap.sockets[0].getsockname()[1])
                finally:
                    swap.close()
            finally:
                ref.close()
            return got, want

        got, want = asyncio.run(run())
        self.assertEqual(len(want), sum(frame.header_len(frame.Link.CHANNEL_S2C)
                                        + len(r.body) for r in REPLIES))
        self.assertEqual(got, want)

    def test_a_dead_reference_is_a_warning_not_a_crash(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        buf = io.StringIO()
        self.assertIsNone(asyncio.run(live_swap.probe_replies(
            "127.0.0.1", port, live_swap.Log(stream=buf))))
        self.assertIn("cannot reach 127.0.0.1", buf.getvalue())

    def test_a_silent_reference_times_out(self):
        async def run():
            async def silent(reader, writer):
                try:
                    await asyncio.sleep(30)
                finally:
                    writer.close()
            srv = await asyncio.start_server(silent, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            try:
                with mock.patch.object(live_swap, "PROBE_TIMEOUT", 0.2):
                    return await live_swap.probe_replies(
                        "127.0.0.1", port, live_swap.Log(stream=io.StringIO()))
            finally:
                srv.close()
                await srv.wait_closed()

        self.assertIsNone(asyncio.run(run()))

    def test_a_reference_answering_the_wrong_frames_is_refused(self):
        """A capture that does not look like the exchange must not be served:
        the client would take the endpoints it carries and drop silently."""
        async def run():
            async def wrong(reader, writer):
                await reader.read(4096)          # the probe's three requests
                writer.write(frame.build(frame.Link.CHANNEL_S2C,
                                         live_swap._op(124, 3), b"\x00" * 8))
                await writer.drain()
                writer.close()
            srv = await asyncio.start_server(wrong, "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            try:
                return await live_swap.probe_replies(
                    "127.0.0.1", port, live_swap.Log(stream=io.StringIO()))
            finally:
                srv.close()
                await srv.wait_closed()

        self.assertIsNone(asyncio.run(run()))


if __name__ == "__main__":
    unittest.main()
