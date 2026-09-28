"""`(1,309)` NPC-REDEEM: the empty `(0,292)` list, over a socket.

The whole behaviour is a constant, so the tests pin the constant and the
frame/lines around it: 129 corpus lines, all `answered with empty S292 list`,
the six dumped requests (09-27) all 13B of wire with a 0B body, each answered
`-> 1 frame(s) 32B`.
"""
from __future__ import annotations

import asyncio
import io
import unittest

import _bootstrap  # noqa: F401

from uslocalserver.game.shop import redeem
from uslocalserver.protocol import frame
from uslocalserver.protocol.crypto import tiles
from uslocalserver.server import game
from uslocalserver.server.logfile import Log


class ConstantsTest(unittest.TestCase):
    def test_opcodes_and_body(self):
        self.assertEqual(redeem.OPCODE.key(), (1, 309))
        self.assertEqual(redeem.REPLY_OPCODE.key(), (0, 292))
        self.assertEqual(redeem.REPLY_BODY, bytes(16))
        self.assertEqual(redeem.NOTE,
                         "answered with empty S292 list (buyback storage "
                         "not implemented)")


class SocketTest(unittest.TestCase):
    """No save attached: the handler reads no state, so it answers in M1 too."""

    def test_the_request_draws_the_16_zero_body_and_the_reference_lines(self):
        log = Log(stream=io.StringIO())
        server = game.GameServer("127.0.0.1", {10013: (0, 1, 10, "Bel Myre")},
                                 game.GameScript.load(), log,
                                 unix_seconds=1_789_824_022)

        async def run():
            await server.start()
            try:
                port = server.ports_bound()[0]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                await asyncio.wait_for(reader.read(65536), timeout=2.0)
                writer.write(frame.build(
                    frame.Link.GAME_C2S, redeem.OPCODE,
                    tiles.encrypt_body(tiles.algo_id(redeem.OPCODE.sub), b""),
                    seq=0))
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

        raw = asyncio.run(run())
        stream = frame.FrameStream(frame.Link.GAME_S2C)
        stream.feed(raw)
        f = stream.next_frame()
        self.assertIsNotNone(f)
        self.assertEqual(f.opcode.key(), (0, 292))
        self.assertEqual(tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body),
                         bytes(16))
        self.assertIsNone(stream.next_frame())
        text = log._fh.getvalue()
        self.assertIn("NPC-REDEEM-309 conn=1 answered with empty S292 list "
                      "(buyback storage not implemented)", text)
        self.assertIn("conn=1 (1,309) -> 1 frame(s) 32B", text)


if __name__ == "__main__":
    unittest.main()
