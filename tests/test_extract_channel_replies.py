"""The extractor's two decisions: where an exchange ends, and which block's
exchange gets shipped.

Both are silent when wrong -- the file looks fine, and the client drops without
a word right after the third ACK (measured 2026-09-27: a 57491-block body
against the rewrite's 7001-block server).
"""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

import extract_channel_replies as tool


def _f(line: int, direction: str, raw: int):
    """One `channel_frames()` tuple: (line, ts, conn, dir, hdr, body, trunc)."""
    return (line, "00:00:00.000", 1, direction, raw.to_bytes(2, "big"), b"", False)


WHOLE = [_f(1, "C->S", 0x000B), _f(2, "S->C", 0x7C0C),
         _f(3, "C->S", 0x0009), _f(4, "S->C", 0x7C0A),
         _f(5, "C->S", 0x0001), _f(6, "S->C", 0x7C03)]


class TestSplit(unittest.TestCase):
    def test_one_exchange_is_three_pairs(self):
        self.assertEqual([len(e) for e in tool.split_exchanges(WHOLE)], [6])

    def test_a_partial_session_does_not_swallow_the_next(self):
        frames = [_f(1, "C->S", 0x000B), _f(2, "S->C", 0x7C0C)] + WHOLE
        got = tool.split_exchanges(frames)
        self.assertEqual([len(e) for e in got], [2, 6])
        self.assertEqual(got[1][0][0], 1, "the second exchange starts at its own CONNECT")

    def test_frames_before_any_connect_are_dropped(self):
        self.assertEqual(tool.split_exchanges([_f(1, "S->C", 0x7C0C)]), [])


class TestBlock(unittest.TestCase):
    STARTS = [(10, 60652), (100, 7001), (200, 49321)]

    def test_the_block_is_the_last_start_before_the_exchange(self):
        self.assertEqual(tool.block_before(150, self.STARTS), 7001)
        self.assertEqual(tool.block_before(250, self.STARTS), 49321)

    def test_no_start_before_the_exchange(self):
        self.assertIsNone(tool.block_before(5, self.STARTS))


if __name__ == "__main__":
    unittest.main()
