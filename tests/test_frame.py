"""frame.py against the 288-frame reference capture.

Every count here is measured off server-20260926.log, not derived.  They are
pinned deliberately: the layer below (logs.py) and the layer above (opcode
registry) both depend on this decode being exactly right.
"""
from __future__ import annotations

import unittest
from collections import Counter, defaultdict

import _bootstrap  # noqa: F401
import _corpus

from uslocalserver.protocol import frame
from uslocalserver.protocol.frame import FrameStream, Link, Opcode, OpcodeEncoding


def link_of(record) -> Link:
    return Link(_corpus.link_of(record))


def parsed(record) -> frame.Frame:
    """Parse any corpus record; truncated dumps need the stated wire size."""
    return frame.parse(link_of(record), record.frame_bytes, expect_size=record.wire)


def by_link(name: str):
    """Every record of one link, truncated dumps included."""
    return tuple(p for p in _corpus.all_packets() if _corpus.link_of(p) == name)


def complete_of(name: str):
    return tuple(p for p in _corpus.complete_packets() if _corpus.link_of(p) == name)


class CorpusCoverage(unittest.TestCase):
    """logs.py has to recover all 288 records, 4 of them truncated."""

    def test_record_counts(self):
        self.assertEqual(len(_corpus.all_packets()), 288)
        self.assertEqual(len(_corpus.complete_packets()), 284)
        self.assertEqual(len(_corpus.truncated_packets()), 4)

    def test_per_link_breakdown(self):
        self.assertEqual(
            Counter(_corpus.link_of(p) for p in _corpus.complete_packets()),
            {"channel-c2s": 3, "channel-s2c": 3, "game-c2s": 221, "game-s2c": 57},
        )

    def test_truncated_records_declare_their_true_size(self):
        for rec in _corpus.truncated_packets():
            with self.subTest(line=rec.line_no):
                self.assertEqual(len(rec.frame_bytes), 4096)
                self.assertEqual(rec.hex.full_size, rec.wire)
                self.assertLess(len(rec.frame_bytes), rec.wire)


class ParseComplete(unittest.TestCase):
    def test_length_field_is_the_whole_frame(self):
        for rec in _corpus.complete_packets():
            with self.subTest(line=rec.line_no):
                f = parsed(rec)
                self.assertEqual(f.wire_size, len(rec.frame_bytes))
                self.assertEqual(f.frame_size, len(rec.frame_bytes))
                self.assertEqual(f.header + f.body, rec.frame_bytes)
                self.assertEqual(f.warnings, ())

    def test_build_roundtrips_byte_for_byte(self):
        for rec in _corpus.complete_packets():
            with self.subTest(line=rec.line_no):
                f = parsed(rec)
                self.assertEqual(
                    frame.build(f.link, f.opcode, f.body, trailer=f.trailer),
                    rec.frame_bytes,
                )

    def test_declared_size_waits_for_a_whole_header(self):
        self.assertIsNone(frame.declared_size(Link.GAME_S2C, b"\x00" * 15))
        self.assertEqual(frame.declared_size(Link.GAME_S2C, b"\x00" * 16), 0)


class ParseTruncated(unittest.TestCase):
    def test_strict_parse_rejects_a_short_dump(self):
        for rec in _corpus.truncated_packets():
            with self.subTest(line=rec.line_no):
                with self.assertRaises(frame.LengthMismatch):
                    frame.parse(link_of(rec), rec.frame_bytes)

    def test_expect_size_recovers_the_header(self):
        for rec in _corpus.truncated_packets():
            with self.subTest(line=rec.line_no):
                f = frame.parse(link_of(rec), rec.frame_bytes, expect_size=rec.wire)
                self.assertEqual(f.wire_size, rec.wire)
                self.assertEqual(f.frame_size, 4096)
                self.assertEqual(f.header, rec.frame_bytes[:f.header_len])
                self.assertEqual(f.warnings, ())


class GameS2CHeaderInvariants(unittest.TestCase):
    """61/61 measured S->C game frames obey all three rules."""

    def setUp(self):
        self.frames = [parsed(p) for p in by_link("game-s2c")]
        self.assertEqual(len(self.frames), 61)

    def test_final_header_byte_is_zero(self):
        for f in self.frames:
            self.assertEqual(f.header[15], 0x00)

    def test_byte_7_equals_byte_11(self):
        for f in self.frames:
            self.assertEqual(f.header[7], f.header[11])

    def test_only_the_leading_byte_of_each_word_is_shared(self):
        # NEGATIVE assertion.  An earlier pass generalised [7]==[11] into
        # [7:11] == [11:15]; it is false on all 61 frames, and this pins the
        # corrected conclusion so it cannot be un-learned.
        for f in self.frames:
            self.assertNotEqual(f.header[7:11], f.header[11:15])


class GameMainByte(unittest.TestCase):
    """`main` is a direction/response flag, not an opcode family."""

    def _c2s(self):
        return [parsed(p) for p in _corpus.packets_for("game", "C->S")]

    def _s2c(self):
        return [parsed(p) for p in by_link("game-s2c")]

    def test_c2s_main_is_always_one(self):
        self.assertEqual(Counter(f.opcode.main for f in self._c2s()), {1: 221})

    def test_s2c_main_splits_47_push_14_response(self):
        self.assertEqual(Counter(f.opcode.main for f in self._s2c()), {0: 47, 1: 14})

    def test_s2c_responses_echo_the_request_opcode(self):
        c2s_subs = {f.opcode.sub for f in self._c2s()}
        echoed = {f.opcode.sub for f in self._s2c() if f.opcode.main == 1}
        # (1,845) is the one sub with no c2s counterpart anywhere in the capture.
        self.assertEqual(echoed - c2s_subs, {845})

    def test_each_echoed_response_follows_its_request(self):
        c2s = [(p.ts, parsed(p).opcode.sub) for p in _corpus.packets_for("game", "C->S")]
        for p in by_link("game-s2c"):
            f = parsed(p)
            if f.opcode.main != 1 or f.opcode.sub == 845:
                continue
            earlier = [ts for ts, sub in c2s if sub == f.opcode.sub and ts <= p.ts]
            self.assertTrue(earlier, f"line {p.line_no}: {f.opcode} has no earlier request")

    def test_s2c_push_opcodes_are_mostly_server_only(self):
        c2s_subs = {f.opcode.sub for f in self._c2s()}
        push_subs = {f.opcode.sub for f in self._s2c() if f.opcode.main == 0}
        self.assertEqual(len(push_subs), 28)
        self.assertEqual(push_subs & c2s_subs, {1, 2, 36, 1280})


class MeasuredFacts(unittest.TestCase):
    def test_channel_trailer_is_the_fixed_constant(self):
        recs = [p for p in _corpus.complete_packets()
                if _corpus.link_of(p).startswith("channel")]
        self.assertEqual(len(recs), 6)
        for rec in recs:
            self.assertEqual(parsed(rec).trailer, frame.CHANNEL_TRAILER)

    def test_game_c2s_seq_runs_zero_to_220_on_one_connection(self):
        seqs = defaultdict(list)
        for rec in _corpus.packets_for("game", "C->S"):
            f = parsed(rec)
            self.assertIsNotNone(f.seq)
            seqs[rec.conn].append(f.seq)
        self.assertEqual(dict(seqs), {2: list(range(221))})

    def test_seq_is_none_off_game_c2s(self):
        for rec in _corpus.complete_packets():
            if _corpus.link_of(rec) != "game-c2s":
                self.assertIsNone(parsed(rec).seq)


class OpcodeCodec(unittest.TestCase):
    def test_game_roundtrip(self):
        op = Opcode.from_game(b"\x01\x10\x00")
        self.assertEqual(op.key(), (1, 16))
        self.assertIs(op.encoding, OpcodeEncoding.U8_U16LE)
        self.assertTrue(op.main_is_semantic)
        self.assertEqual(op.to_bytes(), b"\x01\x10\x00")
        self.assertEqual(str(op), "(1,16)")

    def test_channel_roundtrip_keeps_main_non_semantic(self):
        # The 0x7c prefix on channel-s2c is unexplained, so that main must
        # never reach the game opcode namespace.
        op = Opcode.from_channel(b"\x7c\x03")
        self.assertEqual(op.key(), (0x7C, 3))
        self.assertIs(op.encoding, OpcodeEncoding.U16BE)
        self.assertFalse(op.main_is_semantic)
        self.assertEqual(op.to_bytes(), b"\x7c\x03")
        self.assertEqual(str(op), "(?124,3)")

    def test_corpus_channel_opcodes(self):
        c2s = sorted(parsed(p).opcode.key() for p in complete_of("channel-c2s"))
        s2c = sorted(parsed(p).opcode.key() for p in complete_of("channel-s2c"))
        self.assertEqual(c2s, [(0, 1), (0, 9), (0, 11)])
        self.assertEqual(s2c, [(0x7C, 3), (0x7C, 10), (0x7C, 12)])


class Build(unittest.TestCase):
    def test_game_c2s_default_trailer_carries_the_seq(self):
        blob = frame.build(Link.GAME_C2S, Opcode(1, 16, OpcodeEncoding.U8_U16LE),
                           b"\xaa\xbb", seq=0x1234)
        self.assertEqual(len(blob), 15)
        self.assertEqual(blob[:3], b"\x01\x10\x00")
        self.assertEqual(int.from_bytes(blob[3:7], "little"), 15)
        self.assertEqual(blob[11:13], b"\x34\x12")
        self.assertEqual(frame.parse(Link.GAME_C2S, blob).seq, 0x1234)

    def test_game_s2c_trailer_is_derived_from_the_body(self):
        # It is not a constant and it is not nine zero bytes (0/61 measured
        # frames carry those): [7:11] is crc32(body) through `header_tag`.
        # Without a body there is no trailer to give, and a silent wrong one
        # would be a frame that cannot parse back.
        with self.assertRaises(frame.ProtocolError):
            frame.SPECS[Link.GAME_S2C].default_trailer()
        blob = frame.build(Link.GAME_S2C, Opcode(0, 5, OpcodeEncoding.U8_U16LE), b"\x01\x02")
        self.assertEqual(len(blob), 18)
        self.assertEqual(blob[7], blob[11])
        self.assertEqual(frame.parse(Link.GAME_S2C, blob).body, b"\x01\x02")

    def test_channel_default_trailer_is_the_constant(self):
        blob = frame.build(Link.CHANNEL_C2S, Opcode(0, 1, OpcodeEncoding.U16BE, False))
        self.assertEqual(blob, b"\x00\x01" + (11).to_bytes(4, "little") + frame.CHANNEL_TRAILER)

    def test_foreign_opcode_is_rejected(self):
        with self.assertRaises(frame.ForeignOpcode):
            frame.build(Link.CHANNEL_C2S, Opcode(1, 16, OpcodeEncoding.U8_U16LE))

    def test_trailer_length_is_enforced(self):
        with self.assertRaises(frame.ProtocolError):
            frame.build(Link.GAME_C2S, Opcode(1, 16, OpcodeEncoding.U8_U16LE), trailer=b"\x00")

    def test_non_strict_parse_collects_warnings(self):
        blob = bytearray(frame.build(Link.CHANNEL_S2C,
                                     Opcode(0x7C, 3, OpcodeEncoding.U16BE, False)))
        blob[10] = 0x00                      # last byte of the fixed trailer
        with self.assertRaises(frame.BadFixedTail):
            frame.parse(Link.CHANNEL_S2C, bytes(blob))
        f = frame.parse(Link.CHANNEL_S2C, bytes(blob), strict=False)
        self.assertEqual(len(f.warnings), 1)
        self.assertIn("trailer", f.warnings[0])

    def test_game_s2c_last_header_byte_is_fatal_when_set(self):
        blob = bytearray(frame.build(Link.GAME_S2C, Opcode(0, 5, OpcodeEncoding.U8_U16LE),
                                     b"\x01\x02"))
        blob[15] = 0x01
        with self.assertRaises(frame.BadGameTrailer):
            frame.parse(Link.GAME_S2C, bytes(blob))
        f = frame.parse(Link.GAME_S2C, bytes(blob), strict=False)
        self.assertEqual(len(f.warnings), 1)

    def test_try_parse_returns_none_instead_of_raising(self):
        self.assertIsNone(frame.try_parse(Link.GAME_C2S, b"\x01"))
        good = frame.build(Link.GAME_C2S, Opcode(1, 1, OpcodeEncoding.U8_U16LE))
        self.assertIsNotNone(frame.try_parse(Link.GAME_C2S, good))


class Stream(unittest.TestCase):
    LINKS = ("channel-c2s", "channel-s2c", "game-c2s", "game-s2c")

    def test_bulk_and_byte_dribble_agree(self):
        for name in self.LINKS:
            with self.subTest(link=name):
                recs = complete_of(name)
                blob = b"".join(r.frame_bytes for r in recs)
                bulk = FrameStream(Link(name))
                bulk.feed(blob)
                bulk_frames = bulk.frames()

                dribble = FrameStream(Link(name))
                dribble_frames = []
                for i in range(len(blob)):
                    dribble.feed(blob[i:i + 1])
                    dribble_frames.extend(dribble.frames())

                self.assertEqual(len(bulk_frames), len(recs))
                self.assertEqual([f.rebuild() for f in bulk_frames],
                                 [f.rebuild() for f in dribble_frames])
                self.assertEqual(bulk.pending, 0)
                self.assertEqual(dribble.pending, 0)

    def test_truncated_tail_stays_pending(self):
        opener = b"\x01\x10\x00" + (64).to_bytes(4, "little") + bytes(6) + bytes(10)
        s = FrameStream(Link.GAME_C2S)
        s.feed(opener)
        self.assertEqual(s.frames(), [])
        self.assertEqual(s.pending, len(opener))

    def test_declared_below_header_len_poisons(self):
        s = FrameStream(Link.GAME_C2S)
        s.feed(b"\x01\x10\x00" + (5).to_bytes(4, "little") + bytes(6))
        with self.assertRaises(frame.LengthMismatch):
            s.next_frame()
        self.assertTrue(s.poisoned)
        with self.assertRaises(frame.ProtocolError):
            s.feed(b"")
        with self.assertRaises(frame.ProtocolError):
            s.next_frame()

    def test_declared_above_the_body_cap_poisons(self):
        s = FrameStream(Link.GAME_C2S, max_body=100)
        s.feed(b"\x01\x10\x00" + (114).to_bytes(4, "little") + bytes(6))
        with self.assertRaises(frame.FrameTooLarge):
            s.next_frame()
        self.assertTrue(s.poisoned)

    def test_buffer_overflow_poisons(self):
        s = FrameStream(Link.GAME_S2C, max_buffer=32)
        with self.assertRaises(frame.FrameTooLarge):
            s.feed(bytes(33))
        self.assertTrue(s.poisoned)

    def test_reset_clears_poison_and_buffer(self):
        s = FrameStream(Link.GAME_C2S)
        s.feed(b"\x01\x10\x00" + (5).to_bytes(4, "little") + bytes(6))
        with self.assertRaises(frame.LengthMismatch):
            s.next_frame()
        s.reset()
        self.assertFalse(s.poisoned)
        self.assertEqual(s.pending, 0)

    def test_a_game_s2c_frame_may_start_with_zero(self):
        # Why the link can never be auto-detected from the stream.
        self.assertTrue(any(r.frame_bytes[0] == 0x00 for r in complete_of("game-s2c")))


if __name__ == "__main__":
    unittest.main()
