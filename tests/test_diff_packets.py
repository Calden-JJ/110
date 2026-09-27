"""`tools/diff_packets.py` -- the M1 comparison harness.

The tool's own self-test is that a log diffed against itself comes out empty;
if that ever stops holding, every future "the rewrite matches the reference"
claim is worthless.  The rest pins the two traps that produce *invented*
opcodes: cell transitions written where opcodes sit, and channel opcodes
leaking into the game namespace.
"""
from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401 (sys.path)
import _corpus

import diff_packets as D

#: Cells that DUNGEON-ENTER / DCOD-PORTAL-MOVE print as `conn=2 (a,b) -> (c,d)`.
#: `(1,3)` is deliberately absent -- a cell there collides with the real EXIT
#: opcode, which is why the arrow, not the value range, has to be the guard.
TRANSITION_CELLS = ("(2,4)", "(3,4)", "(2,2)", "(2,3)", "(3,2)", "(0,4)", "(1,0)")


class DigestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.digest = D.digest(_corpus.CORPUS_LOG)

    def test_every_packet_dump_parses(self):
        self.assertEqual(self.digest.packets, _corpus.EXPECTED_TOTAL)
        self.assertEqual(self.digest.bad, {})

    def test_truncated_frames_are_not_errors(self):
        # 4 dumps are cut at the logger's 4096B limit; `expect_size` is what
        # keeps them out of `bad` and out of `notes`.
        self.assertEqual(self.digest.notes, {})

    def test_truncated_bodies_report_the_size_they_claim(self):
        # A cut dump keeps 4080B of body -- 16 of its 4096 are header -- but
        # the frame's own length field says the body is bigger.  Measuring the
        # bytes on hand would report 4080 for three (0,13)s and one (0,2),
        # which is exactly how long this rewrite's replacements for them
        # currently are: the four short bodies would diff as identical.
        self.assertNotIn(4080, self.digest.stats["(0,13)"].body_sizes)
        self.assertNotIn(4080, self.digest.stats["(0,2)"].body_sizes)
        self.assertEqual(sorted(self.digest.stats["(0,13)"].body_sizes),
                         [8, 504, 1656, 3304, 4872, 5584, 12552])
        self.assertEqual(sorted(self.digest.stats["(0,2)"].body_sizes),
                         [1296, 1776, 4672])

    def test_busiest_opcode_is_the_m1_finding(self):
        self.assertEqual(self.digest.stats["(1,2126)"].frames, 162)

    def test_channel_opcodes_keep_their_own_namespace(self):
        keys = set(self.digest.stats)
        for raw in ("ch[0001]", "ch[0009]", "ch[000b]",
                    "ch[7c03]", "ch[7c0a]", "ch[7c0c]"):
            self.assertIn(raw, keys)
        # The 0x7c prefix is unexplained, not main==124.
        self.assertFalse([k for k in keys if k.startswith("(124,")])

    def test_coordinates_never_invent_a_frame_row(self):
        for cell in TRANSITION_CELLS:
            self.assertNotIn(cell, self.digest.stats, cell)


class BodyDiffTest(unittest.TestCase):
    """`--bodies`: the content behind the body sizes.

    A rewrite that sends the right *number* of the wrong bytes was invisible
    here before this existed -- every other check this tool makes sees sizes.
    """
    @classmethod
    def setUpClass(cls):
        cls.digest = D.digest(_corpus.CORPUS_LOG, bodies=True)

    def test_a_log_differs_from_itself_with_bodies_too(self):
        a = D.digest(_corpus.CORPUS_LOG, bodies=True)
        b = D.digest(_corpus.CORPUS_LOG, bodies=True)
        self.assertEqual(D.diff(a, b), [])

    def test_only_s2c_is_collected(self):
        # C->S bodies are the client's, not the server's, and the capture
        # prints their plaintext anyway.
        self.assertEqual(set(self.digest.bodies),
                         {k for k, st in self.digest.stats.items()
                          if "S->C" in st.directions})

    def test_the_channelinfo_body_decodes_as_channelinfo(self):
        # `(0,1)` is not one of the 14 tiles -- it is the pre-cipher
        # CHANNELINFO, and a diff that decrypted it with tile `sub % 14` would
        # compare noise on both sides and find it "equal".
        body = self.digest.bodies["(0,1)"][0]
        self.assertEqual(body.full_size, 511)
        self.assertEqual(int.from_bytes(body.plain[:4], "little"), 507)

    def test_a_truncated_dump_still_yields_its_prefix(self):
        # The 4 frames cut at the logger's 4096B cap: 4080B of body recover,
        # the length field still says 4872+.
        cut = [b for b in self.digest.bodies["(0,13)"] if b.truncated]
        self.assertEqual(len(cut), 3)
        for b in cut:
            self.assertEqual(b.size, 4080)
            self.assertGreater(b.full_size, 4080)

    def test_same_size_different_content_is_a_difference(self):
        # The flag's entire reason to exist: these two digests agree on every
        # opcode, count and size, and differ only in a byte of body.
        s = {"(1,4)": {"frames": 1, "sizes": {8: 1}}}
        a = _digest("ref", s)
        b = _digest("new", s)
        a.bodies["(1,4)"] = [_body(b"\x00\x00\x00\x00\x01\x02\x03\x04", "a")]
        b.bodies["(1,4)"] = [_body(b"\x00\x00\x00\x00\x01\xff\x03\x04", "b")]

        out = "\n".join(D.diff(a, b))
        self.assertIn("1/1 S->C bodies differ", out)
        self.assertIn("1B differ in 1 run(s) [0x005]", out)
        self.assertIn("first @0x5 02->ff", out)

    def test_body_count_change_is_reported_before_the_pairs_it_shifts(self):
        s = {"(0,23)": {"frames": 2, "sizes": {8: 2}}}
        a, b = _digest("ref", s), _digest("new", s)
        one = _body(b"\x00" * 8, "a")
        a.bodies["(0,23)"] = [one, one]
        b.bodies["(0,23)"] = [one]
        self.assertIn("body count 2 -> 1", "\n".join(D.diff(a, b)))

    def test_only_the_differences_are_listed(self):
        s = {"(0,23)": {"frames": 2, "sizes": {8: 2}}}
        a, b = _digest("ref", s), _digest("new", s)
        a.bodies["(0,23)"] = b.bodies["(0,23)"] = [_body(b"\x00" * 8, "a"),
                                                   _body(b"\x00" * 8, "a")]
        self.assertEqual(D.diff(a, b), [])


class DiffRunsTest(unittest.TestCase):
    def test_runs_merge_adjacent_offsets(self):
        self.assertEqual(D._diff_runs(b"\x00\x01\x02\x03", b"\x00\x09\x09\x03"),
                         [(1, 3)])

    def test_a_longer_side_is_a_run_to_its_end(self):
        self.assertEqual(D._diff_runs(b"ab", b"abc"), [(2, 3)])
        self.assertEqual(D._diff_runs(b"abc", b"ab"), [(2, 3)])


class SelfDiffTest(unittest.TestCase):
    def test_a_log_differs_from_itself_in_no_way(self):
        a = D.digest(_corpus.CORPUS_LOG)
        b = D.digest(_corpus.CORPUS_LOG)
        self.assertEqual(D.diff(a, b), [])

    def test_a_side_without_packet_dumps_says_so(self):
        a = D.Digest(label="ref", lines=10, packets=7)
        b = D.Digest(label="new", lines=10, packets=0)
        out = D.diff(a, b)
        self.assertTrue(any("no DEBUG PACKET dumps" in ln for ln in out))


class SessionScopeTest(unittest.TestCase):
    """`--session` is what makes a six-session capture comparable to a
    one-session replay.  Without it the five sessions nobody replayed read as
    a mountain of behavioural differences, and there is no threshold at which
    that noise stops hiding a real one."""

    def test_scoping_keeps_the_frames_and_drops_the_other_sessions(self):
        # The whole file holds one more thing the framing cannot see: the five
        # sessions logged with the packet dump off still write `-> N frame(s)`
        # prose, and counting that as this replay's behaviour is the noise
        # `--session` exists to remove.  (Their PACKET lines are absent
        # entirely, not hex-less, so `notes` is 0 either way.)
        whole = D.digest(_corpus.CORPUS_LOG)
        corpus = D.digest(_corpus.CORPUS_LOG, kinds=["channel", "game"])
        self.assertEqual(whole.packets, _corpus.EXPECTED_TOTAL)
        self.assertEqual(corpus.packets, whole.packets)
        self.assertLess(corpus.lines, whole.lines)
        self.assertNotEqual(corpus.resp_frames, whole.resp_frames)
        self.assertGreater(sum(whole.resp_frames.values()),
                           sum(corpus.resp_frames.values()))

    def test_an_unknown_kind_is_an_error_not_a_whole_file(self):
        # A typo must not quietly widen the comparison to everything: that
        # reads as a diff, not as a broken invocation.
        with self.assertRaises(SystemExit):
            D.spans(_corpus.CORPUS_LOG, ["dungeon"])


class RequestOpcodeTest(unittest.TestCase):
    def test_real_opcode_lines_resolve(self):
        self.assertEqual(D.request_opcode("EXIT conn=2 (1,3) rc=0"), "(1,3)")
        self.assertEqual(D.request_opcode("STATE conn=1 (0,13) bytes=8"), "(0,13)")

    def test_cell_transitions_are_not_opcodes(self):
        # DUNGEON-ENTER and DCOD-PORTAL-MOVE write cells exactly where an
        # opcode would sit, and `main in (0,1)` alone lets (0,4)/(1,0) past.
        for msg in ("DUNGEON-ENTER conn=2 (2,4) -> (0,1) named portal",
                    "DCOD-PORTAL-MOVE conn=2 (0,4) -> (1,3) named portal",
                    "DUNGEON-MOVE-45 conn=2 (0,3) -> (0,2) map=100003683"):
            self.assertIsNone(D.request_opcode(msg), msg)

    def test_lines_without_an_opcode_resolve_to_none(self):
        self.assertIsNone(D.request_opcode("DUNGEON-ENTER conn=2 key=1 dungeon=100002627"))


def _body(plain: bytes, tag: str) -> D.Body:
    """A synthetic body keyed the way `digest` keys real ones: by content."""
    return D.Body(size=len(plain), full_size=len(plain), digest=tag * 16,
                  truncated=False, opaque=False, plain=plain)


def _digest(label: str, stats: dict) -> D.Digest:
    d = D.Digest(label=label, lines=1,
                 packets=sum(s["frames"] for s in stats.values()))
    for key, spec in stats.items():
        st = D.Stat(frames=spec["frames"])
        st.body_sizes.update(spec.get("sizes", {}))
        d.stats[key] = st
    return d


class DiffTest(unittest.TestCase):
    def test_only_in_one_side(self):
        out = "\n".join(D.diff(_digest("ref", {"(1,35)": {"frames": 3}}),
                               _digest("new", {"(1,36)": {"frames": 3}})))
        self.assertIn("only in ref", out)
        self.assertIn("only in new", out)

    def test_body_size_change_is_a_difference(self):
        out = D.diff(_digest("ref", {"(1,35)": {"frames": 2, "sizes": {8: 2}}}),
                     _digest("new", {"(1,35)": {"frames": 2, "sizes": {8: 1, 16: 1}}}))
        self.assertTrue(any("body sizes" in ln for ln in out))

    def test_response_count_change_is_a_difference(self):
        a = D.Digest(label="ref", lines=1, packets=1)
        b = D.Digest(label="new", lines=1, packets=1)
        a.resp_frames[2] = 5
        b.resp_frames[2] = 7
        self.assertTrue(any("response frames" in ln for ln in D.diff(a, b)))

    def test_identical_digests_produce_nothing(self):
        s = {"(1,35)": {"frames": 2, "sizes": {8: 2}}}
        self.assertEqual(D.diff(_digest("ref", s), _digest("new", s)), [])


if __name__ == "__main__":
    unittest.main()
