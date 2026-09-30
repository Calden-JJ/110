"""`logs.py` against the real lines, with the column trap pinned.

`test_frame.py` exercises this layer through the corpus, but only for `hex=`
and only on the one log that has hex dumps.  The three shapes of `plain=`
and the punctuation that trails them never reach that path, and they are what
M1's diff tool will be built on -- `plain=` is the only place the server
writes a *decrypted* body.
"""
from __future__ import annotations

import functools
import unittest

import _bootstrap  # noqa: F401
import _corpus

from uslocalserver import logs, paths


@functools.lru_cache(maxsize=1)
def fields() -> tuple[tuple[str, str, str], ...]:
    """`(key, raw token, shape)` for every `hex=`/`plain=` in the corpus."""
    _corpus.require()
    out = []
    import re
    for path in paths.corpus_logs():
        for ln in logs.stream(path):
            for m in re.finditer(r"(?<![\w=])(hex|plain)=([^\s]+)", ln.msg):
                f = logs.find_hex_field(ln.msg[m.start():], m.group(1))
                shape = ("length" if f.is_length
                         else "truncated" if f.truncated else "full")
                out.append((m.group(1), m.group(2), shape))
    return tuple(out)


class TheColumnLayout(unittest.TestCase):
    """`PACKET` is the tag, not the level -- a hand-written `split()` gets an
    empty opcode table and no error."""

    LINE = ("2026-09-26 22:16:32.032 +08:00 DEBUG PACKET     conn=1 C->S game "
            "(1,39) wire=13 body=0 state=Ready hex=010000000000000000")

    def test_the_line_regex_splits_where_the_table_says(self):
        m = logs.LINE.match(self.LINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "2026-09-26 22:16:32.032")
        self.assertEqual(m.group(2), "+08:00")
        self.assertEqual(m.group(3), "DEBUG")      # level
        self.assertEqual(m.group(4), "PACKET")     # tag
        self.assertTrue(m.group(5).startswith("conn=1"))

    def test_a_level_is_not_a_tag(self):
        # `DEBUG PACKET` and `WARN UNHANDLED` both put the interesting word
        # third; a `split()`-based reader would key on DEBUG / WARN and find
        # neither.  Two independent checks: the two sets must stay disjoint in
        # whatever logs are present (a narrow release may write neither tag,
        # so which tags exist is not asserted), and the shapes must parse.
        levels, tags = set(), set()
        for path in paths.server_logs():
            for ln in logs.stream(path):
                levels.add(ln.level)
                tags.add(ln.tag)
        self.assertTrue(levels, "no server logs to read")
        self.assertFalse(levels & tags)
        # The two shapes, parsed rather than globbed for.
        for level, tag in (("DEBUG", "PACKET"), ("WARN", "UNHANDLED"),
                           ("INFO", "LISTEN")):
            line = (f"2026-09-26 22:16:32.032 +08:00 {level} {tag:<12} "
                    f"conn=1 C->S game (1,39) wire=13 body=0 state=Ready")
            m = logs.LINE.match(line)
            self.assertIsNotNone(m, line)
            self.assertEqual((m.group(3), m.group(4)), (level, tag))

    def test_a_real_packet_line_yields_a_record(self):
        records = tuple(logs.iter_packets(_corpus.require()))
        self.assertTrue(records)
        r = records[0]
        self.assertIn(r.direction, ("C->S", "S->C"))
        self.assertIn(r.link, ("game", "channel"))
        self.assertIsInstance(r.line_no, int)


class HexFieldShapes(unittest.TestCase):
    def test_the_three_shapes_are_parseable_and_distinguished(self):
        counts = {"full": 0, "truncated": 0, "length": 0}
        for _key, _raw, shape in fields():
            counts[shape] += 1
        self.assertEqual(counts, {"full": 1522, "truncated": 70, "length": 69})

    def test_the_punctuation_after_a_dump_is_not_part_of_it(self):
        # The token runs to the next space, so it swallows whatever closes
        # the sentence: `(plain=412B)`, `plain=511B;`, `plain=<hex>,`.  All
        # three occur; before this was handled, 72 tokens failed to parse.
        cases = {
            "plain=412B)": ("length", 412, 0),
            "plain=511B;": ("length", 511, 0),
            "plain=1384B)": ("length", 1384, 0),
            "plain=0011,": ("full", None, 2),
            "plain=0011;": ("full", None, 2),
            "plain=0011)": ("full", None, 2),
        }
        for msg, (shape, declared, size) in cases.items():
            with self.subTest(msg=msg):
                f = logs.find_hex_field(msg, "plain")
                self.assertTrue(f.is_length if shape == "length" else not f.is_length)
                self.assertEqual(f.declared, declared)
                self.assertEqual(len(f.data), size)

    def test_a_truncated_dump_keeps_its_ellipsis_and_count(self):
        # `...(+304B)` ends in `)`, which the punctuation stripping must not
        # eat -- it parses on the first try, so stripping never runs.
        f = logs.find_hex_field("plain=0011...(+304B)", "plain")
        self.assertTrue(f.truncated)
        self.assertEqual(f.declared, 304)
        self.assertEqual(f.full_size, len(f.data) + 304)

    def test_a_nibble_survives_the_truncation_cut(self):
        # The 4096-byte cut lands mid-byte once; the odd nibble is dropped
        # rather than handed to `bytes.fromhex`.
        f = logs.find_hex_field("hex=0011223...(+9B)", "hex")
        self.assertEqual(f.data.hex(), "001122")
        self.assertEqual(f.full_size, 3 + 9)

    def test_every_dump_in_every_log_parses(self):
        # The count above is the measurement; this is the no-survivors check
        # behind it, and it is what was false before the fix.
        self.assertGreater(len(fields()), 1500)
        for key in ("hex", "plain"):
            for path in paths.server_logs():
                for ln in logs.stream(path):
                    if f"{key}=" not in ln.msg:
                        continue
                    with self.subTest(line=ln.line_no):
                        self.assertIsNotNone(logs.find_hex_field(ln.msg, key))

    def test_the_corpus_log_is_the_only_one_with_hex_dumps(self):
        # So a test that needs a whole frame has exactly one log to read.
        # Later logs are not part of the corpus and do carry dumps -- that is
        # the point of pinning the corpus rather than globbing the directory.
        _corpus.require()
        per_log = {}
        for path in paths.corpus_logs():
            per_log[path.name] = sum(
                1 for ln in logs.stream(path) if "hex=" in ln.msg)
        self.assertEqual({k: v for k, v in per_log.items() if v},
                         {"server-20260926.log": 288})


class OpcodeHelpers(unittest.TestCase):
    def test_seen_lists_are_read_whole(self):
        line = "seen=[(1,1), (1,2), (1,35), (1,36)]"
        self.assertEqual(logs.seen_opcodes(line), [(1, 1), (1, 2), (1, 35), (1, 36)])
        self.assertEqual(logs.seen_opcodes("no list here"), [])

    def test_response_arrows_are_read(self):
        self.assertEqual(logs.response_opcodes("ack -> (0,1) and -> (1,33)"),
                         [(0, 1), (1, 33)])
        self.assertEqual(logs.response_opcodes("plain -> nothing"), [])

    def test_a_coordinate_pair_is_not_an_opcode(self):
        # COMBAT-DIE-39 logs `cell=(1,0) boss=(3,0)`; a bare \((\d+),(\d+)\)
        # picks those up and pollutes the registry with main in {2,3,4,5}.
        records = tuple(logs.iter_packets(_corpus.require()))
        for r in records:
            if r.opcode is not None:
                with self.subTest(line=r.line_no):
                    self.assertIn(r.opcode[0], (0, 1))

    def test_the_tag_suffix_rule_only_proposes(self):
        self.assertEqual(logs.tag_suffix_opcode("DUNGEON-ENTER-16"), (1, 16))
        self.assertEqual(logs.tag_suffix_opcode("TOWN-MOVE-35"), (1, 35))
        self.assertIsNone(logs.tag_suffix_opcode("PACKET"))
        self.assertIsNone(logs.tag_suffix_opcode("LISTEN"))


if __name__ == "__main__":
    unittest.main()
