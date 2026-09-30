"""The 0.4.4 log is hashed, not lost -- and the relay join is what makes it useful.

0.4.4 ships with the readable diagnostics compiled out; `server-*.log` holds
`event=<12 hex>` and nothing else.  Two facts make that workable again, and
both are pinned here: the digest is `sha256(label)[:12]` of the literal the
0.3.6 build printed (so the exe's own string table is the dictionary), and a
relay capture carries the same millisecond clock (so an event can be attributed
to the frame that caused it).

The digest constants below are observed, not derived -- they are what the live
2026-09-30 session log actually contains.
"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import _bootstrap  # noqa: F401

from ref044 import decode_events044 as D
from ref044 import join_capture as J
from uslocalserver import paths

#: (label, digest) as they appear in a real 0.4.4 session log.
OBSERVED = [
    ("UNHANDLED", "DFA486E77ACE"),
    ("STUN", "A437C0C98DE2"),
    ("HANDLER-ERR", "9B661375353F"),
]

SAMPLE_LOG = "﻿" + "\n".join([
    "2026-09-30 17:57:04.082 +08:00 WARN  EVENT      conn=2 event=DFA486E77ACE",
    "2026-09-30 17:57:04.141 +08:00 WARN  EVENT      event=A437C0C98DE2",
    "2026-09-30 18:28:11.027 +08:00 ERROR EVENT      conn=2 event=9B661375353F",
    "",
    "2026-09-30 18:28:12.000 +08:00 INFO  MIGRATE    local store ready",
])

CONN_LOG = "\n".join([
    "=== conn2 port=10011 peer=('127.0.0.1', 51757) at 18:32:09",
    "  (0,1) CHANNELINFO server=1 channel=1 host='127.0.0.2' blob=334B == static",
    "18:32:09.671 S2C (0,1) wire=526 body=510 plain=fa01",
    "18:32:09.672 C2S (1,318) wire=21 body=8 plain=9acc24163de1eb4f",
    "18:32:14.000 C2S GAP 12B dropped (resync)",
    "=== conn2 closed after 4.0s frames=2 relayed=21+526B",
])


def _event(label: str, ts: str, conn: int | None = 2) -> D.Event:
    return D.Event(ts, "WARN", "EVENT", conn, D.event_digest(label), label)


def _frames(lines: list[str], conn: int = 2) -> list[J.Frame]:
    return [f for f in (J.parse_frame_line(line, conn) for line in lines)
            if f is not None]


def _write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


class DigestTest(unittest.TestCase):
    def test_the_live_digests_are_sha256_of_the_bare_label(self) -> None:
        for label, digest in OBSERVED:
            self.assertEqual(digest, D.event_digest(label), label)

    def test_the_dictionary_reads_the_labels_out_of_the_exe(self) -> None:
        exe = paths.ACTIVE.exe
        if not exe.exists():
            self.skipTest(f"no reference exe at {exe}")
        dictionary = D.build_dictionary(exe)
        for label, digest in OBSERVED:
            self.assertEqual(label, dictionary.get(digest))
        self.assertGreater(len(dictionary), 1000)

    def test_field_order_and_spacing_do_not_matter(self) -> None:
        line = ("2026-09-30 17:57:04.082 +08:00 WARN  EVENT      "
                "event=dfa486e77ace conn=7")
        event = D.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(7, event.conn)
        self.assertEqual("DFA486E77ACE", event.digest, "digest normalises to upper")
        self.assertAlmostEqual(4.082, event.seconds % 60, places=3)
        self.assertEqual("2026-09-30", event.date)

    def test_non_event_lines_are_ignored(self) -> None:
        for line in ("", "   ", "2026-09-30 18:28:12.000 +08:00 INFO  MIGRATE  ok",
                     "2026-09-30 18:28:12.000 +08:00 INFO  EVENT conn=1"):
            self.assertIsNone(D.parse_line(line), line)


class DecodeCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.log = _write(Path(self._dir.name), "server-20260930.log", SAMPLE_LOG)

    def test_counts_by_label_and_writes_json(self) -> None:
        out = Path(self._dir.name) / "counts.json"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = D.main(["decode", str(self.log), "--json", str(out)])
        self.assertEqual(0, code)
        counts = json.loads(out.read_text(encoding="utf-8"))[str(self.log)]
        self.assertEqual({"UNHANDLED": 1, "STUN": 1, "HANDLER-ERR": 1}, counts)
        self.assertIn("levels: {'WARN': 2, 'ERROR': 1}", buf.getvalue())

    def test_a_digest_outside_the_dictionary_keeps_its_raw_form(self) -> None:
        path = _write(Path(self._dir.name), "server-20260101.log",
                      "2026-01-01 00:00:00.000 +08:00 WARN  EVENT      event=0000000000FF")
        buf = io.StringIO()
        with redirect_stdout(buf):
            D.main(["--exe", str(Path(self._dir.name) / "nope.exe"),
                    "decode", str(path)])
        self.assertIn("?0000000000FF", buf.getvalue())
        self.assertIn("unknown digest", buf.getvalue())


class FrameParsingTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = _write(Path(self._dir.name), "conn2.log", CONN_LOG)

    def test_only_frame_lines_become_frames(self) -> None:
        frames = J.read_frames(self.path)
        self.assertEqual(2, len(frames))
        self.assertEqual(2, frames[0].conn)
        self.assertEqual(("S2C", "(0,1)"), (frames[0].direction, frames[0].key))
        self.assertAlmostEqual(9.672, frames[1].seconds % 60, places=3)
        self.assertEqual("(1,318)", frames[1].key)

    def test_capture_date_comes_from_the_stamp_directory(self) -> None:
        self.assertEqual("2026-09-30",
                         J.capture_dir_date(Path("Logs-capture/20260930-183150")))
        self.assertIsNone(J.capture_dir_date(Path("Logs-capture/not-a-stamp")))


class MarkTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.capture = Path(self._dir.name)
        self.frames = _frames([
            "18:32:09.600 C2S (1,310) wire=21 body=8 plain=9acc",
            "18:32:11.000 C2S (1,311) wire=21 body=8 plain=9acc",
        ])

    def test_no_marks_file_means_one_whole_session_block(self) -> None:
        self.assertEqual([], J.read_marks(self.capture))
        blocks = J.split_blocks(self.frames, [])
        self.assertEqual(1, len(blocks))
        self.assertEqual(2, len(blocks[0][1]))

    def test_marks_cut_the_stream_into_gameplay_blocks(self) -> None:
        _write(self.capture, "marks.log",
               "18:32:09.000  login\n18:32:10.500  shop buy\n")
        blocks = J.split_blocks(self.frames, J.read_marks(self.capture))
        self.assertEqual([("18:32:09.000  login", 1),
                          ("18:32:10.500  shop buy", 1)],
                         [(label, len(block)) for label, block in blocks])

    def test_a_mark_past_the_last_frame_still_opens_a_block(self) -> None:
        blocks = J.split_blocks(self.frames, [("18:33:00.000", "logging out")])
        self.assertEqual([("(before the first mark)", 2),
                          ("18:33:00.000  logging out", 0)],
                         [(label, len(block)) for label, block in blocks])


class AttributeTest(unittest.TestCase):
    def test_an_event_lands_on_the_c2s_frame_that_triggered_it(self) -> None:
        frames = _frames(["18:32:09.672 C2S (1,318) wire=21 body=8 plain=9acc"])
        joined, unmatched = J.attribute(
            frames, [_event("UNHANDLED", "2026-09-30 18:32:09.674")], 0.150)
        self.assertEqual([], unmatched)
        self.assertEqual(("UNHANDLED",), joined[0].labels, "direct match, no ~")
        self.assertIn("# UNHANDLED", joined[0].annotated())

    def test_the_same_connection_number_wins_a_tie(self) -> None:
        frames = _frames(["18:32:09.672 C2S (1,318) wire=21 body=8 plain=9acc"], conn=2)
        frames += _frames(["18:32:09.672 C2S (1,319) wire=21 body=8 plain=9acc"], conn=1)
        joined, _ = J.attribute(
            frames, [_event("STUN", "2026-09-30 18:32:09.672", conn=1)], 0.150)
        self.assertEqual((), joined[0].labels, "the conn=2 frame stays clean")
        self.assertEqual(("STUN",), joined[1].labels)

    def test_the_clock_beats_the_connection_number(self) -> None:
        # The relay numbers connections from 1 per run, the server for its
        # whole lifetime, so a shared number is a coincidence -- never let it
        # pull an event off the frame that is closer in time.
        frames = _frames(["18:32:09.672 C2S (1,318) wire=21 body=8 plain=9acc"], conn=2)
        frames += _frames(["18:32:09.700 C2S (1,319) wire=21 body=8 plain=9acc"], conn=9)
        joined, _ = J.attribute(
            frames, [_event("STUN", "2026-09-30 18:32:09.701", conn=2)], 0.150)
        self.assertEqual(("~STUN",), joined[1].labels, "closest wins despite the conn")
        self.assertEqual((), joined[0].labels)

    def test_an_event_far_from_every_frame_stays_unmatched(self) -> None:
        frames = _frames(["18:32:09.672 C2S (1,318) wire=21 body=8 plain=9acc"])
        joined, unmatched = J.attribute(
            frames, [_event("UNHANDLED", "2026-09-30 18:32:40.000")], 0.150)
        self.assertEqual(1, len(unmatched))
        self.assertEqual((), joined[0].labels)

    def test_an_s2c_match_is_marked_inferred(self) -> None:
        frames = _frames(["18:32:09.671 S2C (0,1) wire=526 body=510 plain=fa01"])
        joined, _ = J.attribute(
            frames, [_event("UNHANDLED", "2026-09-30 18:32:09.700")], 0.150)
        self.assertEqual(("~UNHANDLED",), joined[0].labels)

    def test_two_events_can_share_one_frame(self) -> None:
        frames = _frames(["18:32:09.672 C2S (1,318) wire=21 body=8 plain=9acc"])
        joined, _ = J.attribute(frames, [
            _event("UNHANDLED", "2026-09-30 18:32:09.674"),
            _event("STUN", "2026-09-30 18:32:09.676"),
        ], 0.150)
        self.assertEqual(("UNHANDLED", "STUN"), joined[0].labels)

    def test_the_census_counts_labels_per_opcode(self) -> None:
        frames = _frames(["18:32:09.672 C2S (1,318) wire=21 body=8 plain=9acc"])
        joined, _ = J.attribute(frames, [
            _event("UNHANDLED", "2026-09-30 18:32:09.672"),
            _event("UNHANDLED", "2026-09-30 18:32:09.674"),
        ], 0.150)
        counts = J.census(joined)
        self.assertEqual(2, counts[("C2S", "(1,318)", "UNHANDLED")])


if __name__ == "__main__":
    unittest.main()
