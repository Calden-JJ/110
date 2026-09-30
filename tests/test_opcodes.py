"""The opcode registry: reproducible, and free of the log's opcode-shaped traps.

The counts below are measured from server-2026091{9,25,26}.log.  They are
pinned so that a widened or narrowed scan cannot pass unnoticed -- which also
means the module is unverifiable without that exact capture set, so it skips as
a whole when the 0.3.6 logs are not on disk rather than re-pinning against a
different release's log.
"""
from __future__ import annotations

import functools
import re
import unittest

import _bootstrap  # noqa: F401
import _corpus

import gen_opcodes
from uslocalserver import logs, paths
from uslocalserver.protocol import opcodes

_bootstrap.require_pinned_corpus()     # every count here is that capture's

LOGS = paths.corpus_logs()
BARE_PAIR = re.compile(r"\((\d+),(\d+)\)")
ANCHORED_PAIR = re.compile(r"conn=\d+\s+\((\d+),(\d+)\)")

EXPECTED_GAME = 184
EXPECTED_CHANNEL = 6
EXPECTED_NAMED = 63
EXPECTED_DISPATCHED = 13
EXPECTED_UNHANDLED = 48
EXPECTED_BY_DIRECTION = {"c2s": 149, "s2c": 49}
EXPECTED_BY_EVIDENCE = {"channel": 6, "dispatch": 13, "packet-c2s": 35,
                        "packet-s2c": 40, "response": 9, "seen": 149,
                        "tagged": 2, "unhandled": 48}
EXPECTED_CHANNEL_KEYS = {0x0001, 0x0009, 0x000B, 0x7C03, 0x7C0A, 0x7C0C}


@functools.lru_cache(maxsize=1)
def all_lines():
    return tuple(ln for p in LOGS for ln in logs.stream(p))


def lines_tagged(tag: str):
    return [ln for ln in all_lines() if ln.tag == tag]


class Regeneration(unittest.TestCase):
    def test_output_is_reproducible_byte_for_byte(self):
        payload = gen_opcodes.build_payload(LOGS)
        self.assertEqual(gen_opcodes.render(payload),
                         paths.OPCODES_JSON.read_text(encoding="utf-8"))

    def test_logs_scanned_match_the_committed_record(self):
        self.assertEqual([p.name for p in LOGS],
                         list(opcodes.load().logs))


class Baselines(unittest.TestCase):
    def setUp(self):
        self.reg = opcodes.default_registry()
        self.census = self.reg.census()

    def test_census(self):
        self.assertEqual(self.census.game, EXPECTED_GAME)
        self.assertEqual(self.census.channel, EXPECTED_CHANNEL)
        self.assertEqual(self.census.named, EXPECTED_NAMED)
        self.assertEqual(self.census.dispatched, EXPECTED_DISPATCHED)
        self.assertEqual(self.census.unhandled, EXPECTED_UNHANDLED)
        self.assertEqual(self.census.game - self.census.dispatched - self.census.unhandled,
                         self.census.unknown)
        self.assertEqual(self.census.by_direction, EXPECTED_BY_DIRECTION)
        self.assertEqual(self.census.by_evidence, EXPECTED_BY_EVIDENCE)
        self.assertEqual(self.census.uncorroborated_tags, ("HOTKEY-440",))

    def test_every_record_carries_evidence(self):
        for rec in self.reg.game.values():
            self.assertTrue(rec.evidence, rec)
            self.assertTrue(rec.directions, rec)


class CoordinateTraps(unittest.TestCase):
    """Cell coordinates are parenthesised pairs too.  Three guards keep them out."""

    def setUp(self):
        self.reg = opcodes.default_registry()

    def test_naive_scanning_of_the_corpus_is_wildly_wrong(self):
        mains = {int(m) for ln in all_lines() for m, _ in BARE_PAIR.findall(ln.msg)}
        self.assertGreater(len(mains), 100)
        self.assertIn(2, mains)                      # (2,4) and friends
        self.assertNotIn(max(mains), {0, 1})         # up to 3547: map ids

    def test_dungeon_move_coordinates_yield_no_opcode(self):
        trap = [ln for ln in all_lines() if "(0,1) -> (2,4)" in ln.msg]
        self.assertTrue(trap)                        # the trap is really in the log
        self.assertIn(("2", "4"), BARE_PAIR.findall(trap[0].msg))
        self.assertNotIn((2, 4), self.reg.game)
        self.assertNotIn((2, 4), self.reg.channel)

    def test_portal_moves_put_coordinates_where_opcodes_sit(self):
        # `conn=19 (0,1) -> (2,4) named portal` -- anchored on `conn=`, so the
        # anchor alone does NOT save you; the generator's (?!-> \\() guard does.
        portal = lines_tagged("DCOD-PORTAL-MOVE")
        self.assertTrue(portal)
        pairs = {(int(m), int(s)) for ln in portal
                 for m, s in ANCHORED_PAIR.findall(ln.msg)}
        injected = {p for p in pairs if p[0] in (0, 1)}
        self.assertEqual(len(injected), 8)
        # Six of the eight happen to collide with real opcodes (so they would
        # silently inflate evidence); two are pure fabrications.
        self.assertEqual(injected - set(self.reg.game), {(0, 4), (1, 0)})
        self.assertNotIn("DCOD-PORTAL-MOVE", self.reg.tagged_tags)

    def test_cell_transitions_are_not_response_refs(self):
        # `(0,3) -> (0,2)` is a move; only `-> (0,29) 107B` is a response frame.
        moves = lines_tagged("DUNGEON-MOVE-45")
        self.assertTrue(moves)
        self.assertEqual({p for ln in moves
                          for p in gen_opcodes.RESPONSE_SHAPE.findall(ln.msg)},
                         {("0", "29")})

    def test_an_uncorroborated_tag_stays_out(self):
        # HOTKEY-440 is the only tag suffix with no other evidence for (1,440).
        self.assertNotIn((1, 440), self.reg.game)
        self.assertIn("HOTKEY-440", self.reg.uncorroborated_tags)


class Namespaces(unittest.TestCase):
    def setUp(self):
        self.reg = opcodes.default_registry()

    def test_game_main_is_never_anything_but_a_flag(self):
        self.assertEqual({r.main for r in self.reg.game.values()}, {0, 1})

    def test_channel_opcodes_are_keyed_by_their_raw_u16be(self):
        self.assertEqual(set(self.reg.channel), EXPECTED_CHANNEL_KEYS)
        for raw, rec in self.reg.channel.items():
            self.assertEqual((rec.main << 8) | rec.sub, raw)

    def test_the_0x7c_prefix_stays_out_of_the_game_namespace(self):
        self.assertEqual({r.main for raw, r in self.reg.channel.items() if raw & 0x7C00},
                         {0x7C})
        self.assertIsNone(self.reg.lookup(0x7C, 3))
        self.assertIsNone(opcodes.lookup(124, 3))
        rec = self.reg.channel_lookup(0x7C03)
        self.assertEqual((rec.main, rec.sub, rec.directions), (0x7C, 3, ("s2c",)))

    def test_channel_opcodes_have_no_names(self):
        for rec in self.reg.channel.values():
            self.assertIsNone(rec.name)


class Evidence(unittest.TestCase):
    def setUp(self):
        self.reg = opcodes.default_registry()

    def test_a_response_echoes_its_request_opcode(self):
        # The frame layer measured that s2c main=1 reuses the request opcode;
        # here both directions land on one registry entry, named by the tag.
        rec = self.reg.lookup(1, 37)
        self.assertEqual(rec.directions, ("c2s", "s2c"))
        self.assertEqual(rec.name, "DUNGEON-LOADED")
        self.assertEqual(rec.evidence["response"], 1279)
        self.assertEqual(rec.evidence["seen"], 11)

    def test_size_shaped_response_refs_are_collected_from_every_tag(self):
        # Regression: an early `continue` skipped this scan for most tags and
        # (0,30) -- a response push with no other evidence -- went missing.
        rec = self.reg.lookup(0, 30)
        self.assertEqual(rec.evidence, {"response": 1279})
        self.assertEqual(rec.directions, ("s2c",))
        self.assertIsNone(rec.name)

    def test_handled_reflects_dispatch_versus_unhandled(self):
        self.assertFalse(self.reg.lookup(1, 1592).handled)
        self.assertTrue(self.reg.lookup(1, 433).handled)
        self.assertIsNone(self.reg.lookup(0, 30).handled)

    def test_dispatch_records_its_response_frame_count(self):
        self.assertEqual(self.reg.lookup(1, 433).responses, {1: 3})

    def test_descriptive_tag_lines_are_evidence_too(self):
        quest = self.reg.lookup(0, 342)
        self.assertEqual(quest.logged_by, ("TOWN-QUEST-STATE",))
        self.assertIn("packet-s2c", quest.evidence)
        quick = self.reg.lookup(0, 376)
        self.assertEqual(quick.logged_by, ("TOWN-QUICKSLOT",))

    def test_a_suffix_shared_by_two_tags_keeps_both(self):
        rec = self.reg.lookup(1, 45)
        self.assertEqual(rec.named_by, ("DUNGEON-MOVE-45", "ISPINS-MOVE-45"))
        self.assertEqual(rec.name, "DUNGEON-MOVE")


class UnhandledList(unittest.TestCase):
    def test_queue_is_busiest_first(self):
        queue = opcodes.unhandled()
        self.assertEqual(len(queue), EXPECTED_UNHANDLED)
        self.assertTrue(all(r.handled is False for r in queue))
        self.assertEqual([r.hits for r in queue],
                         sorted((r.hits for r in queue), reverse=True))
        self.assertEqual(queue[0].key, (1, 2126))
        self.assertEqual(queue[0].hits, 3622)


if __name__ == "__main__":
    unittest.main()
