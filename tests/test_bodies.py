"""`bodies/` against the logged request bodies.

The three opcodes modelled in M0 sit at three different levels of evidence,
and the tests are organised around that:

  * `(1,1592)` is **verified**.  `WARN UNHANDLED conn=N (1,1592) body=32B has
    no handler plain=<hex>` carries the whole body, and the three corpus logs
    hold 23 of those lines, all byte-identical.  Parsing one is M0's
    acceptance demo -- demo ① of the plan file.
  * `(1,16)` and `(1,33)` are **declared**.  The reference server names their
    fields in its own `INFO DUNGEON-ENTER-16 ... request=SelectDungeonRequest
    { DungeonId = 7114, ... }` lines, but no `hex=` or `plain=` dump of either
    body has ever been logged, so the widths are a reading of the field types.
    The *values* used below are real; the bytes are not, and the test says so.
"""
from __future__ import annotations

import functools
import re
import unittest

import _bootstrap  # noqa: F401

from uslocalserver import logs, paths
from uslocalserver.protocol import bodies
from uslocalserver.protocol.bodies import ClientEnvironment, LayoutUnverified
from uslocalserver.protocol.reader import BodyReader, TruncatedBody

#: The whole `(1,1592)` body, byte for byte, as the 23 log lines spell it:
#: u32le(19) "China Standard Time", u32le(4) "4,9,", one 0 byte.
ENVIRONMENT = "130000004368696E61205374616E646172642054696D6504000000342C392C00"

#: Distinct bodies seen across the three corpus logs.  The scan below runs
#: over every server log, so this is a floor: later reference runs add copies
#: of the same body, never a new one (all samples must still be byte-identical).
EXPECTED_SAMPLES = 23

#: `DungeonId` reaches 291100268 in one day's logs, so it is wider than u16 --
#: the entry can never narrow to the two bytes the opcode's neighbours use.
TWO_DECLARED = ((1, 16), (1, 33))


@functools.lru_cache(maxsize=1)
def unhandled_1592() -> tuple[tuple[int | None, bytes], ...]:
    """`(body=, plain=)` for every `UNHANDLED` line that dumped this body."""
    out = []
    for path in paths.server_logs():
        for ln in logs.stream(path):
            if ln.tag != "UNHANDLED" or "(1,1592)" not in ln.msg:
                continue
            field = logs.find_hex_field(ln.msg, "plain")
            if field is not None:
                declared = re.search(r"\bbody=(\d+)B", ln.msg)
                out.append((int(declared.group(1)) if declared else None, field.data))
    return tuple(out)


def encode_environment(*, timezone: str, list: str, trailing: int) -> bytes:
    """Serialise the verified layout the way the test expects to read it."""
    tz, lst = timezone.encode(), list.encode()
    return (len(tz).to_bytes(4, "little") + tz
            + len(lst).to_bytes(4, "little") + lst
            + bytes([trailing]))


class ClientEnvironmentVerified(unittest.TestCase):
    """`(1,1592)` -- the one body whose bytes are known."""

    def test_the_logged_body_parses(self):
        # M0 acceptance demo ①: a real body off the wire, decoded.
        body = unhandled_1592()[0][1]
        self.assertEqual(len(body), 32)
        self.assertEqual(
            bodies.parse_body((1, 1592), body),
            ClientEnvironment(timezone="China Standard Time", list="4,9,", trailing=0),
        )

    def test_every_logged_sample_is_the_same_body(self):
        # Nothing in this struct could be told apart by contrast if the
        # samples differed, so the agreement *is* the measurement.
        samples = unhandled_1592()
        self.assertGreaterEqual(len(samples), EXPECTED_SAMPLES)
        self.assertEqual({body for _, body in samples}, {bytes.fromhex(ENVIRONMENT)})

    def test_the_declared_length_agrees_with_every_dump(self):
        # `body=32B` is the server's own count of the body; the dump has to
        # match it, or plain= is missing a chunk and the layout is a guess
        # about a prefix.
        for declared, body in unhandled_1592():
            with self.subTest(declared=declared):
                self.assertEqual(declared, len(body))

    def test_the_round_trip_reproduces_the_logged_bytes(self):
        # `parse_body` calls `expect_eof`, so a layout with slack could still
        # pass above -- this is the assertion that pins both boundaries.
        decoded = bodies.parse_body((1, 1592), bytes.fromhex(ENVIRONMENT))
        self.assertEqual(
            encode_environment(timezone=decoded.timezone, list=decoded.list,
                               trailing=decoded.trailing),
            bytes.fromhex(ENVIRONMENT),
        )

    def test_a_short_body_is_an_error_not_a_short_read(self):
        for cut in (0, 4, 8, 22, 31):
            with self.subTest(cut=cut):
                with self.assertRaises(TruncatedBody):
                    bodies.parse_body((1, 1592), bytes.fromhex(ENVIRONMENT)[:cut])

    def test_a_long_body_is_an_error_too(self):
        # A trailing byte the layout does not account for means the layout is
        # wrong, not that the extra byte is padding.
        with self.assertRaises(ValueError):
            bodies.parse_body((1, 1592), bytes.fromhex(ENVIRONMENT) + b"\x00")


class DeclaredLayoutsAreGuarded(unittest.TestCase):
    """`(1,16)` and `(1,33)` -- field names known, wire bytes never seen."""

    def test_the_registry_says_which_is_which(self):
        self.assertTrue(bodies.REGISTRY[(1, 1592)].verified)
        self.assertEqual(
            sorted(op for op, spec in bodies.REGISTRY.items() if not spec.verified),
            list(TWO_DECLARED),
        )

    def test_no_capture_exists_for_either_declared_body(self):
        # The guard is only honest while this holds.  221 C->S game packets
        # carry a hex dump all day; neither opcode is among them, and no
        # 20-byte body appears anywhere.  If a capture ever shows up this
        # fails, and the entry gets promoted to verified instead.
        twenty = 0
        for path in paths.server_logs():
            for rec in logs.iter_packets(path):
                self.assertNotIn(rec.opcode, TWO_DECLARED)
                if rec.body_len == 20:
                    twenty += 1
        self.assertEqual(twenty, 0)

    def test_a_declared_body_is_refused_unless_asked_for(self):
        for opcode in TWO_DECLARED:
            with self.subTest(opcode=opcode):
                with self.assertRaises(LayoutUnverified) as caught:
                    bodies.parse_body(opcode, bytes(20))
                self.assertIn(str(opcode), str(caught.exception))
                self.assertIn("allow_declared=True", str(caught.exception))

    def test_select_dungeon_reads_the_reference_servers_field_order(self):
        # Values from `server-20260925.log:289`: request=SelectDungeonRequest
        # { DungeonId = 7114, Difficulty = 0, EntryOption = 0, Mode = 0,
        #   HellDifficulty = 0 }.  The bytes are the declared reading of that.
        parsed = bodies.parse_body((1, 16), (7114).to_bytes(4, "little") + bytes(16),
                                   allow_declared=True)
        self.assertEqual(parsed, bodies.SelectDungeonRequest(7114, 0, 0, 0, 0))

    def test_town_placement_reads_the_reference_servers_field_order(self):
        # From `server-20260925.log:735`: placement=TownPlacement
        # { TownId = 38, AreaId = 2, X = 254, Y = 249, State = 4 }.
        raw = b"".join(v.to_bytes(4, "little") for v in (38, 2, 254, 249, 4))
        parsed = bodies.parse_body((1, 33), raw, allow_declared=True)
        self.assertEqual(parsed, bodies.TownPlacement(38, 2, 254, 249, 4))

    def test_the_lines_those_values_came_from_are_real(self):
        # Otherwise the two fixtures above are just numbers agreeing with
        # themselves.  These two spellings occur in the logs, on those lines.
        wanted = {
            "SelectDungeonRequest { DungeonId = 7114, Difficulty = 0, "
            "EntryOption = 0, Mode = 0, HellDifficulty = 0 }",
            "TownPlacement { TownId = 38, AreaId = 2, X = 254, Y = 249, State = 4 }",
        }
        found = set()
        for path in paths.server_logs():
            for ln in logs.stream(path):
                for text in wanted:
                    if text in ln.msg:
                        found.add(text)
        self.assertEqual(found, wanted)


class RegistryShape(unittest.TestCase):
    """Every entry, whichever side of the guard it is on."""

    #: Smallest body each layout can be satisfied by: two empty strings and a
    #: 0 byte for the verified one, five zero u32s for the two declared ones.
    MINIMAL_BODY = {
        (1, 1592): bytes(9),
        (1, 16): bytes(20),
        (1, 33): bytes(20),
    }

    def test_an_unmodelled_opcode_is_a_key_error(self):
        with self.assertRaises(KeyError):
            bodies.parse_body((1, 9999), bytes(20))
        with self.assertRaises(KeyError):
            bodies.parse_body((9, 1592), bytes(20))

    def test_every_entry_is_named_and_describes_itself(self):
        for opcode, spec in bodies.REGISTRY.items():
            with self.subTest(opcode=opcode):
                self.assertIn("u32le", spec.layout)
                self.assertTrue(spec.doc, "an entry has to say what it is for")
                # `from __future__ import annotations` keeps these as strings.
                self.assertEqual(spec.parse.__annotations__["return"],
                                 spec.body.__name__)

    def test_the_sizes_above_cover_the_registry(self):
        # A fourth entry arriving without a minimal body would otherwise make
        # the next test silently vacuous.
        self.assertEqual(set(self.MINIMAL_BODY), set(bodies.REGISTRY))

    def test_each_parser_consumes_its_body_exactly(self):
        # The layout string's byte count and the code have to agree, or a body
        # arrives with bytes the parser never looked at.
        for opcode, spec in bodies.REGISTRY.items():
            body = self.MINIMAL_BODY[opcode]
            with self.subTest(opcode=opcode):
                r = BodyReader(body)
                self.assertEqual(spec.parse(r), spec.parse(BodyReader(body)))
                self.assertTrue(r.eof)
                with self.assertRaises(ValueError):
                    spec.parse(BodyReader(body + b"\x00"))


if __name__ == "__main__":
    unittest.main()
