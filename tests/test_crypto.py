"""The cipher suite, after it moved from `tools/` into the package.

A move like this has one failure mode worth a test: the module still imports,
but finds no key tables, or the probes that drove it stop working.  So the
assertions are the two things that were true before the move and must stay
true after it --

  * `tools/verify_gold.py`, untouched, still decrypts every gold pair, and
  * the two zero-block vectors in the capture still come out of the two
    ciphers that produced them.

The third leg is `SELFTEST`: the round-trip the file used to run only as
`__main__` now runs here, so a primitive broken by an edit is caught by the
suite and not only by whoever remembers to run the script.
"""
from __future__ import annotations

import re
import subprocess
import sys
import unittest
from collections import Counter

import _bootstrap  # noqa: F401
import _corpus

from uslocalserver import paths
from uslocalserver.protocol import crypto

#: `tools/probe_oracle.py` hunts these through every binary as fixed vectors;
#: they are in the capture too, as whole packets whose plain body is zeros.
#: C->S `(1,390)` is algo 12 = DFO-16B; S->C is algo 2 = RC6-480-DFO.  Both
#: keys are slices of `data/crypto/channelinfo_key_blob.bin`.
C2S_ZERO = "d8542ae1bbeac96b9ccf9ac12d501244"
S2C_ZERO = "829bec98e3808b1e704ed8de024a5852"

VERIFY_GOLD = paths.TOOLS_DIR / "verify_gold.py"
# `OK` rows pad the name to three spaces and `FAIL` rows to one, so the gap
# after the verdict is `\s+` and not a literal space -- and one name contains
# a space (`Custom 8B`), so the name runs to the optional `(alt)` marker.
SUMMARY = re.compile(r"^\s+algo\s+(\d+):\s+(\d+) (OK|FAIL)\s+(.+?)(\s+\(alt\))?\s*$",
                     re.M | re.I)

#: `verify_gold.py`'s own summary, pinned (algo, verdict, name, is-alternate).
#: Algo ids 4, 8 and 11 (AES-128, XTEA-LE, Khazad-like) are absent because
#: that day's capture holds no gold pair for them -- an absence of evidence,
#: not a failure.
EXPECTED_GOLD = Counter({
    (0, "OK", "XTEA-BE", False): 1, (1, "OK", "CAST-128", False): 1,
    (2, "OK", "RC6-480-DFO", False): 1, (3, "OK", "Twofish256", False): 1,
    (5, "OK", "Skipjack", False): 2, (6, "OK", "MISTY1-DFO", False): 2,
    (7, "OK", "Blowfish-DFO", False): 1, (9, "OK", "DFO-Rijndael12", False): 1,
    (10, "OK", "XOR-32", False): 1, (12, "OK", "DFO-16B", False): 7,
    (13, "OK", "Custom 8B", False): 1,
    # The alternates are deliberate comparisons, kept in the script so that
    # the stock algorithm failing is a listed result, not a silent swap.
    (2, "FAIL", "stock", True): 1, (6, "FAIL", "stock", True): 2,
    (7, "FAIL", "stock", True): 1,
})

MISSING_ALGOS = (4, 8, 11)


def key_slice(off: int, length: int) -> bytes:
    blob = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()
    return blob[off:off + length]


class ZeroBlockVectors(unittest.TestCase):
    """Two 16-byte ciphertexts whose plaintext is all zeros, both logged."""

    def test_the_c2s_vector_is_dfo16_under_its_own_key(self):
        self.assertEqual(crypto.dfo16_encrypt(bytes(16), key_slice(278, 16)).hex(),
                         C2S_ZERO)

    def test_the_s2c_vector_is_rc6_under_a_different_key(self):
        self.assertEqual(crypto.rc6_dfo_encrypt(bytes(16), key_slice(32, 60)).hex(),
                         S2C_ZERO)

    def test_the_two_vectors_are_not_the_same_cipher(self):
        # Both are 16 zero bytes off the same key blob.  That they differ is
        # what makes them two data points rather than one -- and neither is a
        # typo of the other, because RC6 under a third 60-byte slice of the
        # same blob is a third value still.
        self.assertNotEqual(C2S_ZERO, S2C_ZERO)
        self.assertNotIn(crypto.rc6_dfo_encrypt(bytes(16), key_slice(92, 60)).hex(),
                         (C2S_ZERO, S2C_ZERO))

    def test_the_two_unresolved_tiles_are_xtea(self):
        # AlgoId 0 and 8 were the last two slots.  What settled them: an
        # 8-byte block repeating inside S->C `(1,848)` is XTEA-LE off tile 8,
        # and the tail of C->S `(1,1302)` is XTEA-BE off tile 0 -- the frame
        # whose recorded oracle plaintext the BE decrypt reproduces exactly.
        self.assertEqual(
            crypto.xtea_be_encrypt(bytes(8), key_slice(0, 16)).hex(),
            "94c6b7441a8ee699")
        self.assertEqual(
            crypto.xtea_le_encrypt(bytes(8), key_slice(222, 16)).hex(),
            "a7c02233e5721520")

    def test_the_two_xtea_endiannesses_are_genuinely_different(self):
        # Same cipher, same 8 zero bytes, two key slices -- so the two vectors
        # being distinct is what makes endianness a real degree of freedom
        # rather than a flag nobody can observe.
        self.assertNotEqual(
            crypto.xtea_le_encrypt(bytes(8), key_slice(0, 16)).hex(),
            "94c6b7441a8ee699")

    def test_the_zero_vectors_are_in_the_capture(self):
        # Otherwise the constants above are just strings agreeing with a
        # function that could have been written to return them.
        text = _corpus.require().read_text(
            encoding="utf-8-sig", errors="replace")
        self.assertIn(C2S_ZERO, text)
        self.assertIn(S2C_ZERO, text)
        self.assertIn("94c6b7441a8ee699", text)
        self.assertIn("a7c02233e5721520", text)


class SelfTest(unittest.TestCase):
    def test_every_primitive_round_trips(self):
        self.assertEqual(crypto.selftest(), 0)

    def test_the_selftest_table_covers_the_suite(self):
        # 15 primitives over 14 key slices: the RFC MISTY1 and the DFO variant
        # are two implementations of one slot, which is why the table has to
        # name both offsets rather than assume one per cipher.
        offsets = [off for _, _, _, off, _, _ in crypto.SELFTEST]
        self.assertEqual(len(offsets), 15)
        self.assertEqual(sum(o == 150 for o in offsets), 2)

    def test_the_selftest_slices_are_exactly_the_14_algo_tiles(self):
        # The whole `AlgoId = sub % 14` rule is only usable if the key blob's
        # tile starts are the offsets the ciphers were validated at; if these
        # two ever drift apart, every decryption picks up the wrong key.
        spans = [(0, 16), (16, 32), (32, 92), (92, 124), (124, 140), (140, 150),
                 (150, 166), (166, 222), (222, 238), (238, 254), (254, 262),
                 (262, 278), (278, 294), (294, 334)]
        blob = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()
        self.assertEqual(blob[294:334], blob[294:])   # 334B, no slack
        used = sorted({off for _, _, _, off, _, _ in crypto.SELFTEST})
        self.assertEqual(used, [start for start, _ in spans])

    def test_the_ecb_helper_only_passes_whole_blocks_through(self):
        # The server's shared validator 0x5843b0 rejects a partial block, so
        # a tail must come back untouched rather than partly encrypted.
        data = bytes(range(8)) + b"\xde\xad\xbe"
        out = crypto.ecb_encrypt(crypto.dfo16_encrypt, data, key_slice(278, 16), 16)
        self.assertEqual(out[8:], data[8:])


class VerifyGoldStillRuns(unittest.TestCase):
    """The untouched script is the regression; these pin its verdict.

    `verify_gold.py` decrypts the 0.3.6 capture with each of the 14 tiles, so
    without that log it has nothing to say -- skip rather than assert on an
    empty summary.
    """

    @classmethod
    def setUpClass(cls):
        if not VERIFY_GOLD.is_file():
            raise unittest.SkipTest(f"no {VERIFY_GOLD}")
        _corpus.require()
        cls.proc = subprocess.run([sys.executable, str(VERIFY_GOLD)],
                                  capture_output=True, text=True)

    def test_it_exits_zero(self):
        self.assertEqual(self.proc.returncode, 0,
                         self.proc.stdout[-2000:] + self.proc.stderr[-2000:])

    def gold_summary(self) -> Counter:
        out = Counter()
        for algo, count, verdict, name, alt in SUMMARY.findall(self.proc.stdout):
            out[(int(algo), verdict.upper(), name, bool(alt))] += int(count)
        return out

    def test_the_summary_is_the_one_measured_before_the_move(self):
        self.assertEqual(self.gold_summary(), EXPECTED_GOLD)
        self.assertEqual(sum(c for k, c in EXPECTED_GOLD.items() if k[1] == "OK"), 19)

    def test_three_algos_have_no_gold_pair_and_that_is_why_they_are_absent(self):
        algos = {k[0] for k in self.gold_summary()}
        for algo in MISSING_ALGOS:
            self.assertNotIn(algo, algos)
        # ... and those three are the only gap: 0..13 accounted for.
        self.assertEqual(sorted(algos | set(MISSING_ALGOS)), list(range(14)))

    def test_no_primary_cipher_fails(self):
        # The primary of each algo is the one the server actually uses; the
        # alternates are named `stock` and are allowed to fail.
        primary = {k for k in EXPECTED_GOLD if not k[3]}
        self.assertTrue(primary)
        for key in primary:
            self.assertEqual(key[1], "OK", f"algo {key[0]} {key[2]}")


class TheShimKeepsTheProbesWorking(unittest.TestCase):
    def test_importing_dfo_ciphers_from_tools_yields_the_package(self):
        # `tools/` is on sys.path via _bootstrap, so this is the same import
        # the probes do -- and they use private names too, hence no __all__.
        import dfo_ciphers
        self.assertIs(dfo_ciphers.dfo16_encrypt, crypto.dfo16_encrypt)
        self.assertEqual(dfo_ciphers.TAB, paths.CRYPTO_TABLES)
        self.assertTrue(dfo_ciphers.selftest() == 0)

    def test_the_script_still_self_tests_from_the_command_line(self):
        proc = subprocess.run([sys.executable, str(paths.TOOLS_DIR / "dfo_ciphers.py")],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout[-2000:] + proc.stderr[-2000:])
        self.assertEqual(proc.stdout.count("roundtrip=yes"), 15)
        self.assertNotIn("BAD", proc.stdout)


if __name__ == "__main__":
    unittest.main()
