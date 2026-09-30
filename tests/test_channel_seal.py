"""The channel bodies' day key: AES-128-ECB under `yyyyMMdd` + `000008`.

Three layers of evidence, weakest first: the cipher against the published
vectors, the key schedule against the seed the reference builds (exe 0x58d420
-> 0x58d660 -> 0x58d680), and the whole pipeline against a real capture --
`data/channel/replies.json` ships the SHA-256 of the ciphertext it was taken
from, so re-sealing the stored plaintext under the capture's own day has to
give those exact bytes back.
"""
from __future__ import annotations

import hashlib
import json
import unittest
import zlib

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.protocol.crypto import aes128_decrypt, aes128_encrypt
from uslocalserver.server import channel


class TestAesVectors(unittest.TestCase):
    """The tile set's `AES-128` is stock FIPS-197.

    Worth pinning here: four of the fourteen tiles are DFO variants of the
    RFC cipher (MISTY1-DFO, Blowfish-DFO, RC6-480-DFO, Rijndael12), so "the
    tile called AES-128" is not something to assume.
    """

    def test_fips_197_c1(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(aes128_encrypt(plain, key).hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes128_decrypt(bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
                                        key), plain)

    def test_sp_800_38a_ecb_aes128(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                              "ae2d8a571e03ac9c9eb76fac45af8e51")
        self.assertEqual(aes128_encrypt(plain, key).hex(),
                         "3ad77bb40d7a3660a89ecaf32466ef97"
                         "f5d3d58503b9699de785895a96fdbaaf")


class TestDayKey(unittest.TestCase):
    def test_the_key_is_the_token_padded_with_nuls(self):
        self.assertEqual(channel.day_key("20260929"), b"20260929000008\0\0")
        self.assertEqual(len(channel.day_key("20260929")), 16)

    def test_the_seed_connect_ack_ships_is_the_key(self):
        connect = next(r for r in channel.ChannelReplies.load() if r.name == "CONNECT_ACK")
        day = connect.plain[4:12].decode("ascii")
        self.assertEqual(connect.plain[12:18], channel.SEED_SUFFIX.encode("ascii"))
        self.assertEqual(connect.plain[4:20], channel.day_key(day),
                         "the 16 bytes the client is handed are the cipher key")


class TestSeal(unittest.TestCase):
    def test_round_trip_and_zero_padding(self):
        for n in (0, 1, 15, 16, 17, 484):
            content = (bytes(range(256)) * 2)[:n]
            body = channel.seal(content, "20260929")
            self.assertEqual(channel.unseal(body, "20260929"),
                             content + b"\0" * (-n % 16))

    def test_the_day_moves_the_bytes(self):
        content = b"x" * 32
        self.assertNotEqual(channel.seal(content, "20260929"),
                            channel.seal(content, "20260930"))

    def test_another_day_does_not_open_the_body(self):
        content = b"x" * 32
        body = channel.seal(content, "20260929")
        self.assertNotEqual(channel.unseal(body, "20260930"), content)


REPLIES_DOC = json.loads((paths.DATA_DIR / "channel" / "replies.json")
                         .read_text(encoding="utf-8"))
CAPTURE_DAY = REPLIES_DOC["day"]


class TestAdvertise(unittest.TestCase):
    """The directory names a host; serving a capture from another one points
    the client at a machine that is not this one (192.168.1.6 on 09-27,
    192.168.2.226 on 09-29 -- the same box after a DHCP move)."""

    PLAIN = bytes.fromhex(next(f for f in REPLIES_DOC["frames"]
                               if f["name"] == "CHANNEL_ACK")["plain_hex"])

    def test_every_record_is_restamped_and_nothing_else_moves(self):
        out = channel.with_advertise(self.PLAIN, "10.0.0.7")
        self.assertEqual(len(out), len(self.PLAIN))
        # walk the directory: 16B section name + u32 0 + u32le count, then
        # records of 16B "#ch.N" + u32 0 + u32le max + u32 0 + 16B address +
        # u32le gamePort
        fields, off = [], 4
        for _ in range(int.from_bytes(self.PLAIN[:4], "little")):
            off += 24
            channels = int.from_bytes(self.PLAIN[off - 4:off], "little")
            for _ in range(channels):
                fields.append((off + 28, off + 44))
                off += 48
        self.assertEqual(self.PLAIN[off:].strip(b"\0"), b"",
                         "the walk must land on the end (pad-to-16 tail aside)")
        self.assertEqual(len(fields), 9)
        moved = [i for i, (a, b) in enumerate(zip(out, self.PLAIN)) if a != b]
        self.assertTrue(moved, "the address must have moved the bytes")
        for i in moved:
            self.assertTrue(any(s <= i < e for s, e in fields),
                            f"byte {i} outside every address field")
        for s, e in fields:
            self.assertEqual(out[s:e].rstrip(b"\0"), b"10.0.0.7")
        self.assertNotIn(b"192.168.2.226", out)

    def test_a_body_that_is_not_the_directory_is_returned_untouched(self):
        script = bytes.fromhex(next(f for f in REPLIES_DOC["frames"]
                                    if f["name"] == "SCRIPT_ACK")["plain_hex"])
        self.assertEqual(channel.with_advertise(script, "10.0.0.7"), script)
        self.assertEqual(channel.with_advertise(b"", "10.0.0.7"), b"")
        for n in (4, 28, 300, 480):          # mid-header and mid-record cuts
            truncated = self.PLAIN[:n]
            self.assertEqual(channel.with_advertise(truncated, "10.0.0.7"), truncated,
                             f"{n}B: a truncated directory must come back untouched")
        # the tail is only the pad the sealer re-does, so it may be absent
        self.assertEqual(channel.with_advertise(self.PLAIN[:484], "10.0.0.7"),
                         channel.with_advertise(self.PLAIN, "10.0.0.7")[:484])

    def test_the_shipped_capture_names_the_capture_day_machine(self):
        # 09-29's reference answered on 192.168.2.226 (its START line says so);
        # today's box is 192.168.1.6, which is why the server re-stamps.
        self.assertIn(b"192.168.2.226", self.PLAIN)


class TestCaptureGolden(unittest.TestCase):
    """`replies.json` is a real capture's plaintext; the capture itself is gone.

    The extractor proves the pair on the way in -- re-sealing has to reproduce
    the captured ciphertext byte for byte or it refuses to write -- and stores
    the SHA-256 so that stays checkable afterwards, on any machine, with no
    reference server and no log.
    """

    def test_the_capture_reseals_byte_for_byte(self):
        sealed = [f for f in REPLIES_DOC["frames"] if f["sealed"]]
        self.assertEqual([f["name"] for f in sealed], ["SCRIPT_ACK", "CHANNEL_ACK"])
        for f in sealed:
            content = bytes.fromhex(f["plain_hex"])
            self.assertEqual(len(content) % 16, 0, f"{f['name']} is not whole blocks")
            self.assertEqual(hashlib.sha256(zlib.decompress(
                channel.seal(content, CAPTURE_DAY))).hexdigest(),
                f["cipher_sha256"], f["name"])

    def test_another_day_would_not_reproduce_it(self):
        other = "20270101" if CAPTURE_DAY != "20270101" else "20270102"
        for f in (x for x in REPLIES_DOC["frames"] if x["sealed"]):
            content = bytes.fromhex(f["plain_hex"])
            self.assertNotEqual(hashlib.sha256(zlib.decompress(
                channel.seal(content, other))).hexdigest(),
                f["cipher_sha256"], f"{f['name']}: the day must move the bytes")

    def test_plain_len_is_the_content_behind_the_padding(self):
        for f in REPLIES_DOC["frames"]:
            n = len(bytes.fromhex(f["plain_hex"]))
            self.assertGreaterEqual(n, f["plain_len"], f["name"])
            self.assertLess(n - f["plain_len"], 16, f["name"])

    def test_the_token_and_the_capture_day_agree(self):
        connect = next(f for f in REPLIES_DOC["frames"] if f["name"] == "CONNECT_ACK")
        self.assertEqual(bytes.fromhex(connect["plain_hex"])[4:12].decode("ascii"),
                         CAPTURE_DAY)


if __name__ == "__main__":
    unittest.main()
