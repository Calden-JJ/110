"""What the launcher says to the client, and what it refuses to say.

The passport is the whole endpoint mechanism (there is no endpoint memory
patch), so its golden value is pinned here twice: as a literal, and as the
`passport_sample` the reference's own self-test asserts.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.launcher import client, server
from uslocalserver.launcher.config import LauncherConfig

GOLDEN = ("99?127.0.0.1?7001?0?de509f65e9ccaae621cb7278fc2b8e6c?01?1?0?0?0?0?1?"
          "9n2b1c8r3w7y?0?0?19847")


class TestPassport(unittest.TestCase):
    def test_matches_the_reference_sample(self):
        self.assertEqual(client.build_passport("127.0.0.1", 7001), GOLDEN)
        data = client.launch_data()
        self.assertEqual(data.passport_template.format(address="127.0.0.1", port=7001),
                         GOLDEN)

    def test_launch_data_carries_the_sample_verbatim(self):
        raw = json.loads((paths.LAUNCHER_DATA_DIR / "launch-2.31.1.117.json")
                         .read_text(encoding="utf-8"))
        self.assertEqual(raw["launch"]["passport_sample"], GOLDEN)

    def test_only_address_and_port_change(self):
        got = client.build_passport("192.168.1.6", 49321)
        self.assertEqual(got, GOLDEN.replace("127.0.0.1", "192.168.1.6")
                         .replace("?7001?", "?49321?"))

    def test_address_must_be_canonical_ipv4(self):
        for bad in ("localhost", "::1", "127.1", "127.0.0.1:7001", " 127.0.0.1"):
            with self.subTest(bad=bad):
                with self.assertRaises(client.ClientError):
                    client.build_passport(bad, 7001)

    def test_port_must_be_in_range(self):
        for bad in (0, -1, 65536):
            with self.subTest(port=bad):
                with self.assertRaises(client.ClientError):
                    client.build_passport("127.0.0.1", bad)

    def test_unknown_version_has_no_data_file(self):
        with self.assertRaises(client.ClientError):
            client.launch_data("0.0.0.000")


class TestValidate(unittest.TestCase):
    def test_error_paths_without_the_real_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            with self.assertRaises(client.ClientError) as ctx:
                client.validate(d)
            self.assertIn("DFO.exe", str(ctx.exception))
            (d / "DFO.exe").write_bytes(b"MZ" + b"\0" * 100)
            with self.assertRaises(client.ClientError) as ctx:
                client.validate(d)
            self.assertIn("Script.pvf", str(ctx.exception))
            (d / "Script.pvf").write_bytes(b"\0")
            with self.assertRaises(client.ClientError) as ctx:
                client.validate(d)
            self.assertIn("版本不匹配", str(ctx.exception))

    @unittest.skipUnless(paths.CLIENT_EXE.exists(), "no client in this workspace")
    def test_the_real_client_passes(self):
        self.assertEqual(client.validate(paths.CLIENT_DIR), paths.CLIENT_EXE)
        self.assertEqual(client.validate(paths.CLIENT_DIR).stat().st_size,
                         client.launch_data().client_size)

    def test_running_client_refuses_and_a_missing_one_does_not(self):
        with mock.patch.object(client, "EXE_NAME", "python.exe"):
            with self.assertRaises(client.ClientError) as ctx:
                client.ensure_no_running_client()
            self.assertIn("请先关闭", str(ctx.exception))
        with mock.patch.object(client, "EXE_NAME", "no-such-exe-9f3a.exe"):
            self.assertIsNone(client.ensure_no_running_client())


class TestAdvertise(unittest.TestCase):
    def test_configured_address_wins(self):
        cfg = LauncherConfig(client_dir=paths.CLIENT_DIR, server_address="10.1.2.3")
        self.assertEqual(server.advertise_address(cfg), "10.1.2.3")

    def test_blank_falls_back_to_autodetect(self):
        cfg = LauncherConfig(client_dir=paths.CLIENT_DIR, server_address="")
        self.assertEqual(server.advertise_address(cfg), client.local_address())


if __name__ == "__main__":
    unittest.main()
