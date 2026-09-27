"""`launcher.json` round-trips, and the CLI overrides that sit on top of it.

`saveDb: "none"` is the interesting case: it has to clear the default, while a
missing key must leave it alone -- the window's 存档 field then behaves the
same way as the flag.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import _bootstrap  # noqa: F401

import uslocalserver.launcher.__main__ as launcher_main
from uslocalserver import paths
from uslocalserver.launcher import client
from uslocalserver.launcher.config import ConfigError, LauncherConfig, load, save


class TestConfigFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "launcher.json"

    def test_defaults(self):
        cfg = LauncherConfig.defaults()
        self.assertEqual(cfg.client_dir, paths.CLIENT_DIR)
        self.assertEqual(cfg.server_address, client.local_address())
        self.assertEqual(cfg.bind_host, "0.0.0.0")
        self.assertEqual(cfg.save_db, paths.SAVE_DB)
        self.assertFalse(cfg.quiet)

    def test_missing_file_gives_defaults(self):
        self.assertEqual(load(self.path), LauncherConfig.defaults())

    def test_round_trip(self):
        cfg = LauncherConfig(client_dir=Path("C:/game"), server_address="10.0.0.9",
                             bind_host="127.0.0.1", save_db=Path("C:/game/save.db"),
                             quiet=True)
        save(cfg, self.path)
        self.assertEqual(load(self.path), cfg)

    def test_save_writes_the_documented_keys(self):
        save(LauncherConfig.defaults(), self.path)
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(set(raw), {"clientDir", "serverAddress", "bindHost",
                                    "saveDb", "quiet"})
        self.assertIsInstance(raw["clientDir"], str)

    def test_none_clears_the_save_db_but_a_missing_key_keeps_it(self):
        save(replace(LauncherConfig.defaults(), save_db=None), self.path)
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8"))["saveDb"],
                         "none")
        self.assertIsNone(load(self.path).save_db)
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        del raw["saveDb"]
        self.path.write_text(json.dumps(raw), encoding="utf-8")
        self.assertEqual(load(self.path).save_db, paths.SAVE_DB)

    def test_bad_files_are_refused(self):
        self.path.write_text("{ not json", encoding="utf-8")
        with self.assertRaises(ConfigError) as ctx:
            load(self.path)
        self.assertIn("读不了配置文件", str(ctx.exception))
        self.path.write_text("[1, 2]", encoding="utf-8")
        with self.assertRaises(ConfigError) as ctx:
            load(self.path)
        self.assertIn("必须是一个 JSON 对象", str(ctx.exception))

    def test_overrides_ignore_none(self):
        cfg = LauncherConfig.defaults()
        self.assertEqual(cfg.with_overrides(server_address=None), cfg)
        self.assertEqual(cfg.with_overrides(server_address="1.1.1.1").server_address,
                         "1.1.1.1")


class TestCliOverrides(unittest.TestCase):
    def _cfg(self) -> LauncherConfig:
        return LauncherConfig(client_dir=Path("C:/game"), server_address="1.2.3.4",
                              save_db=Path("C:/game/save.db"))

    def _apply(self, *argv) -> LauncherConfig:
        return launcher_main.apply_overrides(self._cfg(), launcher_main.parse_args(argv))

    def test_no_flags_is_the_same_config(self):
        cfg = self._cfg()
        self.assertEqual(launcher_main.apply_overrides(
            cfg, launcher_main.parse_args([])), cfg)

    def test_field_overrides(self):
        cfg = self._apply("--client", "D:/other", "--address", "10.0.0.2",
                          "--host", "0.0.0.0", "--quiet")
        self.assertEqual(cfg.client_dir, Path("D:/other"))
        self.assertEqual(cfg.server_address, "10.0.0.2")
        self.assertEqual(cfg.bind_host, "0.0.0.0")
        self.assertTrue(cfg.quiet)
        self.assertEqual(cfg.save_db, Path("C:/game/save.db"))

    def test_save_none_clears_and_a_path_replaces(self):
        self.assertIsNone(self._apply("--save", "none").save_db)
        self.assertEqual(self._apply("--save", "D:/s.db").save_db, Path("D:/s.db"))

    def test_no_gui_is_a_flag(self):
        self.assertFalse(launcher_main.parse_args([]).no_gui)
        self.assertTrue(launcher_main.parse_args(["--no-gui"]).no_gui)


if __name__ == "__main__":
    unittest.main()
