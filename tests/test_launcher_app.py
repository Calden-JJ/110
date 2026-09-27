"""`Launcher`'s refusal paths and the log prose around them.

A real `start()` needs the 212 MB client and binds the fixed port block; what
is testable offline is everything before the first port is touched -- the
already-running guard, the missing-client funnel, the stop bookkeeping and the
verify step's two early exits.
"""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import _bootstrap  # noqa: F401

from uslocalserver.launcher import client, patches
from uslocalserver.launcher.app import Launcher, LaunchError, Run, run_headless
from uslocalserver.launcher.config import LauncherConfig


class _FakeProcess:
    def __init__(self, pid: int = 4242, alive: bool = True):
        self.pid = pid
        self._alive = alive
        self.closed = False

    def alive(self) -> bool:
        return self._alive

    def close(self) -> None:
        self.closed = True

    def terminate(self) -> None:
        self._alive = False


class _FakeServer:
    def __init__(self, running: bool = False):
        self._running = running
        self.stopped = False

    def is_running(self) -> bool:
        return self._running

    def stop(self) -> None:
        self.stopped = True


def _applied() -> patches.Applied:
    return patches.Applied(patches.Site("smoke", 0x2000, b"\x00", b"\x01"), 0x140002000)


class TestGuards(unittest.TestCase):
    def _launcher(self, **overrides):
        cfg = replace(LauncherConfig.defaults(), **overrides)
        lines: list[str] = []
        return Launcher(cfg, log=lines.append), lines

    def test_second_start_is_refused(self):
        launcher, _ = self._launcher()
        launcher.run = Run(_FakeProcess(), _FakeServer(), [])
        with self.assertRaises(LaunchError) as ctx:
            launcher.start()
        self.assertIn("已经在运行", str(ctx.exception))

    def test_a_missing_client_fails_before_ports_or_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            launcher, lines = self._launcher(client_dir=Path(tmp))
            with self.assertRaises(client.ClientError):
                launcher.start()
            self.assertTrue(any("校验客户端" in ln for ln in lines))

    def test_stop_closes_client_and_server_and_is_idempotent(self):
        launcher, _ = self._launcher()
        launcher.stop()
        proc, server = _FakeProcess(), _FakeServer()
        launcher.run = Run(proc, server, [])
        self.assertTrue(launcher.is_running())
        launcher.stop()
        self.assertTrue(proc.closed)
        self.assertTrue(server.stopped)
        self.assertIsNone(launcher.run)
        launcher.stop()

    def test_is_running_is_false_once_both_halves_are_gone(self):
        launcher, _ = self._launcher()
        launcher.run = Run(_FakeProcess(alive=False), _FakeServer(running=False), [])
        self.assertFalse(launcher.is_running())


class TestVerify(unittest.TestCase):
    def _launcher(self, alive: bool, applied: list[patches.Applied]):
        lines: list[str] = []
        launcher = Launcher(LauncherConfig.defaults(), log=lines.append)
        launcher.run = Run(_FakeProcess(alive=alive), _FakeServer(), applied)
        return launcher, lines

    def test_nothing_applied_is_silent(self):
        launcher, lines = self._launcher(True, [])
        launcher._verify_patches()
        self.assertEqual(lines, [])

    def test_dead_client_points_at_the_client_window(self):
        launcher, lines = self._launcher(False, [_applied()])
        launcher._verify_patches()
        self.assertTrue(any("已退出" in ln for ln in lines))

    def test_config_write_failure_is_reported_not_raised(self):
        launcher, lines = self._launcher(True, [])
        with mock.patch("uslocalserver.launcher.app.config_mod.save",
                        side_effect=OSError("disk full")):
            launcher._save_config()
        self.assertTrue(any("disk full" in ln for ln in lines))


class TestHeadless(unittest.TestCase):
    def test_missing_client_returns_one_with_one_clear_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = replace(LauncherConfig.defaults(), client_dir=Path(tmp))
            lines: list[str] = []
            self.assertEqual(run_headless(cfg, log=lines.append), 1)
            self.assertEqual(sum("✗" in ln for ln in lines), 1)


if __name__ == "__main__":
    unittest.main()
