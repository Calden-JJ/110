"""The port block, its occupants, and the command line the server gets.

Occupancy is checked against a listener this test owns, never against the
default block -- a test run must not care whether the reference server (or a
previous launcher run) is up.
"""
from __future__ import annotations

import os
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

import _bootstrap  # noqa: F401

from uslocalserver import paths
from uslocalserver.launcher import ports
from uslocalserver.launcher.config import LauncherConfig
from uslocalserver.launcher.server import ServerProcess, ServerStartError


class TestBlock(unittest.TestCase):
    def test_the_block_is_fixed(self):
        self.assertEqual(ports.CHANNEL, 7001)
        self.assertEqual(ports.GAME, (10011, 10012, 10013, 10017, 10018,
                                      10019, 10020, 10021))
        self.assertEqual(ports.required_ports(), (7001, *ports.GAME))
        self.assertEqual(ports.ADVERTISED_ONLY, (7200,))
        for port in ports.ADVERTISED_ONLY:
            self.assertNotIn(port, ports.required_ports())


class TestOccupants(unittest.TestCase):
    def _listening_socket(self) -> tuple[socket.socket, int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        self.addCleanup(s.close)
        return s, s.getsockname()[1]

    def test_finds_the_process_holding_a_port(self):
        s, port = self._listening_socket()
        found = ports.occupants((port,))
        self.assertEqual([(o.port, o.pid) for o in found], [(port, os.getpid())])
        self.assertEqual(found[0].name.lower(), Path(sys.executable).name.lower())
        self.assertIn(f"PID {os.getpid()}", str(found[0]))

    def test_busy_port_raises_with_the_holder(self):
        s, port = self._listening_socket()
        with self.assertRaises(ports.PortsBusy) as ctx:
            ports.ensure_free((port,))
        self.assertIn(str(port), str(ctx.exception))
        self.assertEqual([o.port for o in ctx.exception.occupants], [port])

    def test_released_port_is_free_again(self):
        s, port = self._listening_socket()
        s.close()
        self.assertEqual(ports.occupants((port,)), [])
        self.assertIsNone(ports.ensure_free((port,)))

    def test_the_reference_hint_only_for_its_own_process_name(self):
        busy = ports.PortsBusy([ports.Occupant(7001, 1234, "USLocalServer.Server.exe")])
        self.assertIn("先关掉它", str(busy))
        self.assertIn("7001", str(busy))
        quiet = ports.PortsBusy([ports.Occupant(7001, 1234, "chrome.exe")])
        self.assertNotIn("先关掉它", str(quiet))


class TestServerCommand(unittest.TestCase):
    def _cfg(self, **kw) -> LauncherConfig:
        base = dict(client_dir=paths.CLIENT_DIR, server_address="127.0.0.1",
                    save_db=paths.SAVE_DB)
        base.update(kw)
        return LauncherConfig(**base)

    def _command(self, **kw) -> list[str]:
        return ServerProcess(self._cfg(**kw), log=lambda *_: None).command()

    def test_launches_our_own_entry_point_on_the_fixed_block(self):
        cmd = self._command()
        self.assertEqual(cmd[:3], [sys.executable, "-m", "uslocalserver.server.run"])
        self.assertEqual(cmd[cmd.index("--host") + 1], "0.0.0.0")
        self.assertEqual(cmd[cmd.index("--port") + 1], str(ports.CHANNEL))
        self.assertNotIn("--quiet", cmd)

    def test_save_is_always_passed(self):
        cmd = self._command()
        self.assertEqual(cmd[cmd.index("--save") + 1], str(paths.SAVE_DB))
        none = self._command(save_db=None)
        self.assertEqual(none[none.index("--save") + 1], "none")

    def test_quiet_and_bind_host_come_through(self):
        cmd = self._command(quiet=True, bind_host="127.0.0.1")
        self.assertIn("--quiet", cmd)
        self.assertEqual(cmd[cmd.index("--host") + 1], "127.0.0.1")

    def test_a_server_that_dies_before_ready_reports_its_tail(self):
        proc = ServerProcess(self._cfg(), log=lambda *_: None)
        dying = [sys.executable, "-c", "print('boom: nope'); raise SystemExit(3)"]
        with mock.patch.object(ServerProcess, "command", return_value=dying):
            proc.start()
            try:
                with self.assertRaises(ServerStartError) as ctx:
                    proc.wait_ready(timeout=1.0)
            finally:
                proc.stop()
        self.assertIn("boom: nope", str(ctx.exception))
        self.assertIn("码 3", str(ctx.exception))
        self.assertIn("没有就绪", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
