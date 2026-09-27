"""The rewrite's own server, as a child process of the launcher.

Started with the same entry point the diff tools use, so a launcher run and a
manual run produce the same `Logs/server-rewrite.log` lines and stay
comparable.  Readiness is the entry point's own greeting, not a sleep.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading

from .. import paths
from . import client, ports
from .config import LauncherConfig

READY_MARKER = "channel listening on"


class ServerStartError(RuntimeError):
    pass


class ServerProcess:
    def __init__(self, config: LauncherConfig, log=print):
        self.config = config
        self.log = log
        self.proc: subprocess.Popen | None = None
        self._ready = threading.Event()
        self._reader: threading.Thread | None = None
        self.tail: list[str] = []

    def command(self) -> list[str]:
        # `--save` is always passed: omitted, run.py falls back to the
        # reference's own save, which is the opposite of "none".
        cmd = [sys.executable, "-m", "uslocalserver.server.run",
               "--host", self.config.bind_host,
               "--port", str(ports.CHANNEL),
               "--save", "none" if self.config.save_db is None else str(self.config.save_db)]
        if self.config.quiet:
            cmd += ["--quiet"]
        return cmd

    def start(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(paths.SRC_DIR)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
        env["PYTHONUNBUFFERED"] = "1"
        self.log(f"启动服务端：{' '.join(self.command())}")
        self.proc = subprocess.Popen(
            self.command(), cwd=str(paths.REPO_ROOT), env=env, text=True,
            encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            self.tail.append(line)
            if len(self.tail) > 200:
                del self.tail[0]
            if READY_MARKER in line:
                self._ready.set()
            self.log(f"[server] {line}")

    def wait_ready(self, timeout: float = 30.0) -> None:
        if not self._ready.wait(timeout):
            code = self.proc.poll() if self.proc else None
            tail = "\n".join(self.tail[-8:])
            raise ServerStartError(
                f"服务端 {timeout:.0f}s 内没有就绪"
                + (f"（已退出，码 {code}）" if code is not None else "")
                + (f"\n最近输出：\n{tail}" if tail else ""))

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self, timeout: float = 5.0) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.log("[launcher] 停止服务端 …")
        self.proc.terminate()
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout)
        finally:
            self.proc = None


def advertise_address(config: LauncherConfig) -> str:
    """The address the client will dial: config override, else auto-detect."""
    return config.server_address or client.local_address()
