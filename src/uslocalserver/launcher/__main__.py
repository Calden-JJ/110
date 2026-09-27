"""`python -m uslocalserver.launcher`: the window, or `--no-gui` for a console run.

Command-line values override `launcher.json`; the window starts from the same
config and writes edits back on the next successful start.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from . import config as config_mod
from .app import Window, run_headless
from .config import LauncherConfig


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="uslocalserver.launcher",
        description="起自研服务端，给客户端打补丁并拉起来。")
    p.add_argument("--no-gui", action="store_true",
                   help="不开窗口，日志直接打屏；Ctrl+C 结束（一并关客户端与服务端）")
    p.add_argument("--config", type=Path, metavar="PATH",
                   help="配置文件位置（默认 <repo>/launcher.json）")
    p.add_argument("--client", type=Path, metavar="DIR", help="客户端目录（覆盖配置文件）")
    p.add_argument("--address", metavar="IP", help="服务器地址，点分十进制 IPv4（覆盖配置文件）")
    p.add_argument("--save", metavar="PATH|none", help="存档数据库；none 表示不落盘（覆盖配置文件）")
    p.add_argument("--host", metavar="IP", help="服务端绑定地址（覆盖配置文件）")
    p.add_argument("--quiet", action="store_true", help="服务端少说话")
    return p.parse_args(argv)


def apply_overrides(cfg: LauncherConfig, args: argparse.Namespace) -> LauncherConfig:
    kw: dict = {}
    if args.client:
        kw["client_dir"] = args.client
    if args.address:
        kw["server_address"] = args.address
    if args.save is not None:
        kw["save_db"] = None if args.save.lower() in ("", "none") else Path(args.save)
    if args.host:
        kw["bind_host"] = args.host
    if args.quiet:
        kw["quiet"] = True
    return replace(cfg, **kw) if kw else cfg


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args(argv)
    try:
        cfg = config_mod.load(args.config)
    except config_mod.ConfigError as e:
        print(f"[launcher] ✗ {e}")
        return 1
    cfg = apply_overrides(cfg, args)
    if args.no_gui:
        return run_headless(cfg)
    Window(cfg).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
