"""`launcher.json`: the handful of choices a launcher run needs.

Kept next to PLAN.md rather than in the reference server's directory -- the
whole point is that a run here touches nothing under `DFO110-0.3.6\\`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path

from .. import paths
from . import client

CONFIG_PATH = paths.REPO_ROOT / "launcher.json"


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class LauncherConfig:
    client_dir: Path
    server_address: str
    bind_host: str = "0.0.0.0"
    save_db: Path | None = paths.SAVE_DB
    quiet: bool = False

    @classmethod
    def defaults(cls) -> LauncherConfig:
        return cls(client_dir=paths.CLIENT_DIR, server_address=client.local_address())

    def with_overrides(self, **kw) -> LauncherConfig:
        return replace(self, **{k: v for k, v in kw.items() if v is not None})


def _save_db(value) -> Path | None:
    if value is None or str(value).lower() in ("", "none"):
        return None
    return Path(value)


def load(path: Path | None = None) -> LauncherConfig:
    path = CONFIG_PATH if path is None else path
    cfg = LauncherConfig.defaults()
    if not path.exists():
        return cfg
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"读不了配置文件 {path}：{e}") from None
    if not isinstance(raw, dict):
        raise ConfigError(f"配置文件 {path} 必须是一个 JSON 对象")
    cfg = cfg.with_overrides(
        client_dir=Path(raw["clientDir"]) if raw.get("clientDir") else None,
        server_address=raw.get("serverAddress"),
        bind_host=raw.get("bindHost"),
        quiet=raw.get("quiet"),
    )
    # Not through with_overrides: "saveDb": "none" means None, and that helper
    # drops None to mean "no override", which would resurrect the default.
    return replace(cfg, save_db=_save_db(raw["saveDb"])) if "saveDb" in raw else cfg


def save(cfg: LauncherConfig, path: Path | None = None) -> Path:
    path = CONFIG_PATH if path is None else path
    path.write_text(json.dumps({
        "clientDir": str(cfg.client_dir),
        "serverAddress": cfg.server_address,
        "bindHost": cfg.bind_host,
        "saveDb": "none" if cfg.save_db is None else str(cfg.save_db),
        "quiet": cfg.quiet,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    return path
