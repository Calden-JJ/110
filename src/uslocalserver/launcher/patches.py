"""The client-side patches, read from `data/launcher/patches-*.json`.

One module (`ngs_startup_compat`) with two sites, both extracted mechanically
from the reference hook (`Dll1.dll`) by `tools/extract_launcher_patches.py`.
Every site is written verify-then-write: the live bytes must equal `expect`
(the unpatched original) or `bytes` (already patched, which is a success, not
an error).  Anything else is a version mismatch and the launcher refuses.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .. import paths


class PatchError(RuntimeError):
    """Version mismatch or a failed write -- never partial: nothing else runs."""


@dataclass(frozen=True)
class Site:
    name: str
    rva: int
    expect: bytes
    payload: bytes

    @property
    def size(self) -> int:
        return len(self.payload)


@dataclass(frozen=True)
class Module:
    name: str
    sites: tuple[Site, ...]


@dataclass(frozen=True)
class PatchSet:
    version: str
    client_size: int
    client_sha256: str
    modules: tuple[Module, ...]

    @property
    def sites(self) -> tuple[Site, ...]:
        return tuple(s for m in self.modules for s in m.sites)


def default_path(version: str) -> Path:
    return paths.LAUNCHER_DATA_DIR / f"patches-{version}.json"


def load(version: str = "2.31.1.117") -> PatchSet:
    path = default_path(version)
    if not path.exists():
        raise PatchError(f"缺少补丁数据文件：{path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    modules = []
    for m in raw["modules"]:
        sites = []
        for p in m["patches"]:
            expect, payload = bytes.fromhex(p["expect"]), bytes.fromhex(p["bytes"])
            if len(expect) != len(payload) or len(payload) != p["size"]:
                raise PatchError(f"补丁数据自相矛盾：{m['name']}/{p['name']}")
            sites.append(Site(p["name"], int(p["rva"], 16), expect, payload))
        modules.append(Module(m["name"], tuple(sites)))
    return PatchSet(raw["client_version"], raw["client"]["size"],
                    raw["client"]["sha256"], tuple(modules))


@dataclass(frozen=True)
class Applied:
    site: Site
    address: int


def apply(process_handle: int, base: int, patch_set: PatchSet) -> list[Applied]:
    """Write every site; returns the ones this call actually changed.

    A site that already holds `payload` is counted as success and skipped, so
    a restart against an already-patched process is a no-op rather than a lie.
    """
    from . import win32

    done: list[Applied] = []
    for site in patch_set.sites:
        addr = base + site.rva
        live = win32.read_bytes(process_handle, addr, site.size)
        if live == site.payload:
            continue
        if live != site.expect:
            raise PatchError(
                f"{site.name}: 客户端内存与 2.31.1.117 不符（0x{addr:x} "
                f"期望 {site.expect.hex()}，实际 {live.hex()}）—— 客户端版本不匹配，拒绝启动")
        win32.write_remote(process_handle, addr, site.payload)
        done.append(Applied(site, addr))
    return done


def verify_still_applied(process_handle: int, applied: list[Applied]) -> list[str]:
    """Re-read after resume: Themida unpacks before the entrypoint runs.

    Measured 2026-09-27: the writes survive, so anything returned here is a
    real regression and worth failing loudly.
    """
    from . import win32

    lost = []
    for a in applied:
        if win32.read_bytes(process_handle, a.address, a.site.size) != a.site.payload:
            lost.append(a.site.name)
    return lost
