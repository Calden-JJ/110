"""Finding, checking and steering the game client.

The client is pinned to one build: the two NGS patches sit at fixed RVAs and
the endpoint rides in a command-line passport whose constant tail was baked in
for 2.31.1.117.  So validation is size + SHA-256, exactly what the reference
`DfoProcessLauncher.ValidateInstallation` does, and the error prose keeps its
distinction between the original build and a pre-patched rebuild.
"""
from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from ..protocol import channelinfo
from . import win32

EXE_NAME = "DFO.exe"
SCRIPT_NAME = "Script.pvf"


class ClientError(RuntimeError):
    """User-facing: what is wrong with the installation, in one sentence."""


@dataclass(frozen=True)
class LaunchData:
    version: str
    client_size: int
    client_sha256: str
    rebuilt_size: int
    rebuilt_sha256: str
    passport_template: str


def launch_data(version: str = "2.31.1.117") -> LaunchData:
    path = paths.LAUNCHER_DATA_DIR / f"launch-{version}.json"
    if not path.exists():
        raise ClientError(f"缺少启动数据文件：{path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return LaunchData(
        version=raw["client_version"],
        client_size=raw["client"]["size"],
        client_sha256=raw["client"]["sha256"].upper(),
        rebuilt_size=raw["rebuilt_client"]["size"],
        rebuilt_sha256=raw["rebuilt_client"]["sha256"].upper(),
        passport_template=raw["launch"]["passport"],
    )


def build_passport(address: str, port: int, version: str = "2.31.1.117") -> str:
    """The one argument the client gets; same rules the reference enforces."""
    try:
        packed = socket.inet_aton(address)
    except OSError:
        raise ClientError(f"服务器地址必须是 IPv4 地址：{address!r}") from None
    if socket.inet_ntoa(packed) != address:
        raise ClientError(f"服务器地址必须是点分十进制 IPv4：{address!r}")
    if not 1 <= port <= 65535:
        raise ClientError(f"频道端口必须在 1 到 65535 之间：{port}")
    return launch_data(version).passport_template.format(address=address, port=port)


def validate(client_dir: Path, version: str = "2.31.1.117") -> Path:
    """Return the exe path, or raise with the reason."""
    exe = client_dir / EXE_NAME
    if not exe.exists():
        raise ClientError(f"客户端目录里没有 {EXE_NAME}：{exe}")
    if not (client_dir / SCRIPT_NAME).exists():
        raise ClientError(f"客户端目录里没有 {SCRIPT_NAME}：{client_dir}")
    data = launch_data(version)
    size = exe.stat().st_size
    digest = hashlib.sha256(exe.read_bytes()).hexdigest().upper()
    if size == data.client_size and digest == data.client_sha256:
        return exe
    if size == data.rebuilt_size and digest == data.rebuilt_sha256:
        raise ClientError("这是「固定重建版」客户端（NGS 补丁已打进文件），"
                          "请换用 110US 原版 DFO.exe。")
    raise ClientError(f"客户端版本不匹配：需要已验证的 110US 原版 {EXE_NAME}"
                      f"（{data.client_size} 字节 / SHA-256 {data.client_sha256[:16]}…），"
                      f"实际 {size} 字节 / {digest[:16]}…")


def ensure_no_running_client() -> None:
    pids = win32.process_ids_by_name(EXE_NAME)
    if pids:
        raise ClientError(f"已有 {EXE_NAME} 在运行（PID {', '.join(map(str, pids))}），"
                          "请先关闭它再启动。")


def local_address() -> str:
    """Same auto-detection the reference uses; loopback only as a fallback."""
    return channelinfo.local_address()
