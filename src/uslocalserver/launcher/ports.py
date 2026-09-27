"""Port block: 7001 plus the eight game ports, and never a drift.

The reference drifts the whole block when 7001 is busy (measured: 60652-60660)
and rewrites `server.json` so the client follows.  The rewrite advertises its
ports through the passport it builds itself, so a drift would be invisible to
an already running Python server anyway -- staying put and reporting who holds
the port is what makes the "close the reference server first" rule obvious.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..server import channel, game
from . import win32

CHANNEL = channel.CHANNEL_PORT
GAME: tuple[int, ...] = tuple(sorted(game.GAME_PORTS))

#: Advertised inside the LOGIN_OK body, never bound -- listed so the occupancy
#: check does not flag a harmless squatter on it.
ADVERTISED_ONLY: tuple[int, ...] = (game.LOGIN_OK_PORT,)


@dataclass(frozen=True)
class Occupant:
    port: int
    pid: int
    name: str

    def __str__(self) -> str:
        return f"{self.port}（PID {self.pid}，{self.name}）"


class PortsBusy(RuntimeError):
    def __init__(self, occupants: list[Occupant]):
        self.occupants = occupants
        joined = "、".join(str(o) for o in occupants)
        hint = ""
        if any(o.name.lower().startswith("uslocalserver") for o in occupants):
            hint = "；看起来参考服务端还在跑，先关掉它"
        super().__init__(f"端口被占用：{joined}{hint}")


def required_ports() -> tuple[int, ...]:
    return (CHANNEL, *GAME)


def occupants(ports: tuple[int, ...] | None = None) -> list[Occupant]:
    """Listening sockets on our ports, with the process holding each one."""
    out = []
    for port in ports if ports is not None else required_ports():
        for pid in win32.tcp_listener_pids(port):
            out.append(Occupant(port, pid, win32.process_name(pid)))
    return out


def ensure_free(ports: tuple[int, ...] | None = None) -> None:
    taken = occupants(ports)
    if taken:
        raise PortsBusy(taken)
