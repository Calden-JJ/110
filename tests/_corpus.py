"""Shared test corpus: the real wire frames captured with packetHexLog on.

`server-20260926.log` is the only log with `DEBUG PACKET ... hex=` dumps (the
2026-09-25 run had packetHexLog off), so it is the reference corpus for
everything frame-related.  It covers the login/channel handshake window only.

288 lines carry a hex dump; 4 of them are truncated as `<hex>...(+NNB)` --
all S->C game frames whose body exceeds the logger's 4096-byte cut.
"""
from __future__ import annotations

import functools
import os
from pathlib import Path

import _bootstrap  # noqa: F401  (sys.path)

from uslocalserver import logs, paths
from uslocalserver.logs import PacketRecord

CORPUS_LOG = Path(os.environ.get("DFO_CORPUS_LOG", paths.LOGS_DIR / "server-20260926.log"))

EXPECTED_TOTAL = 288
EXPECTED_TRUNCATED = 4


@functools.lru_cache(maxsize=1)
def all_packets() -> tuple[PacketRecord, ...]:
    return tuple(p for p in logs.iter_packets(CORPUS_LOG) if p.hex is not None)


@functools.lru_cache(maxsize=1)
def complete_packets() -> tuple[PacketRecord, ...]:
    """The frames whose dump is whole -- the ones `parse` must round-trip."""
    return tuple(p for p in all_packets() if not p.truncated)


@functools.lru_cache(maxsize=1)
def truncated_packets() -> tuple[PacketRecord, ...]:
    return tuple(p for p in all_packets() if p.truncated)


def packets_for(link: str, direction: str) -> tuple[PacketRecord, ...]:
    return tuple(p for p in complete_packets()
                 if p.link == link and p.direction == direction)


def link_of(record: PacketRecord) -> str:
    """Map a log record to the frame.Link value name."""
    return f"{record.link}-{'c2s' if record.direction == 'C->S' else 's2c'}"
