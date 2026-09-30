"""Shared test corpus: the real wire frames captured with packetHexLog on.

`server-20260926.log` is the only log with `DEBUG PACKET ... hex=` dumps (the
2026-09-25 run had packetHexLog off), so it is the reference corpus for
everything frame-related.  It covers the login/channel handshake window only.

288 lines carry a hex dump; 4 of them are truncated as `<hex>...(+NNB)` --
all S->C game frames whose body exceeds the logger's 4096-byte cut.

That log lived in the 0.3.6 tree, which has been deleted; `CORPUS_LOG` is now
resolved by `_bootstrap.corpus_log()` and every consumer must go through
`require()`, which skips rather than reporting a missing fixture as a defect.
"""
from __future__ import annotations

import functools
from pathlib import Path

import _bootstrap  # noqa: F401  (sys.path)
from _bootstrap import require_corpus

from uslocalserver import logs
from uslocalserver.logs import PacketRecord

#: The 0.3.6 capture, when present.  None means the corpus is not on disk and
#: every frame-count assertion in the suite is unverifiable.
CORPUS_LOG: Path | None = _bootstrap.corpus_log()

EXPECTED_TOTAL = 288
EXPECTED_TRUNCATED = 4


def require() -> Path:
    """The corpus path, skipping the test when it is not on disk."""
    global CORPUS_LOG
    if CORPUS_LOG is None:
        CORPUS_LOG = require_corpus()
    return CORPUS_LOG


@functools.lru_cache(maxsize=1)
def all_packets() -> tuple[PacketRecord, ...]:
    return tuple(p for p in logs.iter_packets(require()) if p.hex is not None)


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
