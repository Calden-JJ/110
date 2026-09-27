"""Connection numbering, shared by every listener.

The reference numbers connections from one counter across all its ports --
the capture's channel session is conn=1 and the game session that follows on
10013 is conn=2 -- and the log's `conn=` field is how a packet is tied to a
session.  One counter per process, not per listener.
"""
from __future__ import annotations


class ConnectionIds:
    def __init__(self, start: int = 1) -> None:
        self._next = start

    def take(self) -> int:
        n = self._next
        self._next += 1
        return n
