"""The S->C write gap, enforced against a clock that actually moves.

`await asyncio.sleep(gap)` is not, by itself, a guarantee on this platform.
CPython's proactor loop fires any timer whose deadline falls within
`time() + clock_resolution`, and `time.monotonic()` here reports a 15.625ms
resolution -- larger than both gaps (channel 12ms, game 5ms).  Any socket I/O
completion that wakes the loop while a gap is pending can therefore sweep the
timer and run the next write immediately: measured 0.15ms for a 12ms sleep on
a pipelined channel handshake, which put two ACKs in one client `recv()` --
the documented failure where the client draws the server row and never gets
the endpoint.

Re-checking against a real-time deadline is the only form that holds.  An
early wake just sleeps the remainder; an overshoot is harmless (the reference
itself bursts at 8.3ms/19.5ms, not 12.0ms).
"""
from __future__ import annotations

import asyncio
import time


async def sleep_gap(gap: float) -> None:
    if gap <= 0:
        return
    deadline = time.perf_counter() + gap
    while (remaining := deadline - time.perf_counter()) > 0:
        await asyncio.sleep(remaining)
