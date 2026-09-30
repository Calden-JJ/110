"""The dungeon chain, M3.1: the doorway.

One session's worth of evidence backs this package -- `Logs-dungeon/
server-20260928.log`, the 09-28 run from character select through four
dungeons, replayed by `tools/diff_dungeon.py` against this code.  What it
pins, in the order a client drives it:

    (1,15)  the gate: which worldmap the town's area opens, and its nodes
    (1,16)  the entry: which maze, which map, and the (0,28) + (0,29) pair
    (1,45)  a room move -- only its effect on the run's cell is here, M3.2
            owns its frame
    (1,37)  the client's "map loaded" ack, answered from the run's cell
    (1,46)  the clear -- only the flag behind `(1,42)`'s `settled=` is here
    (1,42)  the settlement back to town

The four nodes the modules carry one each: `select`, `entry`, `loaded`,
`settle`.  `blocks` holds the frames that are the same everywhere, `run`
holds what a connection learns by playing.
"""
from __future__ import annotations

from . import blocks, entry, loaded, run, select, settle

__all__ = ["blocks", "entry", "loaded", "run", "select", "settle"]
