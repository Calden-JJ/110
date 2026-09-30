"""`(1,37)` DUNGEON-LOADED-37 -- the client's "the room is up" ack.

A request of 16 zero bytes (the wire is 29B: 13B of game header), answered
with the same two frames every time, 21 times over:

    (1,37)  16B  `01` + 15 zeros.  The note counts its content as 1B.
    (0,30)  16B  all zeros; content 5B by the note's own count.  Only
                 `DUNGEON-PICKUP`'s `(1,43)` chain ever sends another.

The INFO line is the only thing that varies, and it reads the run: which
dungeon, which maze, the cell the client is standing on, and the map id
there.  So the ack is a statement about the run rather than about the
request -- the request carries nothing at all.  It is sent once per room,
right after the client has drawn one, and its `map=` always agrees with the
`(0,29)` the entry or the preceding `(1,45)` sent.

`(1,45)` DUNGEON-MOVE-45 shares the module because it is the same reading
one room later: a 160B request whose first two bytes are the *destination*
cell, which moves the run's cell and its map together and answers with a
`(0,29)` built for the room it walked into -- the entry's own frame, or the
40B map-`0xff00` one when this run has been in the room before.  One line
precedes it, and its two numbers read the run: `alive=k/n`, which falls as
`(1,39)` reports kills, and `N29=`, the frame's content size.  All 16 moves
in the capture are answered with exactly that one frame.
"""
from __future__ import annotations

from ...protocol import frame
from . import entry
from .maze import Cell
from .run import DungeonRun, DungeonSession

LOADED_OPCODE = frame.Opcode(1, 37, frame.OpcodeEncoding.U8_U16LE, True)
TRAIL_OPCODE = frame.Opcode(0, 30, frame.OpcodeEncoding.U8_U16LE, True)

MOVE_OPCODE = frame.Opcode(1, 45, frame.OpcodeEncoding.U8_U16LE, True)

#: The ack request, and the `(1,45)` request whose first two bytes are the cell.
BODY_SIZE = 16
MOVE_BODY_SIZE = 160

ACK_BODY = b"\x01" + bytes(15)
TRAIL_BODY = bytes(16)

#: What the note counts as each frame's content, verbatim -- the trailing
#: bytes are padding, exactly as `(0,3)`'s `4B` and `(0,27)`'s `35B` are.
ACK_CONTENT = "1B"
TRAIL_CONTENT = "5B"


def replies() -> list[tuple[frame.Opcode, bytes]]:
    """The pair, in the reference's order."""
    return [(LOADED_OPCODE, ACK_BODY), (TRAIL_OPCODE, TRAIL_BODY)]


def note(run: DungeonRun) -> str:
    """The `DUNGEON-LOADED-37` prose after the bare `conn=N `."""
    return (f"dungeon={run.dungeon} maze={run.maze} "
            f"cell=({run.cell[0]},{run.cell[1]}) map={run.map_id} -> "
            f"(1,37) ack {ACK_CONTENT} + (0,30) {TRAIL_CONTENT}")


def move_cell(plain: bytes) -> tuple[int, int]:
    """`(1,45)`'s destination, the first two bytes of its 160."""
    return (plain[0], plain[1])


def move(session: DungeonSession, cell: Cell) \
        -> tuple[list[tuple[frame.Opcode, bytes]], str] | None:
    """`(1,45)`: the run walks into the cell, and its room is answered with.

    None when there is no run -- a `(1,45)` after a `(1,42)` -- or when the
    cell holds no map; the capture shows neither, and the reference's own
    answers to them are unrecorded.
    """
    run = session.run
    if run is None:
        return None
    before = run.cell
    revisit = run.move_to(cell)
    if revisit is None:
        return None
    body = entry.room_body(run, revisit=revisit)
    return [(entry.SPAWN_OPCODE, body)], move_note(run, before, revisit)


def move_note(run: DungeonRun, before: Cell, revisit: bool) -> str:
    """The `DUNGEON-MOVE-45` prose after the bare `conn=N `."""
    alive, total = run.alive(run.map_id)
    return (f"dungeon={run.dungeon} maze={run.maze} "
            f"({before[0]},{before[1]})->({run.cell[0]},{run.cell[1]}) "
            f"map={run.map_id} revisit={revisit} alive={alive}/{total} "
            f"N29={entry.content_len(run.map_id, revisit=revisit)}B")
