"""`(1,15)` DUNGEON-SELECT-15 -- the dungeon UI's gate.

The request is 8B: a `u32le` preselect and four zero bytes.  The reference
reads only the preselect, and only to echo it in its line; the answer depends
entirely on where the connection stands:

*   The connection's `(town, area)` is looked up in table 044's gates.  Town
    38 has four -- areas 2, 4, 5 and 7 opening worldmaps 2, 1, 100 and 163 --
    and area 1 has none, which is the capture's first `(1,15)`: the line
    spells the miss out and nothing is sent.
*   A run already in progress wins over everything: the client sent its
    second gate-open from inside dungeon 6 and drew "received during an
    existing dungeon run; ignoring", preselect and gate both absent from the
    line.
*   Otherwise the burst goes out: `(0,5)` with each node's state, a `(0,23)`
    carrying area `0xFF` and the *town row's* position, the three constant
    frames, and a `(0,5)` refresh whose nodes all read 2.

The `(0,23)` is the same frame `(1,36)`'s pair opens with (`movement.
area_pair`), with the area field replaced: it is the worldmap view's own
frame, so the area the client sees while the map is up is the wildcard.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from functools import lru_cache

from ...game import data
from ...protocol import frame
from ..town import movement
from . import blocks
from .run import DungeonSession

SELECT_OPCODE = frame.Opcode(1, 15, frame.OpcodeEncoding.U8_U16LE, True)

BODY_SIZE = 8

#: The area the burst's `(0,23)` carries where `(1,36)`'s own pair carries the
#: character's: the line prints it as `area=0xFF`, and all three captured
#: bursts pack the field as `ff 00 00 00` -- a byte, not a u32 of ones.
AREA_WILDCARD = 0xFF


@dataclass(frozen=True, slots=True)
class Select:
    preselect: int

    @classmethod
    def parse(cls, plain: bytes) -> "Select":
        if len(plain) != BODY_SIZE:
            raise ValueError(f"(1,15) body is {len(plain)}B, expected {BODY_SIZE}")
        return cls(struct.unpack_from("<I", plain, 0)[0])


@dataclass(frozen=True, slots=True)
class Gate:
    """One row of table 044's gate list: which worldmap an area opens."""

    town: int
    area: int
    worldmap: int


@lru_cache(maxsize=1)
def _gates() -> dict[tuple[int, int], Gate]:
    return {(row.townId, row.areaId): Gate(row.townId, row.areaId, row.worldmapId)
            for row in data.rows("dungeon_worldmap", "gates")}


def gate(town: int, area: int) -> Gate | None:
    """The gate at this location, or None."""
    return _gates().get((town, area))


def burst(session: DungeonSession, gate_row: Gate,
          location: movement.Location) -> list[tuple[frame.Opcode, bytes]]:
    """The six frames, in the capture's order."""
    nodes = blocks.worldmap_nodes(gate_row.worldmap)
    key = session.key
    area_ack = (key.to_bytes(2, "little")
                + struct.pack("<II", gate_row.town, AREA_WILDCARD)
                + struct.pack("<hh", location.x, location.y)
                + bytes([location.direction & 0xFF]) + b"\x01")
    return [
        (blocks.WORLDMAP_OPCODE, blocks.worldmap_body(nodes)),
        (movement.AREA_ACK_OPCODE, area_ack),
        (blocks.ACK_OPCODE, blocks.ack_body(key)),
        (blocks.ZERO_OPCODE, blocks.ZERO_BODY),
        (blocks.HEAD_OPCODE, blocks.HEAD_BODY),
        (blocks.WORLDMAP_OPCODE,
         blocks.worldmap_body(nodes, state=blocks.REFRESH_STATE)),
    ]


def note(session: DungeonSession, select: Select, gate_row: Gate) -> str:
    """The `DUNGEON-SELECT-15` prose after the bare `conn=N `."""
    nodes = blocks.worldmap_nodes(gate_row.worldmap)
    listed = ",".join(map(str, nodes))
    return (f"key={session.key} preselect={select.preselect} "
            f"gate=({gate_row.town},{gate_row.area}) -> worldmap "
            f"{gate_row.worldmap} nodes=[{listed}] -> (0,5) {len(nodes)} "
            f"dungeon(s) states={blocks.states_text(nodes)} + (0,23) area=0xFF "
            f"+ (0,3) + (0,26) + (0,27) body={blocks.HEAD_CONTENT} "
            f"+ (0,5) refresh state={blocks.REFRESH_STATE}")


def miss_note(town: int, area: int) -> str:
    """The no-gate line, verbatim -- including the parenthetical."""
    return (f"no dungeon gate for town={town} area={area}; ignoring "
            f"(sending a foreign worldmap's nodes would just leave the UI empty)")


#: What a `(1,15)` sent while a run is in progress prints instead of a gate
#: line.  The guard runs before the gate lookup: the capture's mid-run send
#: came from area 2, which does have one.
IN_RUN_NOTE = "received during an existing dungeon run; ignoring"
