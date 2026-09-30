"""The dungeon chain's constant frames, and the one table-driven builder.

Two of the frames every dungeon burst carries never differ:

    (0,26)  16B  all zeros.
    (0,27)  40B  a head byte and 39 zeros; the notes count 35B of content, so
                 5 bytes of the 40 are padding.  The head is 00 in the
                 `(1,15)` burst and 01 in the tutorial entry's pre-frames.

The third, `(0,3)`, carries the session key -- see `ack_body`.

The fourth is `(0,5)`, the worldmap the gate opens:

    u16le count + count x [u32le dungeon id + u8 state]

with `state` a pure function of the dungeon's own `difficulty` array in table
045 -- see `node_state`.  The `(1,15)` burst sends it twice: once with each
node's state, then a refresh copy with every state 2.
"""
from __future__ import annotations

import struct
from functools import lru_cache
from typing import Sequence

from ...game import data
from ...protocol import frame

ACK_OPCODE = frame.Opcode(0, 3, frame.OpcodeEncoding.U8_U16LE, True)
ZERO_OPCODE = frame.Opcode(0, 26, frame.OpcodeEncoding.U8_U16LE, True)
HEAD_OPCODE = frame.Opcode(0, 27, frame.OpcodeEncoding.U8_U16LE, True)
WORLDMAP_OPCODE = frame.Opcode(0, 5, frame.OpcodeEncoding.U8_U16LE, True)
ENABLE_OPCODE = frame.Opcode(0, 31, frame.OpcodeEncoding.U8_U16LE, True)
BOSS_ACK_OPCODE = frame.Opcode(0, 115, frame.OpcodeEncoding.U8_U16LE, True)

def ack_body(key: int) -> bytes:
    """`(0,3)`: `01`, the session key, `00 01`, twelve zeros.

    The front pair was a constant `01 03` here until the second key-bearing
    capture arrived: LRouDao is slot 2 and every one of its `(0,3)` readings
    says `01 02`, while XJianHun (slot 3) says `01 03` in all thirteen of its
    own -- fifteen samples, four sessions, no exception.  `key` is the same
    `slot_index + 1` that `(0,23)`/`(0,24)` carry and `TOWN-SPAWN` prints; the
    old constant was fitted off the 09-28 slot-3 logs alone.

    The corpus cannot fully separate key from job (slot 3 is job 0, slot 2 is
    job 1), but the reference notes pair `(0,3)` with the key-carrying pair,
    and 03-for-everyone is the reading with a contradiction in it.
    """
    return bytes([1]) + struct.pack("<H", key) + bytes([1]) + bytes(12)

#: `(0,26)`.
ZERO_BODY = bytes(16)

#: `(0,31)` ENABLE_CLEAR: what a `(1,39)` appends when the kill empties the
#: maze's boss cell.  All three of the capture's are sixteen zero bytes.
ENABLE_BODY = bytes(16)


def boss_ack_body(target: int) -> bytes:
    """`(0,115)`: `01 01`, the id as `u16le`, twelve zeros.

    Two senders, one shape: the kill that empties the maze's boss cell when
    the record it killed is Boss-ranked (dungeon 5's seq 68, `rank=Boss`;
    dungeon 3's boss 36 dies a hundred lines earlier and is answered without
    one), and the `(1,117)` that asks about an id outright -- both echoes of
    the id they name.
    """
    return b"\x01\x01" + struct.pack("<H", target) + bytes(12)

#: `(0,27)` and its entry-time head.  The notes spell both content sizes out
#: verbatim, which is why they are strings here rather than `len()` calls.
HEAD_BODY = bytes(40)
ENTRY_HEAD_BODY = b"\x01" + bytes(39)
ACK_CONTENT = "4B"
HEAD_CONTENT = "35B"

#: What the refresh copy of `(0,5)` sets every node's state to.
REFRESH_STATE = 2


@lru_cache(maxsize=1)
def _worldmaps() -> dict[int, tuple[int, ...]]:
    return {w.id: tuple(w.dungeonIds) for w in data.rows("dungeon_worldmap", "worldmaps")}


@lru_cache(maxsize=1)
def _difficulties() -> dict[int, tuple[int, ...] | None]:
    return {d.id: (tuple(d.difficulty) if d.difficulty else None)
            for d in data.rows("dungeon_content", "dungeons")}


def node_state(dungeon_id: int) -> int:
    """`(0,5)`'s state byte for one worldmap node: the highest set index.

    The client's difficulty picker stops at the last tier the dungeon offers,
    so the state is the largest index whose `difficulty` entry is set.  A
    dungeon the table has no row for shows no picker at all and counts as 1
    -- 182 such nodes sit in the worldmaps, and every one of them reads 1 in
    the reference's logs.

    The rule was first fitted as "the number of set tiers minus one", off
    worldmap 2 -- the only worldmap the M2 corpus showed, and every one of
    its arrays is a prefix (`(1,0,0,0,0)`, `(1,1,1,1,0)`), where the two
    readings cannot differ.  Of the table's 2,070 set arrays over half
    (1,051) are *not* prefixes, and they do: worldmap 39's 316/7539/315 are
    `(0,0,0,1,0)`/`(0,0,1,0,0)`/`(0,1,0,0,0)`, got state 0 from the old
    rule, and the client dropped the connection on 2026-09-30.  The
    reference's own logs then settle it: across their 22 `states=` lines
    over 19 worldmaps the old rule mismatches 8,753 node states; this one,
    none.
    """
    difficulty = _difficulties().get(dungeon_id) or ()
    return max((i for i, tier in enumerate(difficulty) if tier), default=1)


def worldmap_nodes(worldmap_id: int) -> list[int]:
    """The node ids `(0,5)` lists, in the table's own order."""
    return list(_worldmaps().get(worldmap_id, ()))


def worldmap_body(nodes: Sequence[int], *, state: int | None = None) -> bytes:
    """`(0,5)`: the node list, each with its own state or one shared state."""
    out = struct.pack("<H", len(nodes))
    for node in nodes:
        out += struct.pack("<IB", node, node_state(node) if state is None else state)
    return out


def states_text(nodes: Sequence[int]) -> str:
    """`states=[...]` as the `(1,15)` note spells it."""
    return "[" + ",".join(str(node_state(node)) for node in nodes) + "]"
