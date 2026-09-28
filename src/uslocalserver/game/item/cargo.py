"""`(1,19)` moves that touch a warehouse: the CARGO-MOVE line and its frames.

A move is a cargo move when either end's `list_type` is 2 (the character's
warehouse, still `character_items`) or 12 (the account warehouse,
`account_cargo_items`).  The reference then logs its own line after the usual
`ITEM-MOVE-19` one --

    CARGO-MOVE conn={c} account={a} character={ch} {src}/{slot}->{dst}/{slot} count={n}; committed

-- and, instead of the `moved; answered with ...` continuation and the
equipment refresh, answers four frames (measured 2026-09-27 22:56, three
moves, all `0 <-> 2`)::

    (1,19)   16B  the same ack a plain move gets
    (0,14)  168B  the source slot, post-move
    (0,14)  168B  the destination slot, post-move
    (0,1361) 16B  `32` + 15 zeros (`refresh.BOARD_AFTER_WRITE_BODY`)

No `EQUIPMENT-SPECIFICITY` line comes with it, and nothing resends USERINFO.

**`count` is applied here, and only here.**  The M2.1 oracle showed a plain
move echoes `count` and never applies it (a 495-stack moved with `count=1`
stays 495), but the third 09-27 cargo move is a split: `2/5->0/83 count=1`
out of a two-stack left one unit in `(2,5)` and created one in `(0,83)`,
which is exactly what its two `(0,14)` frames say (both `17040000 01000000`)
and what the save holds.  So `count >= src.count` moves the row whole and
`0 < count < src.count` splits it.

What the frame side of the *unmeasured* pairs is (2->2 same-list, 12<->x)
is inferred from the one rule that is uniform in the corpus -- every such
move carries the same `CARGO-MOVE` line -- and the same-container rule the
plain path measured: no `(0,14)` pair when both ends share a list.  A
refusal (empty source, filled destination) is unmeasured too, so it writes
nothing and answers nothing rather than guessing an ack.  The 16B board
closes every write run either way.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, replace

from ...persistence import cargo as cargo_rows
from ...persistence import items
from ...protocol import frame
from . import refresh
from .inventory import OPCODE, MoveRequest

#: list 2 = the character's warehouse, list 12 = the account's.
CHARACTER_LIST = 2
ACCOUNT_LIST = 12
CARGO_LISTS = frozenset({CHARACTER_LIST, ACCOUNT_LIST})

TAG = "CARGO-MOVE"


def is_cargo(request: MoveRequest) -> bool:
    return (request.src.list_type in CARGO_LISTS
            or request.dst.list_type in CARGO_LISTS)


def _rows(list_type: int):
    """Which table's row accessors a list lives in."""
    return cargo_rows if list_type == ACCOUNT_LIST else items


def _load(conn, account_id, character_id, list_type, slot_index):
    if list_type == ACCOUNT_LIST:
        return cargo_rows.load(conn, account_id, list_type, slot_index)
    return items.load(conn, character_id, list_type, slot_index)


def _key(account_id, character_id, list_type):
    """What keys a row of this list: the account for 12, the character else."""
    return account_id if list_type == ACCOUNT_LIST else character_id


@dataclass(frozen=True, slots=True)
class Outcome:
    ok: bool
    action: str = ""            # "moved" | "split"
    reason: str = ""            # why nothing was written, for the caller's WARN
    src_after: items.ItemStack | None = None
    dst_after: items.ItemStack | None = None


def note_line(conn: int, account_id: int, character_id: int,
              request: MoveRequest) -> str:
    return (f"conn={conn} account={account_id} character={character_id} "
            f"{request.src.list_type}/{request.src.slot_index}->"
            f"{request.dst.list_type}/{request.dst.slot_index} "
            f"count={request.count}; committed")


def execute(conn: sqlite3.Connection, account_id: int, character_id: int,
            request: MoveRequest, *, now: int | None = None) -> Outcome:
    """Load both ends, split or relocate, and commit -- one transaction.

    `account_id`/`character_id` are what the line prints; a list 12 row is
    keyed by the account, a list 2 row by the character.
    """
    now = int(time.time()) if now is None else now
    with conn:
        src = _load(conn, account_id, character_id, request.src.list_type,
                    request.src.slot_index)
        dst = _load(conn, account_id, character_id, request.dst.list_type,
                    request.dst.slot_index)
        if src is None or dst is not None:
            # Empty source is the plain path's rejection; a filled
            # destination (merge or swap) has no cargo sample at all.
            return Outcome(False, reason="nothing to move" if src is None
                           else "destination is filled")
        if 0 < request.count < src.count:
            return _split(conn, account_id, character_id, request, src, now)
        return _relocate(conn, account_id, character_id, request, src, now)


def _relocate(conn, account_id, character_id, request, src, now) -> Outcome:
    target = src.at(request.dst.list_type, request.dst.slot_index, now)
    here = _rows(request.src.list_type)
    there = _rows(request.dst.list_type)
    if here is there:
        here.relocate(conn, src, request.dst.list_type, request.dst.slot_index,
                      now)
    else:
        # Across the two tables the row is rewritten, not moved: the account
        # table has no `character_id` column to carry.
        here.delete(conn, _key(account_id, character_id, request.src.list_type),
                    request.src.list_type, request.src.slot_index)
        target = replace(target, character_id=_key(account_id, character_id,
                                                   request.dst.list_type))
        there.insert(conn, target)
    return Outcome(True, action="moved", dst_after=target)


def _split(conn, account_id, character_id, request, src, now) -> Outcome:
    """`0 < count < stack`: the source keeps the rest, the destination gets a
    new row of `count`."""
    left = replace(src, count=src.count - request.count, updated_at=now)
    moved = src.at(request.dst.list_type, request.dst.slot_index, now)
    moved = replace(moved, count=request.count)
    _rows(request.src.list_type).set_count(conn, src, left.count, now)
    _rows(request.dst.list_type).insert(
        conn, replace(moved, character_id=_key(account_id, character_id,
                                               request.dst.list_type)))
    return Outcome(True, action="split", src_after=left, dst_after=moved)


def frames(request: MoveRequest,
           outcome: Outcome) -> list[tuple[frame.Opcode, bytes]]:
    """The four frames, in the reference's order.

    A same-container cargo move (2->2) draws no `(0,14)` pair -- that is the
    plain path's own measured rule -- and keeps the ack and the board.
    """
    out = [(OPCODE, request.ack(ok=True))]
    if request.cross_container:
        out.append((refresh.OPCODE_SLOT,
                    refresh.slot_body(outcome.src_after, request.src.list_type,
                                      request.src.slot_index)))
        out.append((refresh.OPCODE_SLOT,
                    refresh.slot_body(outcome.dst_after, request.dst.list_type,
                                      request.dst.slot_index)))
    out.append((refresh.OPCODE_BOARD, refresh.BOARD_AFTER_WRITE_BODY))
    return out
