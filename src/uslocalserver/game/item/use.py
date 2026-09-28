"""`(1,44)` ITEM-USE -- consume one unit of a stack.

Request body, 16B, read off the two 09-27 dumps (`_csprobe/c2s-1-44.hex`) and
their own note lines::

    u8 slot | u16le list | u32le iv | u32le item_id | 5 zero bytes

(`42 0000 | 72120000 | 17040000 | 0000000000` decodes as slot 66, list 0,
iv 4722, item 1047 -- exactly what `ITEM-USE-44 conn=2 slot=66 list=0
item=1047 iv=4722` printed.)  The reply run is three frames::

    (1,44)   16B  the ack: `01` + the request's first 15 bytes, byte for byte
    (0,14)  168B  the slot after the use (`refresh.slot_body`)
    (0,1361) 16B  `32` + 15 zeros (`refresh.BOARD_AFTER_WRITE_BODY`)

and two INFO lines under the opcode's own tag -- the request line, then
`item 1047 at slot 66: 3 -> 2`.

**What is verified.**  The count decrement and the `updated_at` rewrite are
both pinned against the save: the row behind `24 at slot 71: 989 -> 988`
(09-25 15:59:59.448) carries `updated_at` 1790323199 = 15:59:59, and the
`2660671 at slot 3: 496 -> 495` row (09-26 10:41:17.563) carries 1790390477 =
10:41:17.  The request's `iv` is not the row's `instance_value` (it changes
on every use of one row: 4722 vs the row's 0), so it is echoed, never
matched -- like `(1,19)`'s.

**What is not.**  No capture empties a stack: all 17 corpus `(1,44)` lines
run 3->2, 5->4, 500->499 and 1000->988, and the save has no `count = 0` row.
The save's own `buff_swap_replaced` trigger fires on `NEW.count=0`, so the
reference writes a zero somewhere, but whether the row then stays or is
deleted -- and what the client is sent -- is unmeasured.  A use of the last
unit is refused with a WARN rather than guessed; to pin it, use a `count = 1`
item in a probe session and read the reply run.
"""
from __future__ import annotations

import sqlite3
import struct
import time
from dataclasses import dataclass, replace

from ...persistence import items
from ...protocol import frame
from . import refresh

OPCODE = frame.Opcode(1, 44, frame.OpcodeEncoding.U8_U16LE, True)
BODY_SIZE = 16
#: Constant across all 17 corpus samples; kept for the round-trip check.
TAIL = bytes(5)

TAG = "ITEM-USE-44"
MAIN_LIST = 0


@dataclass(frozen=True, slots=True)
class UseRequest:
    slot_index: int
    list_type: int
    instance_value: int
    item_id: int

    @classmethod
    def parse(cls, plain: bytes) -> "UseRequest":
        if len(plain) != BODY_SIZE:
            raise ValueError(f"(1,44) body is {len(plain)}B, expected {BODY_SIZE}")
        return cls(slot_index=plain[0],
                   list_type=struct.unpack_from("<H", plain, 1)[0],
                   instance_value=struct.unpack_from("<I", plain, 3)[0],
                   item_id=struct.unpack_from("<I", plain, 7)[0])

    def ack(self, plain: bytes) -> bytes:
        """`01` then the request's first 15 bytes -- the captured echo."""
        return b"\x01" + plain[:15]

    def request_line(self, conn: int, plain: bytes) -> str:
        return (f"conn={conn} slot={self.slot_index} list={self.list_type} "
                f"item={self.item_id} iv={self.instance_value} "
                f"plain={plain.hex()}")

    def outcome_line(self, conn: int, before: int, after: int) -> str:
        return (f"conn={conn} item {self.item_id} at slot {self.slot_index}: "
                f"{before} -> {after}")


@dataclass(frozen=True, slots=True)
class Outcome:
    ok: bool
    before: int
    after: items.ItemStack | None = None
    #: Why nothing was written, for the caller's WARN: `missing` (no row, or
    #: another item in it) or `last-unit` (the unmeasured path).
    reason: str = ""


def execute(conn: sqlite3.Connection, character_id: int, request: UseRequest,
            *, now: int | None = None) -> Outcome:
    """Decrement the stack in one transaction; the refusals write nothing."""
    now = int(time.time()) if now is None else now
    with conn:
        stack = items.load(conn, character_id, request.list_type,
                           request.slot_index)
        if stack is None or stack.item_id != request.item_id:
            return Outcome(False, 0, reason="missing")
        if stack.count <= 1:
            return Outcome(False, stack.count, reason="last-unit")
        items.set_count(conn, stack, stack.count - 1, now)
    return Outcome(True, stack.count,
                   after=replace(stack, count=stack.count - 1, updated_at=now))


def frames(request: UseRequest, plain: bytes,
           after: items.ItemStack) -> list[tuple[frame.Opcode, bytes]]:
    """The three S->C frames, in the reference's order."""
    return [
        (OPCODE, request.ack(plain)),
        (refresh.OPCODE_SLOT,
         refresh.slot_body(after, request.list_type, request.slot_index)),
        (refresh.OPCODE_BOARD, refresh.BOARD_AFTER_WRITE_BODY),
    ]
