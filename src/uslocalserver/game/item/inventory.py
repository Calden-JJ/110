"""`(1,19)` ITEM-MOVE -- the first write handler in the rewrite.

Behaviour measured 2026-09-27 by driving the reference with constructed frames
(`tools/probe_m2_item_move.py`; corpora `dfo-server/Logs-m2oracle/`), 29 moves
over four scripts.  The request body is 32B:

    u8 src.list | u16le src.slot | u32le src.iv
    u32le count
    u8 dst.list | u16le dst.slot | u32le dst.iv
    14B constant tail 00 00 00 00 FF FF FF FF 00 00 00 00 00 00

    src filled, dst empty   the source's item moves into dst        ("moved")
    src empty, dst filled   the destination's item moves into src   ("source was
                            empty, moved the destination into it")
    both filled             the two slots swap (also logged as "moved")
    both empty              rejected, `code=4`
    src == dst              no-op, success ack, nothing written

  `iv` is never checked (12345 is accepted) and `count` is echoed back, never
  applied -- a 495-stack moved with `count=1` leaves whole, and `count=5` on a
  single item succeeds.  `list=0` slots 0/1/2 are the gold / revive-coin /
  victory-point pseudo-slots and are rejected on either end.  Order of the
  three rejections is measured: virtual slots first (a virtual src == dst is
  rejected), then same-slot (an empty src == dst succeeds), then empty ends.

The ack is 16B, and both forms were read off the reference's own replies:

    success 01 <src.list> <src.slot u16le> <count u32le> <dst.list> <dst.slot u16le> 00*5
    failure 00 <code> 00 <src.list> <dst.list> 00*11

A same-container move draws the ack alone; an accepted cross-container one
draws the ack plus six refresh frames (`refresh.py`, M2.2) -- the reference
sends a seventh, the M2.3 giant subtype-1 USERINFO, which this does not build
yet.  A destination in the sealed worn slots (33/34/35) is its own branch:
the 0x13 failure ack, logged as `TALISMAN-MOVE-19`, measured once (dst=(3,35),
both ends empty).  Nothing puts an item into a sealed slot, so a sealed *src*
was never probed; neither was a cross-container *swap* (both ends filled,
different lists), which is treated as a cross move and so draws the refresh.
"""
from __future__ import annotations

import sqlite3
import struct
import time
from dataclasses import dataclass

from ...persistence import items
from ...protocol import frame

OPCODE = frame.Opcode(1, 19, frame.OpcodeEncoding.U8_U16LE, True)
BODY_SIZE = 32

#: Constant across all 576 `plain=` samples of the capture and every injected
#: frame the reference accepted; kept for the round-trip check, not validated.
TAIL = bytes.fromhex("00000000ffffffff000000000000")

MAIN_LIST = 0
VIRTUAL_SLOTS = frozenset({0, 1, 2})
EQUIPMENT_LIST = 3

#: Worn slots the reference refuses to fill -- answered with `code=0x13` under
#: a log tag of its own, `TALISMAN-MOVE-19 ... rejected: disabled, invalid
#: state, count or address; 0/7 -> 3/35` for the one probe (dst=(3,35), both
#: ends empty).  Measured on `dst` only; an item cannot reach them, so a
#: sealed `src` has no case.
SEALED_SLOTS = frozenset({33, 34, 35})

#: `code` byte of the failure ack.  4 is what the reference answers for an
#: empty/invalid address; the sealed branch uses 0x13 in the same slot.
REJECT_CODE = 4
REJECT_CODE_SEALED = 0x13

TAG_ITEM_MOVE = "ITEM-MOVE-19"
TAG_TALISMAN = "TALISMAN-MOVE-19"

NOTE_MOVED_FROM_EMPTY = ("source was empty, moved the destination into it; answered "
                         "with the (1,19) ack + 0 (0,14) refresh frame(s)")
NOTE_MOVED = "moved; answered with the (1,19) ack + 0 (0,14) refresh frame(s)"
NOTE_CROSS_MOVED_FROM_EMPTY = ("source was empty, moved the destination into it; answered "
                               "with the (1,19) ack + 2 (0,14) refresh frame(s)")
NOTE_CROSS_MOVED = "moved; answered with the (1,19) ack + 2 (0,14) refresh frame(s)"
NOTE_SAME_SLOT = "source and destination are the same slot; nothing to do"
NOTE_VIRTUAL = ("one end is a main-inventory virtual slot (gold / revive coin / "
                "victory point); answered with the error ack")
NOTE_EMPTY = ("empty source or invalid equipment destination (egg requires hatch; "
              "magic seal requires unseal); answered with the error ack")
NOTE_SEALED = "rejected: disabled, invalid state, count or address"


@dataclass(frozen=True, slots=True)
class Slot:
    list_type: int
    slot_index: int
    instance_value: int

    @property
    def address(self) -> tuple[int, int]:
        return (self.list_type, self.slot_index)

    @property
    def virtual(self) -> bool:
        return self.list_type == MAIN_LIST and self.slot_index in VIRTUAL_SLOTS


@dataclass(frozen=True, slots=True)
class MoveRequest:
    src: Slot
    dst: Slot
    count: int

    @classmethod
    def parse(cls, body: bytes) -> "MoveRequest":
        if len(body) != BODY_SIZE:
            raise ValueError(f"(1,19) body is {len(body)}B, expected {BODY_SIZE}")
        return cls(src=_slot(body, 0), dst=_slot(body, 11),
                   count=struct.unpack_from("<I", body, 7)[0])

    @property
    def same_slot(self) -> bool:
        return self.src.address == self.dst.address

    @property
    def cross_container(self) -> bool:
        return self.src.list_type != self.dst.list_type

    def ack(self, *, ok: bool, code: int = REJECT_CODE) -> bytes:
        if not ok:
            return (b"\x00" + bytes([code, 0x00, self.src.list_type,
                                     self.dst.list_type]) + bytes(11))
        return (b"\x01" + bytes([self.src.list_type])
                + struct.pack("<H", self.src.slot_index)
                + struct.pack("<I", self.count)
                + bytes([self.dst.list_type])
                + struct.pack("<H", self.dst.slot_index) + bytes(5))

    def describe(self) -> str:
        return (f"src=(list={self.src.list_type},slot={self.src.slot_index},"
                f"iv={self.src.instance_value}) "
                f"dst=(list={self.dst.list_type},slot={self.dst.slot_index},"
                f"iv={self.dst.instance_value}) count={self.count}")


def _slot(body: bytes, off: int) -> Slot:
    return Slot(body[off], struct.unpack_from("<H", body, off + 1)[0],
                struct.unpack_from("<I", body, off + 3)[0])


@dataclass(frozen=True, slots=True)
class Outcome:
    ok: bool
    action: str                     # "moved" | "swapped" | "noop" | "rejected"
    note: str                       # the reference's own line, for the log
    tag: str = TAG_ITEM_MOVE        # TALISMAN-MOVE-19 for the sealed branch
    code: int = REJECT_CODE         # the failure ack's code byte


def plan(request: MoveRequest, src: items.ItemStack | None,
         dst: items.ItemStack | None) -> Outcome:
    """Decide the branch from the two loaded slots.  No I/O, so it is testable
    against the oracle's 29 moves without a database."""
    if request.src.virtual or request.dst.virtual:
        return Outcome(False, "rejected", NOTE_VIRTUAL)
    if request.same_slot:
        return Outcome(True, "noop", NOTE_SAME_SLOT)
    if request.dst.list_type == EQUIPMENT_LIST and request.dst.slot_index in SEALED_SLOTS:
        return Outcome(False, "rejected",
                       f"{NOTE_SEALED}; {request.src.list_type}/{request.src.slot_index} "
                       f"-> {request.dst.list_type}/{request.dst.slot_index}",
                       tag=TAG_TALISMAN, code=REJECT_CODE_SEALED)
    if src is None and dst is None:
        return Outcome(False, "rejected", NOTE_EMPTY)
    if src is None:
        return Outcome(True, "moved", NOTE_CROSS_MOVED_FROM_EMPTY
                       if request.cross_container else NOTE_MOVED_FROM_EMPTY)
    return Outcome(True, "moved" if dst is None else "swapped",
                   NOTE_CROSS_MOVED if request.cross_container else NOTE_MOVED)


def execute(conn: sqlite3.Connection, character_id: int, request: MoveRequest,
            *, now: int | None = None) -> Outcome:
    """Load the two ends, decide, and write.  One transaction per move."""
    now = int(time.time()) if now is None else now
    with conn:
        src = items.load(conn, character_id, *request.src.address)
        dst = items.load(conn, character_id, *request.dst.address)
        out = plan(request, src, dst)
        if out.action == "moved":
            stack, target = (dst, request.src) if src is None else (src, request.dst)
            items.relocate(conn, stack, *target.address, now)
        elif out.action == "swapped":
            # delete-then-insert, not two updates: the address is the primary
            # key, so one row would collide with the other's, and the
            # reference's own revision counters move twice per address here.
            to_src = dst.at(*request.src.address, now)
            to_dst = src.at(*request.dst.address, now)
            items.delete(conn, character_id, *request.src.address)
            items.delete(conn, character_id, *request.dst.address)
            items.insert(conn, to_dst)
            items.insert(conn, to_src)
    return out
