"""`(1,35)` TOWN-MOVE and `(1,36)` TOWN-AREA -- M2.4.

Measured 2026-09-27 by driving the running reference with constructed frames
(`tools/probe_town.py`, five sessions; logs in `dfo-server/Logs-townprobe/`)
on top of the four corpus logs' own traffic.  The request bodies:

    (1,35)  8B   i16le x | i16le y | u8 dir | u8 param | u16 constant zero
    (1,36) 24B   u32le town | u32le area | i16le x | i16le y | u8 dir |
                 11B trailer

The coordinates are *signed*.  `(1,35)` sent `x=y=65535` is logged
`pos=(-1,-1)` and the row stores -1; `(1,36)` sent x=65535 y=40000 is logged
`pos=(-1,-25536)`.  A real client stays in 0..32767, so no corpus sample
showed this -- the `edge` and `signed` probe scenarios are what pinned it.
The reply pair still re-emits the request's raw 16 bits (`(0,23)` for the
`signed` run carries `ffff` and `409c`), which packing the signed values back
with `<hh` reproduces exactly.

`(1,35)` draws no reply at all -- no frames, no DISPATCH line (0 `(1,35) ->`
lines across every driven session) -- and is throttled: it writes and logs
only once `PERSIST_INTERVAL` has passed since the last *write* on that
connection.  A throttled move writes nothing and logs nothing; the
in-memory position can run ahead of the row, and the next persist lands on
the newest coordinates.  The timer is armed by a write, not by a send: that
is what makes a 1 Hz walker persist every second send (corpus persist gaps
2.008/2.014/2.014s), and a probe sending four moves 0.2/2.4/2.65s apart
persists the first and third and leaves the save on the third's values.
`(1,36)` arms the timer too -- a walk right after an area change is throttled
for the next 2s, which is what the 09-26 22:16 burst (seven sends, zero
persists, four `(1,36)` writes in between) turns out to be.

`(1,36)` is never throttled.  It writes the whole location and answers with
two frames, both pure functions of the request:

    (0,23) 16B  key u16le town u32le area u32le x u16le y u16le dir 01
    (0,24) 20B  town u32le area u32le `01 00` key u16le x u16le y u16le dir
                `01 01 00`

The 11B trailer is logged verbatim and never read.  The corpus's samples all
echo a town/area pair (the destination for four of them, the source for one),
but no reading fits all five, and the probe sent `(11,22,33)` -- a collision
with neither -- and got the same persist-and-answer as usual.  The `from=` in
the log line is the connection's own state, not the trailer.

Map data is not consulted: town/area `(0,0)` at `(0,0)` is accepted, and there
is no range or consistency check anywhere in either handler.

The leading u16 of both frames is the character's slot key, `slot_index + 1`
-- the same number `TOWN-SPAWN`/`TOWN-AREA-36` print as `key=`.  The M2
corpus could not tell it from a constant, since it only ever played slot 0
and every one of its frames opens `01 00`; the 09-28 dungeon session played
slot 2 and every `(0,23)`/`(0,24)`/`(0,22)` it drew opens `03 00`, with the
reference's own `SELECTION-4 ... slot=2 key=3` line on the same session
naming both numbers.  `(0,22)` carries it in those same first two bytes.

Town entry sends the same pair -- frames 20/21 of the `(1,143)` burst, from
the character row's town/area/position with `town_state` in the direction
byte -- and a third row-built frame, `(0,22)`, right behind it.  All five
driven entries pin that: each session walked before entering (to (5555,666)
dir 2, to town/area 0 at (-1,-1) dir 255, to (1,1) at (-32768,1) dir 0), and
each entry's three frames carried the row's values -- the capture's own
landing coordinates never reappeared.  `Location.of()` reads the row, and
`area_pair()` + `spawn_body()` build the frames.

`(1,1418)`, a 13B header and no body, is 赛利亚房间's lower exit: the
client asks the way back and the server answers it with the same
`(0,23)`/`(0,24)` pair.  The answer comes from `character_previous_village`,
and the *room entry* is what writes it: a `(1,36)` whose destination is the
room saves the source `(town, area)` and the connection's in-memory position
and facing.  That in-memory position is moved by every `(1,35)`, throttled
or not -- the 09-30 session's 54.181 entry saved (985,327) dir 5, exactly
what a *throttled* `(1,35)` at 53.311 had left, and the 55.532 escape
answered those coordinates back.  A character with no saved row -- one that
logged in inside the room without ever walking in -- lands at
`ROOM_TOWN_DOOR` instead.
"""
from __future__ import annotations

import sqlite3
import struct
from dataclasses import dataclass

from ...persistence.characters import CharacterSummary
from ...protocol import frame

MOVE_OPCODE = frame.Opcode(1, 35, frame.OpcodeEncoding.U8_U16LE, True)
AREA_OPCODE = frame.Opcode(1, 36, frame.OpcodeEncoding.U8_U16LE, True)
ENTRY_OPCODE = frame.Opcode(1, 143, frame.OpcodeEncoding.U8_U16LE, True)

#: 赛利亚房间, the one room whose lower exit draws the way back: every one of
#: the reference's 40 `(1,1418)` lines answers from here.
ROOM = (38, 1)
PREV_VILLAGE_OPCODE = frame.Opcode(1, 1418, frame.OpcodeEncoding.U8_U16LE, True)

#: The town entry is not one opcode.  The 09-28 dungeon session's client -- a
#: character with no tutorial flags, so a 1200B `(1,4)` body -- entered through
#: `(1,666)` and never sent `(1,143)` from `CharacterSelected` at all; char 1 in
#: the M2 corpus did the opposite.  Whichever arrives first draws the burst, and
#: either one sent again from `InTown` is a one-frame ack instead, which is what
#: `ENTRY_FROM` -- the state the burst is sent *from* -- tells apart.
ENTRY_OPCODES = (ENTRY_OPCODE,
                 frame.Opcode(1, 666, frame.OpcodeEncoding.U8_U16LE, True))

#: The same two as `(main, sub)`, which is what a dispatch loop compares.
ENTRY_KEYS = tuple(op.key() for op in ENTRY_OPCODES)

#: The state a client sits in between `(1,4)` and the town entry.
ENTRY_FROM = "CharacterSelected"
AREA_ACK_OPCODE = frame.Opcode(0, 23, frame.OpcodeEncoding.U8_U16LE, True)
AREA_ACK_2_OPCODE = frame.Opcode(0, 24, frame.OpcodeEncoding.U8_U16LE, True)
SPAWN_OPCODE = frame.Opcode(0, 22, frame.OpcodeEncoding.U8_U16LE, True)

MOVE_BODY_SIZE = 8
AREA_BODY_SIZE = 24
TRAILER_AT = 13

#: Where the three row-built frames sit in the `(1,143)` replay script: the
#: `(0,23)` + `(0,24)` pair, then the `(0,22)` spawn echo.
ENTRY_PAIR_AT = 20
ENTRY_SPAWN_AT = 22

#: Seconds between `(1,35)` writes on one connection.  The corpus never shows
#: two persist lines closer than 2.001s, and a probe persisting at 2.4s while
#: throttling at 0.2s and 0.25s brackets it from both sides.
PERSIST_INTERVAL = 2.0


@dataclass(frozen=True, slots=True)
class Move:
    x: int
    y: int
    direction: int
    param: int

    @classmethod
    def parse(cls, body: bytes) -> "Move":
        if len(body) != MOVE_BODY_SIZE:
            raise ValueError(f"(1,35) body is {len(body)}B, expected {MOVE_BODY_SIZE}")
        # The trailing u16 is zero in every capture and every probe send; it is
        # read off the body like the reference does and never checked, since no
        # non-zero one has ever been sent to it.
        x, y, direction, param, _tail = struct.unpack("<hhBBH", body)
        return cls(x, y, direction, param)

    def describe(self) -> str:
        return f"pos=({self.x},{self.y}) dir={self.direction} param={self.param}"


@dataclass(frozen=True, slots=True)
class AreaMove:
    town: int
    area: int
    x: int
    y: int
    direction: int
    trailer: bytes

    @classmethod
    def parse(cls, body: bytes) -> "AreaMove":
        if len(body) != AREA_BODY_SIZE:
            raise ValueError(f"(1,36) body is {len(body)}B, expected {AREA_BODY_SIZE}")
        town, area, x, y, direction = struct.unpack_from("<IIhhB", body, 0)
        return cls(town, area, x, y, direction, body[TRAILER_AT:])

    def describe(self) -> str:
        return (f"to=({self.town},{self.area}) pos=({self.x},{self.y}) "
                f"dir={self.direction} trailer={self.trailer.hex()}")


@dataclass(frozen=True, slots=True)
class Location:
    """Where the character row stands: what town entry spawns from.

    The direction is `town_state` -- the row has no direction column, every
    write stores the move's dir there, and the spawn line does not print it.
    """
    town: int
    area: int
    x: int
    y: int
    direction: int

    @classmethod
    def of(cls, summary: CharacterSummary) -> "Location":
        return cls(summary.town_id, summary.area_id, summary.position_x,
                   summary.position_y, summary.town_state)

    def describe(self) -> str:
        return f"town={self.town} area={self.area} pos=({self.x},{self.y})"


#: Where a `(1,1418)` lands when no row was ever saved -- a character that
#: logged in inside the room without walking in: the room's own town door.
#: `(38,0)` at `(1677,222)` dir 5 is the position all three of the reference
#: sessions' room-to-`(38,0)` `(1,36)` lines carry.
ROOM_TOWN_DOOR = Location(38, 0, 1677, 222, 5)


def spawn_body(location: Location, key: int) -> bytes:
    """`(0,22)`: the spawn echo the entry pair is followed by, 16B.

    The slot key, the position, the direction, then `64` and eight zero bytes.
    The tail is constant over all five driven entries -- and those span
    town/area 0 at (-1,-1), dir 255, and x -32768 -- so it is a literal here.
    What the `64` means is unknown; nothing has ever sent anything else.
    """
    return (struct.pack("<H", key) + struct.pack("<hh", location.x, location.y)
            + bytes([location.direction]) + b"\x64" + bytes(8))


def area_pair(key: int, town: int, area: int, x: int, y: int,
              direction: int) -> list[tuple[frame.Opcode, bytes]]:
    """The `(0,23)` + `(0,24)` pair, in the reference's order.

    Both the `(1,36)` answer and the town-entry push build it from these
    values; the coordinates go back out as the request's raw 16 bits.
    """
    xy = struct.pack("<hh", x, y)
    return [
        (AREA_ACK_OPCODE,
         struct.pack("<H", key) + struct.pack("<II", town, area) + xy
         + bytes([direction]) + b"\x01"),
        (AREA_ACK_2_OPCODE,
         struct.pack("<II", town, area) + b"\x01\x00"
         + struct.pack("<H", key) + xy
         + bytes([direction]) + b"\x01\x01\x00"),
    ]


@dataclass(slots=True)
class TownSession:
    """One connection's town state: the AREA line's `from=`, the character's
    in-memory position, and the move throttle's timer.

    Seeded at `(1,4)` from the row the reference's own `TOWN-SPAWN` reads, and
    moved by every `(1,36)`.  `x`/`y`/`direction` track the *client's* own
    position the way the reference's does -- every `(1,35)` moves them, even
    one the throttle swallows -- because a room entry saves them as the way
    back out.
    """
    character_id: int
    town: int
    area: int
    key: int
    x: int = 0
    y: int = 0
    direction: int = 0
    last_persist: float | None = None

    @classmethod
    def of(cls, summary: CharacterSummary) -> "TownSession":
        return cls(character_id=summary.character_id, town=summary.town_id,
                   area=summary.area_id, key=summary.slot_index + 1,
                   x=summary.position_x, y=summary.position_y,
                   direction=summary.town_state)

    def location(self) -> Location:
        return Location(self.town, self.area, self.x, self.y, self.direction)

    def persist_due(self, now: float) -> bool:
        return self.last_persist is None or now - self.last_persist >= PERSIST_INTERVAL

    def persisted(self, now: float) -> None:
        self.last_persist = now


def move_line(session: TownSession, move: Move) -> str:
    """The reference's `TOWN-MOVE-35` prose, after the bare `conn=N `."""
    return f"town={session.town} area={session.area} {move.describe()} persisted"


def area_line(session: TownSession, move: AreaMove) -> str:
    """The reference's `TOWN-AREA-36` prose, after the bare `conn=N `."""
    return (f"key={session.key} from=({session.town},{session.area}) "
            f"{move.describe()} persisted; answered with (0,23) + (0,24)")


def prev_village_line(session: TownSession, where: Location, origin: str) -> str:
    """The reference's `PREV-VILLAGE-1418` prose, after the bare `conn=N `.

    `origin` is `saved` for a row the room entry wrote and `default` for the
    `ROOM_TOWN_DOOR` fallback -- the reference's 40 lines are all `saved`,
    so the second spelling is ours.  The direction is not printed.
    """
    return (f"from=({session.town},{session.area}) "
            f"to=({where.town},{where.area}) pos=({where.x},{where.y}) "
            f"origin={origin}; N23+N24")


def changed(summary: CharacterSummary, move: Move) -> bool:
    """Whether a `(1,35)` would change the row at all.

    The oracle skips writes that would be no-ops: at offset 239.765 a move to
    (191,249) dir=5, exactly what the row already held, left no `TOWN-MOVE-35`
    line, while at 312.814 a dir-only change (183,249) dir=5 over a dir=4 row
    did write.  `param` is not stored by `write_move`, so it is not compared.
    """
    return (summary.position_x != move.x or summary.position_y != move.y
            or summary.town_state != move.direction)


def write_move(conn: sqlite3.Connection, character_id: int, move: Move, *,
               now: int) -> None:
    """The throttled write: position and facing only.

    The direction goes into `town_state` -- the row has no direction column,
    the store carries the move's dir there, and the town-entry pair hands
    `town_state` back out as the direction byte.
    """
    with conn:
        conn.execute("update characters set position_x = ?, position_y = ?, "
                     "town_state = ?, updated_at = ? where character_id = ?",
                     (move.x, move.y, move.direction, now, character_id))


def write_area(conn: sqlite3.Connection, character_id: int, move: AreaMove, *,
               now: int) -> None:
    """`(1,36)` writes the whole location, unconditionally."""
    write_location(conn, character_id,
                   Location(move.town, move.area, move.x, move.y, move.direction),
                   now=now)


def write_location(conn: sqlite3.Connection, character_id: int, where: Location,
                   *, now: int) -> None:
    """The whole row, from a `Location`: `(1,36)`'s write and `(1,1418)`'s."""
    with conn:
        conn.execute("update characters set town_id = ?, area_id = ?, "
                     "position_x = ?, position_y = ?, town_state = ?, "
                     "updated_at = ? where character_id = ?",
                     (where.town, where.area, where.x, where.y, where.direction,
                      now, character_id))


def previous_village(conn: sqlite3.Connection, character_id: int) -> Location | None:
    """`character_previous_village`: the way back a room entry saved.

    Absent for a character that has never walked into the room since the row
    was invented -- a plain login writes nothing.  The reference's save holds
    exactly the characters that entered it (two of three).
    """
    row = conn.execute(
        "select town_id, area_id, position_x, position_y, town_state "
        "from character_previous_village where character_id = ?",
        (character_id,)).fetchone()
    return None if row is None else Location(*row)


def save_previous_village(conn: sqlite3.Connection, character_id: int,
                          where: Location) -> None:
    """The room entry's snapshot: `insert or replace`, one row per character.

    Every entry overwrites -- the 09-30 session saved five different ways
    back in five minutes, and each escape answered with the newest -- and
    nothing clears it afterwards: the save still holds the last entry's
    values after the character has escaped.
    """
    with conn:
        conn.execute(
            "insert or replace into character_previous_village (character_id, "
            "town_id, area_id, position_x, position_y, town_state) "
            "values (?, ?, ?, ?, ?, ?)",
            (character_id, where.town, where.area, where.x, where.y,
             where.direction))
