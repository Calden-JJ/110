"""`(1,16)` DUNGEON-ENTER-16 -- picking a maze, and the `(0,28)`/`(0,29)` pair.

The request is 32B and reads, field for field across all six sends::

    [0:4]   u32le dungeon
    [4:8]   u32le difficulty, 0 in every send
    [8]     u8    entry option
    [9]     u8    0xff
    [10]    u8    0xff
    [11:16] five zero bytes
    [16:18] u16le quest -- 0, 3145, 3146 or 3147, never anything else
    [18:32] fourteen zero bytes

**Which maze.**  A quest names one: table 045's mazes carry a
`questConnection` of `(0, quest, -1)`, and the capture's entries land on
exactly the maze whose connection holds the quest the client sent.  Quest 0
is the other path.  The client sent dungeon 5 with quest 0 once -- a click on
a gate the character had no business entering -- and the reference answered
with `native retry source=5 -> quest=3147 dungeon=6`: it scanned the gate's
worldmap for a maze whose quest the character is already on, found 3147 (the
one in-progress quest), and entered dungeon 6 instead.  That scan is the one
fitted rule here; everything else is the table's own geometry.

**A pick with no quest behind it** gets the dungeon's own first maze -- and
that fallback is not a guess either.  The 09-25 level-110 sessions entered
dungeons 410, 1000, 5000, 7150, 7322, 8523, 100000002, 100000151, 100002627,
100003043 and 291100268, and every one of their `DUNGEON-ENTRY` lines reads
`maze=0` at the table's own `startMap`, `mapId` and `bossMap` (`default_maze`).
Those maze-0 rows carry no `questConnection` -- and a quest match and the
retry both return connection-carrying rows -- so `maze=0` is a line only the
fallback can produce.  All 200 entry lines the five corpus logs hold match
their maze's own geometry, and all 87 non-zero mazes they entered carry a
connection.  Before the fallback existed, such a pick was answered with the
ignored line and no frames at all, and the 09-29 session's client sat on it
for 580s.

**The two frames.**  `(0,28)` is 48B: the dungeon, the maze, the boss cell,
and constants.  `(0,29)` is the room:

    header 40B   [0] cellX [1] cellY [2] 00 [3:7] the run's four seed bytes
                 [7] 00 [8] 00 [9] 01 [10:16] 00 [16] 00 [17:25] ff x8
                 [25:31] 00 [31] entry? 01 : 00 [32:36] u32le map id
                 [36:40] u32le record count
                 -- entry: one more byte ([40], 0xff when the room is
                 empty) and two zeros; revisit: the frame ends at 40.
    records      22B each from offset 43, the last one's final two bytes
                 dropped: u16le spawn id, u32le monster id, u8 basisLevel,
                 u8 flags, 8 zero bytes, and the four mark bytes
                 `i+1 00 i+1 00` -- each group's last record zeroes its pair
                 and the frame's last records `00 00 00 ff`
    padding      to the next multiple of 8

so a populated room is `41 + 22 x records` bytes before padding (the 43-byte
prefix less the two dropped), which is the regularity PLAN.md fits over 917
of its 919 sampled `(0,29)`s.  An empty room keeps its `ff 00 00` and is 43;
the fit cannot see the difference, since both pad to the same multiple of 8.

The spawn ids run from the session's counter, and the seed is drawn once per
run and repeated by every `(0,29)` in it -- `run` and `maze.maze_total` carry
the arithmetic.  The records are the room's table monsters in table order
plus table 049's apcs -- `maze.room_spawns` has the two groups, which is
what makes 53129's seven where table 046 holds five.

**The tutorial.**  A request for the character's own
`pending_tutorial_dungeon_id`, which character creation sets to 7115, enters
through a path of its own: two pre-frames (`(0,3)` and a `(0,27)` whose head
byte is 01) go out ahead of the pair, five lines replace the usual two, and
the pending value is cleared as the run starts.  The line calls it
"client-authoritative, synthetic worldmap" -- 7115 is in no worldmap's node
list, which is why its entry never needed a `(1,15)`.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ...protocol import frame
from . import blocks, maze as maze_data, select
from .run import DungeonRun, DungeonSession

ENTER_OPCODE = frame.Opcode(1, 16, frame.OpcodeEncoding.U8_U16LE, True)
MAP_OPCODE = frame.Opcode(0, 28, frame.OpcodeEncoding.U8_U16LE, True)
SPAWN_OPCODE = frame.Opcode(0, 29, frame.OpcodeEncoding.U8_U16LE, True)

BODY_SIZE = 32
MAP_BODY_SIZE = 48

#: How many response frames the `DUNGEON-ENTRY` line counts -- the pair, not
#: the tutorial's pre-frames.
ANSWERED_FRAMES = 2

#: `training=False` in every `DUNGEON-ENTRY` line the capture holds.
TRAINING = False

#: The first record of a `(0,29)` sits here, after the 40B header and three
#: bytes that are `00 00 00` for a populated room and `ff 00 00` for an
#: empty one.
RECORDS_AT = 43
RECORD_SIZE = 22

#: What a `(0,29)` reports as a map id when the client walks back into a room
#: it has already been in, and the size both revisited frames in the capture
#: are -- 34B of content in a 40B frame, zero records.
REVISIT_MAP = 0xFF00
REVISIT_CONTENT = 34


@dataclass(frozen=True, slots=True)
class Request:
    """`SelectDungeonRequest`, as the reference's own line spells it."""

    dungeon: int
    difficulty: int
    entry_option: int
    mode: int
    hell_difficulty: int
    quest: int

    @classmethod
    def parse(cls, plain: bytes) -> "Request":
        if len(plain) != BODY_SIZE:
            raise ValueError(f"(1,16) body is {len(plain)}B, expected {BODY_SIZE}")
        return cls(dungeon=struct.unpack_from("<I", plain, 0)[0],
                   difficulty=struct.unpack_from("<I", plain, 4)[0],
                   entry_option=plain[8],
                   mode=0,
                   hell_difficulty=0,
                   quest=struct.unpack_from("<H", plain, 16)[0])

    def describe(self) -> str:
        return (f"SelectDungeonRequest {{ DungeonId = {self.dungeon}, "
                f"Difficulty = {self.difficulty}, "
                f"EntryOption = {self.entry_option}, Mode = {self.mode}, "
                f"HellDifficulty = {self.hell_difficulty} }}")


def retry_quest(session: DungeonSession,
                in_progress: set[int]) -> tuple[int, int, int] | None:
    """The maze of a quest the character is on, if the gate opens one.

    Fitted to one send: dungeon 5 asked with quest 0, answered from dungeon
    6's maze 1 -- 3147's maze -- after a walk over the gate's own worldmap
    nodes.  Returns `(dungeon, maze index, quest)` for the first hit.
    """
    gate = select.gate(session.town.town, session.town.area)
    if gate is None:
        return None
    for dungeon in blocks.worldmap_nodes(gate.worldmap):
        for index, row in enumerate(maze_data.mazes(dungeon)):
            connection = row.get("questConnection")
            if connection and connection[1] in in_progress:
                return dungeon, index, connection[1]
    return None


def maze_for(dungeon: int, quest: int) -> int | None:
    """The maze the request's own quest names, if this dungeon has one.

    None is the caller's cue to try the native retry and then the dungeon's
    own first maze; it is not a refusal.
    """
    return maze_data.quest_maze(dungeon, quest) if quest else None


def default_maze(dungeon: int) -> int | None:
    """The maze a pick with no matching quest enters -- the dungeon's first.

    None only for an id table 045 does not hold, which nothing observed
    sends and the ignored line covers.  The corpus cannot tell this rule
    from "the first maze without a `questConnection`": the two differ only
    where that plain maze is not index 0 (dungeon 5's is maze 1 -- 807 of
    the table's dungeons have theirs elsewhere), and no bare pick of such a
    dungeon was ever captured.  Index 0 is the reading every observed
    fallback produces and the one needing no second concept; a reference
    capture of one of those picks would settle it.
    """
    return 0 if maze_data.mazes(dungeon) else None


def map_body(run: DungeonRun) -> bytes:
    """`(0,28)`: the dungeon, the maze, the boss cell, and the constants."""
    rows = maze_data.mazes(run.dungeon)
    boss_x, boss_y = maze_data.boss(rows[run.maze])
    return (struct.pack("<I", run.dungeon) + bytes(3)
            + bytes([run.maze & 0xFF, boss_x & 0xFF, boss_y & 0xFF])
            + b"\xff\xff" + struct.pack("<I", 0) + b"\x0c\x00\x00"
            + b"\xff" * 4 + bytes(25))


def room_body(run: DungeonRun, *, revisit: bool) -> bytes:
    """`(0,29)`: the room the run is standing in, built from its cell, seed
    and id offset.

    A revisit drops the room entirely -- 40B whose map id is `REVISIT_MAP`,
    no record count and 34B of content against the first visit's 41 + 22 x
    records -- because the client already has the room it drew.  The records
    come in the groups `maze.room_spawns` orders them in, and each group
    restarts the mark counter its last record zeroes: 53129's seven are
    `1 2 3 4 0` then `1 0`, with only the frame's last record carrying 0xff
    in the fourth mark byte.
    """
    out = bytearray(40)
    out[0], out[1] = run.cell[0] & 0xFF, run.cell[1] & 0xFF
    out[3:7] = run.seed
    out[8], out[9] = 0x00, 0x01
    out[17:25] = b"\xff" * 8
    if revisit:
        out[31] = 0x00
        out[32:36] = struct.pack("<I", REVISIT_MAP)
        return bytes(out)
    out[31] = 0x01
    out[32:36] = struct.pack("<I", run.map_id)
    basis = maze_data.basis_level(run.dungeon)
    groups = maze_data.room_spawns(run.map_id)
    total = sum(len(group) for group in groups)
    out[36:40] = struct.pack("<I", total)
    out.append(0xFF if not total else 0x00)
    out += bytes(2)
    n = 0
    for group in groups:
        for i, spawn in enumerate(group):
            last = n == total - 1
            mark = 0x00 if i == len(group) - 1 else i + 1
            out += (struct.pack("<H", run.first_id + n)
                    + struct.pack("<I", spawn.monster)
                    + bytes([basis, spawn.flags]) + bytes(8)
                    + bytes([mark, 0x00, mark, 0xFF if last else 0x00]) + bytes(2))
            n += 1
    if total:
        del out[-2:]
    out += bytes(-len(out) % 8)
    return bytes(out)


def content_len(map_id: int, *, revisit: bool) -> int:
    """The `N29=` a room's line counts: its bytes before the padding."""
    if revisit:
        return REVISIT_CONTENT
    total = maze_data.record_count(map_id)
    return RECORDS_AT if not total else RECORDS_AT - 2 + RECORD_SIZE * total


def monster_count(run: DungeonRun) -> int:
    """`monsters=` in the `DUNGEON-ENTRY` line: the start room's table rows."""
    return len(maze_data.room_monsters(run.map_id))


def entry_line(key: int, run: DungeonRun, request: Request, monsters: int) -> str:
    """The `DUNGEON-ENTRY` prose after the bare `conn=N `."""
    rows = maze_data.mazes(run.dungeon)
    boss_x, boss_y = maze_data.boss(rows[run.maze])
    return (f"key={key} dungeon={run.dungeon} difficulty={request.difficulty} "
            f"entryOption={request.entry_option} maze={run.maze} "
            f"start=({run.cell[0]},{run.cell[1]}) map={run.map_id} "
            f"boss=({boss_x},{boss_y}) monsters={monsters} "
            f"training={TRAINING} -> {ANSWERED_FRAMES} frame(s)")


def request_line(key: int, level: int, request: Request) -> str:
    return f"key={key} level={level} request={request.describe()}"


def tutorial_line(key: int, pending: int) -> str:
    return (f"tutorial auto-entry: key={key} dungeon={pending} (pending={pending}, "
            f"client-authoritative, synthetic worldmap)")


def pre_frames_line() -> str:
    """The tutorial's pre-frame note, verbatim -- the two content sizes are
    the reference's own count, 4B and 35B against the 16B and 40B sent."""
    return (f"tutorial loading pre-frames: (0,3) {blocks.ACK_CONTENT} "
            f"+ (0,27) {blocks.HEAD_CONTENT} head=01")


def committed_line(cleared: bool) -> str:
    return f"tutorial entry committed; pending cleared={cleared}"


def retry_line(source: int, quest: int, dungeon: int) -> str:
    return f"native retry source={source} -> quest={quest} dungeon={dungeon}"


def ignored_line(dungeon: int) -> str:
    return (f"entry requires dungeon selection and no existing run; "
            f"ignoring (dungeon={dungeon})")
