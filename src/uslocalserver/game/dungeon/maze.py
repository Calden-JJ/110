"""The table-driven lookups the dungeon chain does: mazes, maps, monsters.

Two tables carry the whole geometry -- 045 `dungeon_content`, whose `mazes`
each hold a `maps` list of `{type, x, y, mapId}` cells plus a `startMap` and a
`bossMap`, and 046 `map_content`, whose maps each hold their monster list.
Nothing here is fitted: the observed frames agree with the tables cell for
cell and monster for monster -- the one frame that carries more than table 046
holds is table 049's two apcs, which `room_spawns` appends.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any, NamedTuple

from ...game import data

Cell = tuple[int, int]
Maze = dict[str, Any]

#: The record flag byte `(0,29)` carries: a boss that is not also a cinematic
#: actor, and table 049's apcs.  Everything else is 0x00.
BOSS_FLAGS = 0x03
APC_FLAGS = 0x05


class Spawn(NamedTuple):
    """One `(0,29)` record: the monster, its flag byte, and whether killing
    it moves the room's `alive` count.

    `words` is table 046's own `monsterFlags` row for the record -- the flag
    byte is a summary of it and cannot be read back: a `cinematic` boss and a
    plain one both carry 0x00 and 0x03, and the combat chain's branches turn
    on `cinematic`/`dummy`.  An apc's word is the literal `apc`.
    """

    monster: int
    flags: int
    counts: bool
    words: tuple[str, ...] = ()


@lru_cache(maxsize=1)
def _dungeons() -> dict[int, Any]:
    return {d.id: d for d in data.rows("dungeon_content", "dungeons")}


@lru_cache(maxsize=1)
def _maps() -> dict[int, Any]:
    return {m.id: m for m in data.rows("map_content", "maps")}


def mazes(dungeon_id: int) -> tuple[Maze, ...]:
    dungeon = _dungeons().get(dungeon_id)
    return () if dungeon is None else tuple(dungeon.mazes)


def basis_level(dungeon_id: int) -> int:
    """The `basisLevel` every `(0,29)` record of this dungeon carries."""
    dungeon = _dungeons().get(dungeon_id)
    return 0 if dungeon is None else dungeon.basisLevel


def quest_maze(dungeon_id: int, quest: int) -> int | None:
    """The maze whose `questConnection` names this quest, if any.

    A connection is `(0, quest, -1)` in every maze that has one; dungeon 3's
    quest 3145 is on maze 1, dungeon 5's 3146 on maze 0, dungeon 6's 3147 on
    maze 1 -- which is what the three observed entries pick.
    """
    for index, maze in enumerate(mazes(dungeon_id)):
        connection = maze.get("questConnection")
        if connection and connection[1] == quest:
            return index
    return None


def start(maze: Maze) -> tuple[Cell, int]:
    """The maze's landing cell and the map id there."""
    cell = tuple(maze["startMap"])
    return cell, map_id_at(maze, cell)


def boss(maze: Maze) -> Cell:
    return tuple(maze["bossMap"])


def map_id_at(maze: Maze, cell: Cell) -> int | None:
    for entry in maze["maps"]:
        if (entry["x"], entry["y"]) == tuple(cell):
            return entry["mapId"]
    return None


def cell_of(maze: Maze, map_id: int) -> Cell | None:
    for entry in maze["maps"]:
        if entry["mapId"] == map_id:
            return (entry["x"], entry["y"])
    return None


def room_monsters(map_id: int) -> list[int]:
    """The map's own monster ids, in table 046's order.

    This is the table's count, which is what the spawn-id arithmetic runs on
    -- a room's `(0,29)` may list more records than this; `room_spawns` has
    the frame's own view.
    """
    entry = _maps().get(map_id)
    if entry is None:
        return []
    return [monster[0] for monster in entry.monsters or ()]


@lru_cache(maxsize=1)
def _apcs() -> dict[int, tuple[int, ...]]:
    return {row.map: tuple(apc["code"] for apc in row.apcs)
            for row in data.rows("tutorial_apcs")}


def room_spawns(map_id: int) -> tuple[tuple[Spawn, ...], ...]:
    """A room's `(0,29)` records, in the two groups the frame marks.

    The map's own monsters first, then table 049's apcs -- the two extra
    records of map 53129 (ids 316 and 317), which no map in 046 holds.

    The flag byte is 0x03 for a boss that is not also cinematic, 0x05 for an
    apc, 0x00 otherwise.  Only the map's monsters count toward `alive=k/n`,
    and only when they are not cinematic: dungeon 3's room 76126 draws eight
    records -- the boss 107000903, four of 109014870, and three story actors
    -- and its line reads 5/8; a kill of one of the three leaves the count
    where it was.
    """
    entry = _maps().get(map_id)
    monsters = () if entry is None else entry.monsters or ()
    flags = () if entry is None else entry.monsterFlags or ()
    own = tuple(
        Spawn(row[0],
              BOSS_FLAGS if "boss" in flag and "cinematic" not in flag else 0x00,
              "cinematic" not in flag, tuple(flag))
        for row, flag in zip(monsters, flags))
    groups = (own,)
    extra = _apcs().get(map_id, ())
    if extra:
        groups += (tuple(Spawn(code, APC_FLAGS, False, ("apc",)) for code in extra),)
    return groups


def room_records(map_id: int) -> tuple[Spawn, ...]:
    """The room's `(0,29)` records as one list, groups flattened."""
    return tuple(spawn for group in room_spawns(map_id) for spawn in group)


def record_count(map_id: int) -> int:
    """How many records the room's `(0,29)` carries, apcs included."""
    return sum(len(group) for group in room_spawns(map_id))


def rank(spawn: Spawn) -> str:
    """`rank=` in a kill line, from the record's own flag byte.

    Fitted over the four logged sessions: of ~6,800 kills, 129 read Boss and
    two Apc, and every one of them is the flag byte spelled out -- the boss
    word with no `cinematic`, and an apc group.  One Boss line has a code the
    map's own record list does not hold, so the fit is 128/129 on that side.
    It is the *record*'s rank, not the room's: dungeon 7115's boss-cell room
    53130 is killed by a Normal record and reads Normal.
    """
    return {BOSS_FLAGS: "Boss", APC_FLAGS: "Apc"}.get(spawn.flags, "Normal")


def cinematic(spawn: Spawn) -> bool:
    """Whether the record is a story actor: it never counts and never grants
    experience -- see `die.resolution` for the two branches it splits into."""
    return "cinematic" in spawn.words


def dummy(spawn: Spawn) -> bool:
    """Whether the record is a hunt dummy -- `displayhuntdummy` in one room,
    plain `dummy` in another.  Killing the last one standing in a cleared
    room is what `cinematic map objective confirmed` reports."""
    return any("dummy" in word for word in spawn.words)


def maze_total(dungeon_id: int, index: int) -> int:
    """How many spawn ids entering this maze adds to the session's counter.

    Fitted to the chain the capture shows: the session's ids run 1..18
    through dungeon 7115's four rooms, then 17 through dungeon 3's five, then
    44 through dungeon 5's, then 71 through dungeon 6's -- and 7115's four
    maps hold 3+3+5+5 monsters, dungeon 3's five hold 4+5+6+4+8, dungeon 5's
    1+4+5+6+11, dungeon 6's five 0+4+4+5+12.  Each entry's first id is the
    running total plus one, so the counter advances by the maze's *table*
    monsters, not by the records its rooms send: 53129 sends seven (two of
    them apcs) but counts five, and the abandoned dungeon 6 run holds ids 71
    to 74 while the next run starts at 96, seventeen past the rooms it never
    walked into.
    """
    return sum(len(room_monsters(entry["mapId"])) for entry in mazes(dungeon_id)[index]["maps"])
