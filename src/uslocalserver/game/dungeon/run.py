"""What one connection knows about dungeons: the run it is in, and the rest.

`key` and `town` are mirrors of the town session's -- the key is the same
`slot_index + 1` every dungeon frame opens with, and `town` is where `(1,15)`
looks its gate up and where `(1,42)` reads the row it settles back to.

`next_id` is the session's spawn-id counter.  It is seeded at 1 and advances
by a maze's table monsters when a run enters it, which is what makes the
capture's entries start at 1, 17, 44 and 71 -- `maze.maze_total` has the
arithmetic.  `selected` is set by a `(1,15)` that found a gate: a `(1,16)`
that is not the tutorial entry needs one, and the one ignored entry in the
capture is ignored for that reason as much as for the run it already had.
`settled` is `(1,46)`'s flag: it marks the run cleared, is read back by
`(1,42)`'s note, and retires the run in place -- see `in_progress`.  `started`
and `difficulty` are the clear chain's: the first is what its `clear=` clock
counts from, the second is the `(1,16)` request's own picker value, printed by
the boss kill's `QUEST-COMBAT` line.

A run also keeps the rooms it has drawn: `drawn` maps a room to the first
spawn id its records took, `sent` counts the records the run has handed out,
and `killed` holds the `(1,39)` ids.  Together they are what a room's
`alive=k/n` and a revisit's silence read -- see `enter`, `kill` and `alive`.
`cleared` is the boss rooms whose `(0,31)` has already gone out: the frame
follows the kill that empties the room, and a later kill in it -- dungeon 5's
cinematic 75099, one line after the boss -- must not send it twice.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ...persistence.characters import CharacterSummary
from ..town import movement
from . import drops
from . import maze as maze_data
from .maze import Cell

if TYPE_CHECKING:
    from . import card


@dataclass(slots=True)
class DungeonRun:
    """The run in progress: which maze, which cell, and the id base it started
    with.  `seed` is its own four random bytes -- every `(0,29)` of a run
    repeats it, and the next run draws a new one."""

    dungeon: int
    maze: int
    cell: Cell
    map_id: int
    seed: bytes
    base: int
    difficulty: int = 0
    started: float = field(default_factory=time.monotonic)
    sent: int = 0
    offset: int = 0
    drawn: dict[int, int] = field(default_factory=dict)
    killed: set[int] = field(default_factory=set)
    cleared: set[int] = field(default_factory=set)

    def elapsed_ms(self) -> int:
        """The `(1,46)` line's `clear=`: milliseconds since the run began.

        The reference's own clock, measured from the run's creation: the
        capture's three read 64769/36268/32380 ms, each within 0.13s of its
        run's `(1,16)` line to its `(1,46)`.  A replay is fed the exact value
        instead (`clear.Card`).
        """
        return int((time.monotonic() - self.started) * 1000)

    @property
    def first_id(self) -> int:
        """The spawn id the room the run is standing in starts its records at."""
        return self.base + self.offset

    def enter(self, map_id: int) -> bool:
        """Draw the room's records, or report that this run has been here.

        The first visit takes the run's next free ids -- `base + sent` and
        the room's records after it -- and a later one reuses them exactly:
        dungeon 6's room 76143 is 96..99 both times its run walks in, and the
        second `(0,29)` carries the room id 0xff00 and no records at all, so
        the reuse is the client's own.
        """
        first = self.drawn.get(map_id)
        if first is None:
            self.drawn[map_id] = self.base + self.sent
            self.offset = self.sent
            self.sent += maze_data.record_count(map_id)
            return False
        self.offset = first - self.base
        return True

    def move_to(self, cell: Cell) -> bool | None:
        """A `(1,45)`: the cell and its map move together, and the room they
        land in is drawn.  None when the cell holds no map."""
        map_id = maze_data.map_id_at(maze_data.mazes(self.dungeon)[self.maze], cell)
        if map_id is None:
            return None
        self.cell, self.map_id = tuple(cell), map_id
        return self.enter(map_id)

    def kill(self, seq: int) -> tuple[int, maze_data.Spawn] | None:
        """A `(1,39)`: the monster that died, if the id is ours.

        Returns the room and the record the id names.  Only the ids of rooms
        this run has drawn count.  The reference refuses the rest -- `could
        not find a live monster sequence in the request` -- and one send in
        the capture is exactly that: id 43, of a run already left behind,
        while this run's rooms start at 71.
        """
        for map_id, first in self.drawn.items():
            records = maze_data.room_records(map_id)
            if first <= seq < first + len(records):
                self.killed.add(seq)
                return map_id, records[seq - first]
        return None

    def live_id(self) -> int:
        """The id a refusal prints: the lowest record the run still has
        standing in the room it is in.

        The four `(1,39)` refusals across the logs read 44 (dungeon 5's start
        room, nothing killed yet), 36 (the same room in the next session),
        585 (76254 with 584/586/587/588 already down) and 654 (room 76307 a
        second after the run walked in) -- each the room's lowest id the run
        has not been told is dead.  A room with nothing left standing reads
        its first id.
        """
        first = self.first_id
        for index, spawn in enumerate(maze_data.room_records(self.map_id)):
            if spawn.counts and first + index not in self.killed:
                return first + index
        return first

    def alive(self, map_id: int) -> tuple[int, int]:
        """`alive=k/n` for a room: the monsters still standing over its
        records.  The cinematic actors and the apcs are records that never
        count, so a killed one of those leaves `k` where it was."""
        first = self.drawn[map_id]
        records = maze_data.room_records(map_id)
        return (sum(1 for i, spawn in enumerate(records)
                    if spawn.counts and first + i not in self.killed),
                len(records))

    def dummies(self, map_id: int) -> int:
        """How many of the room's hunt dummies are still standing."""
        first = self.drawn[map_id]
        return sum(1 for i, spawn in enumerate(maze_data.room_records(map_id))
                   if maze_data.dummy(spawn) and first + i not in self.killed)


@dataclass(slots=True)
class DungeonSession:
    """Everything one connection's dungeon play carries between requests.

    `ground` is what the kills have left lying about: the ground slot they
    were handed, the room they fell in, and the `(0,38)` row itself --
    `(1,43)` looks a slot up here, takes the row away, and refuses the slot
    if it is gone or fell in another room.  It outlives the runs that filled
    it, like `next_ground` does: the 09-28 capture's tutorial drops (slots 1
    and 2) sit on the same counter as dungeon 3's slot 3.
    """

    character_id: int
    key: int
    town: movement.TownSession
    next_id: int = 1
    next_ground: int = 1
    ground: dict[int, tuple[int, drops.Row]] = field(default_factory=dict)
    run: DungeonRun | None = None
    selected: bool = False
    settled: bool = False
    #: The last clear's card context, which the flips and the settlement read.
    #: It outlives its run -- `(1,72)` leaves the run but a replay of the
    #: settlement still needs the flag its story set -- and the next clear
    #: replaces it.
    result: "card.Result | None" = None

    def drop(self, map_id: int, rows: tuple[drops.Row, ...]) -> None:
        """A kill's rows join the ground, in the room they fell in."""
        for row in rows:
            self.ground[row.slot] = (map_id, row)

    @classmethod
    def of(cls, summary: CharacterSummary, town: movement.TownSession) -> "DungeonSession":
        return cls(character_id=summary.character_id, key=summary.slot_index + 1,
                   town=town)

    def begin(self, dungeon: int, index: int, difficulty: int = 0) -> DungeonRun:
        """Enter a maze: the new run takes the counter's current value.

        `difficulty` is the `(1,16)` request's own picker value -- 0 in every
        capture entry -- and is carried for the clear chain's `QUEST-COMBAT`
        line, which prints it.
        """
        cell, map_id = maze_data.start(maze_data.mazes(dungeon)[index])
        run = DungeonRun(dungeon=dungeon, maze=index, cell=cell, map_id=map_id,
                         seed=os.urandom(4), base=self.next_id,
                         difficulty=difficulty)
        run.enter(map_id)
        self.next_id += maze_data.maze_total(dungeon, index)
        self.run = run
        self.settled = False
        return run

    @property
    def in_progress(self) -> bool:
        """Whether a run is still blocking the gates.

        A clear retires the run where it stands: `(1,15)` draws a fresh gate
        burst right after a `(1,46)` (21:11:02, after dungeon 3 was cleared)
        and `(1,16)` enters again (21:12:20), while the run left behind is
        still what `(1,42)` names -- `leaving dungeon=7115 settled=True` is
        the cleared one.  So the flag, not the run, is what the two guards
        read; the run itself goes away only on `(1,42)`.
        """
        return self.run is not None and not self.settled

    def leave(self) -> DungeonRun | None:
        """`(1,42)`: the run ends, whatever its state."""
        run, self.run = self.run, None
        self.selected = False
        self.settled = False
        return run
