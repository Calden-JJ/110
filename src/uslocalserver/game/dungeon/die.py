"""`(1,39)` COMBAT-DIE-39 -- the client's report that a monster died, and the
chain the reference answers it with.

The request is 128B in 68 of the capture's 79 sends and 112B in the other
eleven; whatever the two shapes differ in, their first byte is the same
thing: the dying monster's spawn id.  The reference's own line repeats it as
`seq=`, and all 78 answered sends agree with the note that follows them.  The
send they do not answer is the reference's own refusal -- `could not find a
live monster sequence in the request`, id 43 while the live run hands out 71
and up -- and its `plain=` is the *whole* request, 112 bytes, where the
`WARN UNHANDLED` lines stop at 96.

**The answer.**  Every kill sends `(0,38)`, the drops it left on the ground:
`u16le seq`, `u16le count`, `count` records of 177B, then `00 00 ff 00`, then
zero padding to a multiple of 4 -- so its body is 8B without drops, 188B with
one, 364B with two, and it is `drops.record` that spells a record out.  An
ordinary kill follows it with `(0,37)`, the character's experience, SP and
TP::

    [0]     u8     level
    [1:9]   u64le  total experience
    [12]    u8     00 pad
    [13:15] u16le  SP remaining
    [15:17] u16le  SP remaining
    [17:19] u16le  TP remaining
    [19:21] u16le  TP remaining

96B on the wire, its 82 content bytes zero-padded to the tile's 16.  The two
SP halves carry the same number and the TP halves their own: the tables'
grants less what the save has spent (`spent_for`), which for a character that
never learned a skill is exactly `sum(spTable[:level + 1])` -- 0/30/60/120/180
at levels 1/2/3/5/7 in the capture.  Every value the 09-28 run carries is
under 256, where this little-endian reading and a big-endian one two bytes to
the left spell the same bytes; the 09-30 save (level 55) separates the two --
985 is `d9 03` at [13], [12] zero.  The clear's own `(0,37)` at `(1,46)` is
the same body -- `clear.py` builds it from this one.  A kill that empties the
maze's boss cell appends `(0,31)` ENABLE_CLEAR last, with the clear chain's
own frames -- see `resolution`.

**The three branches.**  A record's own flag words pick the line's outcome --
`maze.cinematic` and `maze.dummy` read them:

* a story actor (`cinematic`, not a dummy) -- `story/friendly actor, no
  experience`, one frame, no exp;
* a hunt dummy in a room with nothing left standing (`cinematic` + `dummy` +
  `alive=0` + no other dummy left: 188 of 189 such kills across the four
  logged sessions) -- `+0 exp ...; cinematic map objective confirmed`, one
  frame;
* anything else -- the exp line, two frames.

**The arithmetic.**  The gain is `byLevel[monsterLevel - 1]` (table 015),
times 10/9 floored when the character's level is below the monster's: dungeon
3's basis level 3 grants 80 at level 1-2 and 72 at level 3, which is what
pins it.  `monsterLevel` is the dungeon's `basisLevel` (045), the level is
`level_for(exp)` over the cumulative `expTable` (013), and quest rewards --
the only non-kill experience in the capture -- are *not* derived: they are
what `Play.exp_before` carries in.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Iterable

from ...game import data
from ...protocol import frame
from . import blocks, drops, maze as maze_data
from .maze import Spawn
from .run import DungeonRun, DungeonSession

DIE_OPCODE = frame.Opcode(1, 39, frame.OpcodeEncoding.U8_U16LE, True)
DROP_OPCODE = frame.Opcode(0, 38, frame.OpcodeEncoding.U8_U16LE, True)
EXP_OPCODE = frame.Opcode(0, 37, frame.OpcodeEncoding.U8_U16LE, True)

#: The frame's wire size; the content is 82B, the rest is tile padding.
EXP_BODY_SIZE = 96

#: `contractBonus=` in every one of the capture's 79 exp lines.
CONTRACT_BONUS = 0

ACTOR_OUTCOME = "story/friendly actor, no experience"
OBJECTIVE_OUTCOME = "cinematic map objective confirmed"
ROOM_CLEAR_SUFFIX = (" (room clear; dungeon clear conditions pending or "
                     "already acknowledged)")
ENABLE_SUFFIX = " including (0,31) ENABLE_CLEAR (boss room cleared)"

REFUSAL = "could not find a live monster sequence in the request"


def sequence(plain: bytes) -> int:
    """The spawn id the request names, `seq=` in the reference's line."""
    return plain[0]


def refusal_note(plain: bytes, alive: int) -> str:
    """What a `(1,39)` that names no drawn record is answered with.

    Nothing is sent and the line carries the whole request in upper-case hex.
    `alive` is the lowest id the run still has standing in the room it is in
    -- `run.DungeonRun.live_id`, not the session's id counter: the four
    logged refusals read 44, 36, 585 and 654, each that room's lowest
    un-killed record.
    """
    return (f"{REFUSAL} (plain={plain.hex().upper()}, alive={alive}); ignoring")


@lru_cache(maxsize=1)
def _by_level() -> tuple[int, ...]:
    return tuple(data.load("monster_experience")["byLevel"])


@lru_cache(maxsize=1)
def _exp_table() -> tuple[int, ...]:
    return tuple(data.load("character_stats")["expTable"])


@lru_cache(maxsize=1)
def _sp_table() -> tuple[int, ...]:
    return tuple(data.load("skill_content")["spTable"])


@lru_cache(maxsize=1)
def _tp_table() -> tuple[int, ...]:
    return tuple(data.load("skill_content")["tpTable"])


@lru_cache(maxsize=1)
def _jobs() -> dict[str, dict]:
    return data.load("skill_content")["jobs"]


def level_for(experience: int) -> int:
    """The level a cumulative experience total stands at.

    `expTable` holds the threshold to *reach* each level, one row per level
    from level 2 on, so the climb is `while exp >= expTable[level - 1]`.
    """
    level, table = 1, _exp_table()
    while level <= len(table) and experience >= table[level - 1]:
        level += 1
    return level


def base_experience(monster_level: int, character_level: int) -> int:
    """What one kill of this monster grants, `base=` in the line.

    Below the monster's level the row scales up by 10/9, floored; above it
    the same row scales down by `monster_level / character_level`, floored --
    the 09-30 save's level-55 character kills dungeon 3's level-3 row (72)
    for +3, which pins the down branch.
    """
    value = _by_level()[monster_level - 1]
    if character_level < monster_level:
        return value * 10 // 9
    if character_level > monster_level:
        return value * monster_level // character_level
    return value


def sp_for(level: int) -> int:
    """The SP the tables grant through this level, before anything is spent."""
    return sum(_sp_table()[:level + 1])


def tp_for(level: int) -> int:
    """The TP the tables grant through this level, before anything is spent."""
    return sum(_tp_table()[:level + 1])


def remaining(level: int, spent: tuple[int, int]) -> tuple[int, int]:
    """The frame's `(sp, tp)` at this level: the grants less what is spent,
    never below zero."""
    return (max(0, sp_for(level) - spent[0]), max(0, tp_for(level) - spent[1]))


def spent_for(class_id: int,
              skills: Iterable[tuple[int, int]]) -> tuple[int, int]:
    """What a save's skill rows have spent, `(sp, tp)`.

    `skills` is the character's `character_skills` rows as `(skill_id,
    level)`, and each level's price comes from the class's own block of the
    skill table -- a row the block does not hold costs nothing.  The 09-30
    save (level 55) reads 4010 by this rule where its own frame implies
    3935; the 75 the model cannot spell is a known display-only debt.
    """
    records = {rec["id"]: rec for rec
               in _jobs().get(str(class_id), {}).get("skills", ())}
    sp = tp = 0
    for skill_id, level in skills:
        rec = records.get(skill_id)
        if rec is None:
            continue
        sp += _paid(rec.get("cost"), level)
        tp += _paid(rec.get("tpCost"), level)
    return sp, tp


def _paid(costs, level: int) -> int:
    """One skill's price through `level`: a flat value, or a short per-level
    ladder whose last entry repeats."""
    costs = tuple(costs or (0,))
    return sum(costs[min(i, len(costs) - 1)] for i in range(level))


def exp_body(level: int, experience: int, sp: int, tp: int) -> bytes:
    """`(0,37)`: level, the cumulative total, SP twice and TP twice.

    The capture's totals all fit three bytes, and three of them are all any
    of its 96B bodies show; the field is written eight wide because the
    09-25/09-26 notes carry level-110 totals past 2^24 (10790517643), which
    three bytes cannot hold, and `giant.py` writes the same row the same way.
    """
    out = bytearray(EXP_BODY_SIZE)
    out[0] = level & 0xFF
    out[1:9] = struct.pack("<Q", experience)
    out[13:15] = struct.pack("<H", sp)
    out[15:17] = struct.pack("<H", sp)
    out[17:19] = struct.pack("<H", tp)
    out[19:21] = struct.pack("<H", tp)
    return bytes(out)


@dataclass(frozen=True, slots=True)
class Play:
    """The oracle's own answer for one kill, when a replay feeds it in.

    `exp_before` is the character's experience *before* the kill's own gain,
    which a quest reward -- the one source the rule cannot derive -- may have
    moved since the previous kill.  `drops` are the items the kill left on
    the ground, in slot order: a live server rolls them, a replay is handed
    them (PLAN.md's "results fed from the log").
    """

    exp_before: int
    drops: tuple[drops.Fact, ...] = ()


@dataclass(frozen=True, slots=True)
class Boss:
    """The clear burst a boss-cell-clearing kill carries, and its line.

    `(0,342)`, `(0,291)` and `(0,21)` -- the quest state the kill's trigger
    write leaves -- plus `(0,115)` when the record it killed is Boss-ranked.
    `clear.boss_burst` builds it, `resolution` splices it in before `(0,31)`,
    and the caller logs its note *before* the kill's own line: the capture's
    two `QUEST-COMBAT` lines each precede their `COMBAT-DIE-39`.
    """

    frames: tuple[tuple[frame.Opcode, bytes], ...]
    note: str


@dataclass(frozen=True, slots=True)
class Resolution:
    """One kill's whole answer: its frames, its line, and where the character
    stands when they have gone out.

    `quest_note` is the `QUEST-COMBAT` line a clear burst carries, `None` for
    every kill that does not empty a boss cell a `clear map` quest names.
    """

    frames: tuple[tuple[frame.Opcode, bytes], ...]
    note: str
    level: int
    experience: int
    quest_note: str | None = None

    @property
    def experience_reply(self) -> tuple[frame.Opcode, bytes] | None:
        return next((f for f in self.frames if f[0] == EXP_OPCODE), None)


def resolution(session: DungeonSession, run: DungeonRun, map_id: int,
               spawn: Spawn, seq: int, play: Play,
               boss: Callable[[int], Boss | None] | None = None, *,
               spent: tuple[int, int] = (0, 0)) -> Resolution:
    """Build the answer to one `(1,39)`, and hand its rows to the ground.

    `run.kill` has already recorded the id, so the room's counts read the
    state this kill leaves behind.  `boss` is the clear chain's window into a
    kill that empties a `clear map` quest's boss cell: it is called with the
    level the kill lands on -- `(0,21)` lists what that level opens, not the
    one the row still carries -- and its frames go in before `(0,31)`.
    `spent` is what the save's skill rows have paid out (`spent_for`), which
    the frame's SP/TP columns come net of.
    """
    rows = drops.rows(play.drops, session.next_ground)
    session.next_ground += len(rows)
    session.drop(map_id, rows)
    branches = _branch(run, map_id, spawn, play.exp_before)
    frames: list[tuple[frame.Opcode, bytes]] = [
        (DROP_OPCODE, drops.body(seq, rows))]
    if branches.gain is not None:
        frames.append((EXP_OPCODE, exp_body(
            branches.level, branches.experience,
            *remaining(branches.level, spent))))
    cleared, suffix = _clear(run, map_id)
    quest_note = None
    if cleared:
        burst = None if boss is None else boss(branches.level)
        if burst is not None:
            frames += burst.frames
            quest_note = burst.note
        if maze_data.rank(spawn) == "Boss":
            frames.append((blocks.BOSS_ACK_OPCODE, blocks.boss_ack_body(seq)))
        frames.append((blocks.ENABLE_OPCODE, blocks.ENABLE_BODY))
        suffix = ENABLE_SUFFIX
    return Resolution(
        frames=tuple(frames),
        note=_note(run, map_id, spawn, seq, rows, branches, len(frames), suffix),
        level=branches.level, experience=branches.experience,
        quest_note=quest_note)


@dataclass(frozen=True, slots=True)
class _Branch:
    """What the kill did to the character: `gain` is None for the two
    branches that print no exp at all."""

    outcome: str
    gain: int | None
    level: int
    experience: int


def _branch(run: DungeonRun, map_id: int, spawn: Spawn,
            exp_before: int) -> _Branch:
    level = level_for(exp_before)
    if maze_data.cinematic(spawn):
        if maze_data.dummy(spawn) and run.alive(map_id)[0] == 0 \
                and run.dummies(map_id) == 0:
            return _Branch(
                outcome=(f"+0 exp (base=0, contractBonus={CONTRACT_BONUS}) -> "
                         f"total={exp_before} level={level}; "
                         f"{OBJECTIVE_OUTCOME}"),
                gain=None, level=level, experience=exp_before)
        return _Branch(outcome=ACTOR_OUTCOME, gain=None, level=level,
                       experience=exp_before)
    gain = base_experience(maze_data.basis_level(run.dungeon), level)
    total = exp_before + gain
    after = level_for(total)
    outcome = (f"+{gain} exp (base={gain}, contractBonus={CONTRACT_BONUS}) -> "
               f"total={total} level={after}")
    if after > level:
        outcome += f" **LEVEL UP** from {level}"
    return _Branch(outcome=outcome, gain=gain, level=after, experience=total)


def _clear(run: DungeonRun, map_id: int) -> tuple[bool, str]:
    """Whether this kill cleared the boss room, and the line's suffix.

    The frame follows the kill that empties the maze's boss cell, once per
    run: dungeon 5's cinematic 75099 dies one line after the boss, in the
    same emptied room, and is *not* answered with a second ENABLE_CLEAR --
    its suffix is the room-clear one.  Fitted over ~6,800 logged kills, 15
    disagree (8 sends this rule does not make, 7 it makes and the reference
    does not); all of them are in dungeons the capture never visits.
    """
    if run.alive(map_id)[0]:
        return False, ""
    if tuple(run.cell) != maze_data.boss(maze_data.mazes(run.dungeon)[run.maze]):
        return False, ROOM_CLEAR_SUFFIX
    if map_id in run.cleared:
        return False, ROOM_CLEAR_SUFFIX
    run.cleared.add(map_id)
    return True, ENABLE_SUFFIX


def _note(run: DungeonRun, map_id: int, spawn: Spawn, seq: int,
          rows: tuple[drops.Row, ...], branch: _Branch, frames: int,
          suffix: str) -> str:
    """The `COMBAT-DIE-39` prose after the bare `conn=N `."""
    alive, total = run.alive(map_id)
    boss_x, boss_y = maze_data.boss(maze_data.mazes(run.dungeon)[run.maze])
    return (f"dungeon={run.dungeon} map={map_id} seq={seq} "
            f"code={spawn.monster} "
            f"monsterLevel={maze_data.basis_level(run.dungeon)} "
            f"rank={maze_data.rank(spawn)} cleanup=0 hellGroup=0 hellOrder=0 "
            f"drops={drops.note(rows)} died; {branch.outcome}; "
            f"alive={alive}/{total} cell=({run.cell[0]},{run.cell[1]}) "
            f"boss=({boss_x},{boss_y}) -> {frames} frame(s){suffix}")
