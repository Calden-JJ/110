"""`(0,342)` / `(0,291)` / `(0,21)` TOWN-QUEST-STATE -- the entry burst's three
quest frames.

They sit at indices 17/18/19 of the 33-frame `(1,143)` burst, between
`(0,440)` hotkeys and the `(0,23)`/`(0,24)` area pair, and are pure functions
of the save when the save is read the way the reference reads it:

    (0,342)  u32le(count) + count x u32le(quest id, ascending) + u32le(0)
    (0,291)  u16le(count) + count x [u16le(id) u16le(trigger) 10 zero bytes]
    (0,21)   u32le(len - 4) + protobuf-ish payload:
             0x10 varint(level) 0x18 varint(count) (0x20 varint(id)) x count

**The lists.**  All three were fitted against every paired
`TOWN-QUEST-STATE`/`TOWN-QUESTS` line in the three corpus logs -- 37 states
from 09-25 08:57 to 09-27 13:23, levels 1/29/30/50/110 -- and against the
captured `(0,21)` frame itself, which reproduces id for id (137 of them) in
all 17 of the `finished=814` states:

*   **finished** = `character_finished_quests`, ascending.  814 rows for
    XRenYing equals the captured `finished=814` and the frame's own count.
*   **in-progress** = `character_quests` minus `character_finished_quests`;
    the wire's `trigger` is `character_quest_progress.trigger_value` (XRenYing's
    only row, quest 13615, carries 1 -- the frame's `01 00`).  The line's
    "(of N ever accepted)" is the `character_quests` row count (XRenYing 11,
    matching the capture).  The 10 trailing bytes are zero in the only sample
    that exists; whether they are per-entry or a frame trailer is not
    measured, and a second in-progress row would settle it.
*   **available** is the rule in `available_ids` -- see it for the evidence.

**Names.**  `class_id` is the key order of the `jobs` table (table 014,
`gm_advancements`'s 17 entries: 0 Slayer, 1 Fighter, 2 Gunner, 3 Mage,
4 Priest, then the female trees, Dark Knight, Creator, ...); the quest
vocabulary's own spellings (`swordman`, `fighter`, `at swordman`, ...) are
what `targetCharacters[].job` and `jobs` use.  Two entries are measured --
class 11 is `at swordman` (XRenYing, whose eight `(at swordman, 5, 1..3)`
epics are accept-able) and class 1 is `fighter` (LRouDao, whose Lv50 fit of 27
needs exactly the `(fighter, 4, 1)` hit on quest 3362) -- and the rest follow
the table's order.

**`worldmap nodes`** in the TOWN-QUESTS line is the sum of `dungeonIds` over
the town's gates in `dungeon_worldmap`: town 39 -> gates to worldmaps 102/7 ->
1 + 8 = 9, and the same formula reproduces all six observed towns (38->29,
146->2, 22->77, 76->0, 40->44).
"""
from __future__ import annotations

import sqlite3
import struct
from dataclasses import dataclass
from functools import lru_cache
from typing import Sequence

from ...game import data
from ...protocol import frame
from ...persistence.characters import CharacterSummary

FINISHED_OPCODE = frame.Opcode(0, 342, frame.OpcodeEncoding.U8_U16LE, True)
IN_PROGRESS_OPCODE = frame.Opcode(0, 291, frame.OpcodeEncoding.U8_U16LE, True)
AVAILABLE_OPCODE = frame.Opcode(0, 21, frame.OpcodeEncoding.U8_U16LE, True)

ACCEPT_OPCODE = frame.Opcode(1, 31, frame.OpcodeEncoding.U8_U16LE, True)
FINISH_OPCODE = frame.Opcode(1, 34, frame.OpcodeEncoding.U8_U16LE, True)

#: Both requests carry the quest id at offset 2, behind a two-byte constant
#: (`1f 00` for the accept, `22 00` for the finish) and its flags.
QUEST_AT = 2

#: Where the three sit in the `(1,143)` burst, 0-based.
FINISHED_AT = 17
IN_PROGRESS_AT = 18
AVAILABLE_AT = 19

#: The class_id -> quest-vocabulary job name, in `gm_advancements.jobs` key
#: order.  See the module docstring for which two of the seventeen are
#: measured and which are order-derived.
CLASS_NAMES = (
    "swordman",           # 0
    "fighter",            # 1  measured (LRouDao)
    "gunner",             # 2
    "mage",               # 3
    "priest",             # 4
    "at gunner",          # 5
    "thief",              # 6
    "at fighter",         # 7
    "at mage",            # 8
    "demonic swordman",   # 9
    "creator mage",       # 10
    "at swordman",        # 11 measured (XRenYing)
    "knight",             # 12
    "demonic lancer",     # 13
    "at priest",          # 14
    "gun blader",         # 15
    "archer",             # 16
)

#: The grades whose `jobs=['all']` half of the rule is open to every
#: character.  Every other grade needs a job/tchar hit; see `available_ids`.
ALLOWED_GRADES = frozenset({"side", "episode", "daily mission", "common unique"})

#: The ten zero bytes each `(0,291)` entry carries past its trigger.
IN_PROGRESS_TAIL = bytes(10)


def request_quest(plain: bytes) -> int:
    """The quest a `(1,31)`/`(1,34)` names: the `u16le` behind the constant."""
    return struct.unpack_from("<H", plain, QUEST_AT)[0]


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def finished_ids(conn: sqlite3.Connection, character_id: int) -> list[int]:
    return [r[0] for r in conn.execute(
        "select quest_id from character_finished_quests where character_id = ? "
        "order by quest_id", (character_id,))]


def in_progress(conn: sqlite3.Connection,
                character_id: int) -> list[tuple[int, int]]:
    """`(quest_id, trigger_value)` of every started-but-unfinished quest.

    Read from `character_quest_progress`, not `character_quests`: the two
    agree for every quest the client accepted -- the accept writes both rows
    -- but only the progress table carries the starter quest a character is
    born on.  A fresh character's first state line reads `in-progress=1 (of 0
    ever accepted); in-progress=3145` (2026-09-28 21:09:42, and the same
    shape on 09-19 and 09-25): one progress row, no accept behind it.  A
    Lv110 character pins the same split from the other side -- 814 finished,
    11 ever accepted, 13615 the one progress row without a finish.
    """
    return [(r[0], r[1]) for r in conn.execute(
        "select p.quest_id, p.trigger_value from character_quest_progress p "
        "where p.character_id = ? and p.quest_id not in "
        "  (select quest_id from character_finished_quests where character_id = ?) "
        "order by p.quest_id", (character_id, character_id))]


def accepted_count(conn: sqlite3.Connection, character_id: int) -> int:
    return conn.execute("select count(*) from character_quests where character_id = ?",
                        (character_id,)).fetchone()[0]


def accept(conn: sqlite3.Connection, character_id: int, quest_id: int, *,
           now: int) -> None:
    """`(1,31)`: the two rows an accept writes.

    The progress row starts at trigger 1, which is what "not yet triggered"
    reads as: every unfinished row in the save carries 1 -- exactly one per
    character, 13615/13780/3147 -- and every finished one 0, so `LRouDao`'s
    117 finished rows are the 117 the boss-cell kill zeroed.  The
    `QUEST-STARTER` line's `trigger=1` is the same value, and `cleared_trigger`
    is the write that takes it to 0.  The or-replace is for a re-sent accept:
    the reference's rows cannot say what it does with one, and dying on the
    primary key would take the connection down.
    """
    with conn:
        conn.execute("insert or replace into character_quests "
                     "(character_id, quest_id, accepted_at) values (?, ?, ?)",
                     (character_id, quest_id, now))
        conn.execute("insert or replace into character_quest_progress "
                     "(character_id, quest_id, trigger_value, answer_index, "
                     "counter_initialized) values (?, ?, 1, -1, 1)",
                     (character_id, quest_id))


@lru_cache(maxsize=1)
def _clear_map_quests() -> dict[int, tuple[int, int]]:
    """Room -> (quest id, `dungeonInfo[0]`) for every `clear map` quest."""
    out: dict[int, tuple[int, int]] = {}
    for key, quest in data.load("quest_content")["quests"].items():
        if quest.get("questType") != "clear map":
            continue
        dungeon = (quest.get("dungeonInfo") or (0,))[0]
        for target in quest.get("targets") or ():
            out.setdefault(target, (int(key), dungeon))
    return out


def clear_map_quest(map_id: int) -> tuple[int, int] | None:
    """The `clear map` quest naming this room, and the dungeon it belongs to.

    The capture's two `QUEST-COMBAT` lines: 76126 -> 3145 (dungeon 3) and
    76136 -> 3146 (dungeon 5).  The tutorial's own boss room, 53130, is in no
    such quest's targets, which is why the tutorial's clear sends no burst --
    its kill still appends `(0,31)`, one frame and no quest state.
    """
    return _clear_map_quests().get(map_id)


def prerequisite(quest_id: int) -> int:
    """The quest a story retry line prints before the arrow.

    All five story lines the corpus holds -- `quest=3146 -> quest=3147
    dungeon=6` and its four 09-26 siblings -- name the target quest's own
    `preRequiredQuests[0]`.  The other reading that fits all five is the
    cleared run's `clear map` quest, which is the same id wherever both
    exist; the table says 0 when a target has no prerequisite at all.
    """
    quest = data.load("quest_content")["quests"].get(str(quest_id)) or {}
    prereqs = tuple(quest.get("preRequiredQuests") or ())
    return prereqs[0] if prereqs else 0


def cleared_trigger(conn: sqlite3.Connection, character_id: int,
                    quest_id: int) -> int:
    """The write a boss-cell-clearing kill makes: the trigger back to 0.

    Returns the value the row carried -- `trigger=1->0` in the reference's
    line.  A quest with no progress row updates nothing, and the 0 it reads
    as is the caller's to print.
    """
    row = conn.execute("select trigger_value from character_quest_progress "
                       "where character_id = ? and quest_id = ?",
                       (character_id, quest_id)).fetchone()
    before = 0 if row is None else row[0]
    with conn:
        conn.execute("update character_quest_progress set trigger_value = 0 "
                     "where character_id = ? and quest_id = ?",
                     (character_id, quest_id))
    return before


def finish(conn: sqlite3.Connection, character_id: int, quest_id: int, *,
           now: int) -> None:
    """`(1,34)`: the finished row, and nothing else.

    Finishing does not require -- or record -- an accept: 804 of `XRenYing`'s
    814 finished quests have no `character_quests` row, and the progress row
    (if any) stays where it is; `in_progress` is what subtracts the finish.
    """
    with conn:
        conn.execute("insert or replace into character_finished_quests "
                     "(character_id, quest_id, finished_at) values (?, ?, ?)",
                     (character_id, quest_id, now))


def finished_body(ids: Sequence[int]) -> bytes:
    """`(0,342)`: the count, then the ids.

    Four bytes of the entry burst's frame are not content: `4 + 4 x 814` is
    3260 and the captured body 3264, and the four zeros the test used to read
    as a terminator are the tile padding every frame of the kind gets.  The
    story burst settles it -- `4 + 4 x 3` is 16, already a multiple of 8, and
    the reference's own frame there is those sixteen bytes with no trailer at
    all (2026-09-28 21:13:22.026, one `03` and three ids).
    """
    return (struct.pack("<I", len(ids))
            + b"".join(struct.pack("<I", i) for i in ids))


def in_progress_body(entries: Sequence[tuple[int, int]]) -> bytes:
    """`(0,291)`: count, then id/trigger pairs each followed by 10 zero bytes."""
    return (struct.pack("<H", len(entries))
            + b"".join(struct.pack("<HH", q, trigger) + IN_PROGRESS_TAIL
                       for q, trigger in entries))


def available_body(level: int, ids: Sequence[int]) -> bytes:
    """`(0,21)`: a `len - 4` prefix, then 0x10 level / 0x18 count / 0x20 ids."""
    payload = (varint(0x10) + varint(level) + varint(0x18) + varint(len(ids))
               + b"".join(varint(0x20) + varint(i) for i in ids))
    return struct.pack("<I", len(payload)) + payload


@dataclass(frozen=True, slots=True)
class Seeker:
    """The character facts the availability rule reads."""
    level: int
    class_id: int
    grow_type: int
    sub_grow_type: int

    @classmethod
    def of(cls, summary: CharacterSummary) -> "Seeker":
        return cls(summary.level, summary.class_id, summary.grow_type,
                   summary.sub_grow_type)


def _opens(quest: dict, seeker: Seeker, finished: set[int]) -> bool:
    """The structural half: unlocked, not done, not being done, not a requirement-gated
    creature/expert/event quest."""
    if quest["level"] > seeker.level:
        return False
    level_max = quest.get("levelMax", -1)
    if level_max >= 0 and seeker.level > level_max:
        return False
    if (quest.get("hasCreatureRequirement") or quest.get("hasExpertRequirement")
            or quest.get("isEvent")):
        return False
    groups = [tuple(g) for g in (quest.get("preRequiredQuestGroups") or ())]
    prereqs = tuple(quest.get("preRequiredQuests") or ())
    if groups:
        return any(set(g) <= finished for g in groups)
    return not prereqs or set(prereqs) <= finished


def _exposed(quest: dict, seeker: Seeker) -> bool:
    """The three ways a quest is shown to *this* character.

    The first clause is the captured `(0,21)` frame's own shape: at
    `finished=814` the frame holds exactly the `side`/`episode`/`daily
    mission`/`common unique` quests with `jobs=['all']`, plus two epics --
    22136 and 22397, whose `targetCharacters` name XRenYing's exact
    `(at swordman, 5, 3)`.  The second clause is what makes the reference's
    Lv50 count 27 instead of 26: quest 3362 is `jobs=[]` but its
    `targetCharacters` also carry `(fighter, 4, 1)`, LRouDao's exact triple.
    The middle clause (job name in `jobs` and grow type in `growTypes`, no
    target name) is the shape the 3357+ family's non-tchar members take --
    3363-3366 say `jobs=['fighter'], growTypes=[4]` for exactly one of the
    four -- but no observed state needs it beyond what the first two cover.
    """
    if quest["grade"] in ALLOWED_GRADES and "all" in (quest.get("jobs") or ()):
        return True
    name = CLASS_NAMES[seeker.class_id]
    if name in (quest.get("jobs") or ()) and seeker.grow_type in (quest.get("growTypes") or ()):
        return True
    return any(t.get("job") == name and t.get("growType") == seeker.grow_type
               and t.get("subGrowType") == seeker.sub_grow_type
               for t in (quest.get("targetCharacters") or ()))


def available_ids(seeker: Seeker, finished: Sequence[int],
                  in_progress_ids: Sequence[int]) -> list[int]:
    """The `(0,21)` list: what this character can take on right now, ascending.

    Reproduces all five captured `available=` counts at Lv110 (144/142/140/
    139/137 as the epic chains finish) and, at `finished=814`, the captured
    frame's full 137-id set -- not just its size -- plus the Lv50 state's 27
    and the Lv1/Lv29/Lv30 states' 8/18/23.
    """
    done = set(finished)
    busy = set(in_progress_ids)
    quests = data.load("quest_content")["quests"]
    out = []
    for key, quest in quests.items():
        i = int(key)
        if i in done or i in busy or not _opens(quest, seeker, done):
            continue
        if _exposed(quest, seeker):
            out.append(i)
    return sorted(out)


def worldmap_nodes(town: int) -> int:
    """The TOWN-QUESTS line's `worldmap nodes=N` for a town."""
    gates = data.rows("dungeon_worldmap", "gates")
    dungeons = {w.id: w.dungeonIds for w in data.rows("dungeon_worldmap", "worldmaps")}
    return sum(len(dungeons.get(g.worldmapId, ())) for g in gates if g.townId == town)


def state_line(finished: Sequence[int],
               in_progress_entries: Sequence[tuple[int, int]],
               accepted: int) -> str:
    """The `TOWN-QUEST-STATE` prose after the bare `conn=N `.

    Empty lists drop their clause entirely (the 08:57 lv1 line reads
    `... (of 0 ever accepted); in-progress=3145` with no `finished=`).
    """
    parts = []
    if finished:
        parts.append("finished=" + ",".join(map(str, finished)))
    if in_progress_entries:
        parts.append("in-progress=" + ",".join(str(q) for q, _ in in_progress_entries))
    tail = "; " + "; ".join(parts) if parts else ""
    return (f"(0,342) finished={len(finished)} (0,291) "
            f"in-progress={len(in_progress_entries)} (of {accepted} ever "
            f"accepted){tail}")


def quests_line(town: int, nodes: int, available: int, active: Sequence[int],
                finished: int, level: int) -> str:
    """The `TOWN-QUESTS` prose after the bare `conn=N `.

    `active=[...]` stays even when empty; the Lv50 line reads `active=[]`.
    """
    return (f"town={town} worldmap nodes={nodes} (0,21) available={available} "
            f"active=[{','.join(map(str, active))}] finished={finished} "
            f"level={level}")
