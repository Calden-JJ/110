"""`(1,46)` DUNGEON-CLEAR-46 -- the five frames a clear is answered with --
and `(1,117)` BOSS-CHECK-117, the boss ack the client asks for by id.

184 sends across the four capture logs, and one shape every time::

    (0,34)  9B payload    00 + u32le(clear_ms) + four zeros
    (0,35)  257 + 29k B   the card the clear drops
    (0,37)  82B           `die.exp_body`, padded to its tile's 16
    (1,69)  1B            `01`
    (1,70)  17B           `01 01 00` + fourteen `ff`

The note counts the four fixed payloads `9B`, `82B`, `1B` and `17B` in all
184, and the card's own size takes six values -- 257, 286, 315, 344, 373,
402 -- which are 257 + 29k, so the card's body is a list of 29-byte records
(the `(1,71)` chain M3.6 covers is what reads them).  The card goes out
second and the note lists it last; the order below is the wire's.

**What is derived.**  `(0,37)` is the character's state *at the clear*: the
tutorial's 480 is exactly what its five kills left, and dungeon 3's 2296 is
the boss kill's own total, so the clear itself grants no experience.  The
level jumps a clear is followed by are a `(1,34)` quest finish's -- dungeon
3's clear leaves the level-3 row and the entry that follows reads 5 because
the finish between them granted +2770.  `free=`, `paid=` and `cost=` are read
off the card, at `[131]`, `[-90]` and `u16le[-118]`; the three 09-28 cards
and every note in the other logs agree.

**What is fed.**  `clear_ms` is the reference's own clock, and the card's
bytes are a table the capture does not spell out.  A replay is fed both from
the reference's own log (`diff_dungeon.clear_feed`); a run with nothing fed
rolls a live card from the dungeon's own pools instead (`cardpool`), so the
note's `(0,35)` size and its `free= paid= cost=` are the roll's own.

**`(1,117)`** is `03 00` + the id as `u16le`, answered with `(0,115)`
(`blocks.boss_ack_body`).  The client sends it right after a boss dies --
78ms after dungeon 3's clearing kill, 142ms after dungeon 5's -- and the two
notes read `valid=True clear=True`: the id names a record of a room this run
has drawn, and that room's `(0,31)` has gone out.  A second reading of
`valid` -- the id names a Boss-ranked record -- fits both sends too, and the
capture cannot separate the two.

**`source=C46/movie completion`** closes every one of the 184 lines.
"""
from __future__ import annotations

import sqlite3
import struct
from dataclasses import dataclass

from ...protocol import frame
from ...protocol.crypto import tiles
from ..town import queststate
from . import die
from .maze import room_records
from .run import DungeonRun

CLEAR_OPCODE = frame.Opcode(1, 46, frame.OpcodeEncoding.U8_U16LE, True)
CHECK_OPCODE = frame.Opcode(1, 117, frame.OpcodeEncoding.U8_U16LE, True)
ACK_OPCODE = frame.Opcode(0, 34, frame.OpcodeEncoding.U8_U16LE, True)
CARD_OPCODE = frame.Opcode(0, 35, frame.OpcodeEncoding.U8_U16LE, True)
STAGE_OPCODE = frame.Opcode(1, 69, frame.OpcodeEncoding.U8_U16LE, True)
STAGE_FLAGS_OPCODE = frame.Opcode(1, 70, frame.OpcodeEncoding.U8_U16LE, True)

#: `(1,46)`'s request is 128B; `(1,117)`'s is `03 00` + the id + 12 zeros.
CLEAR_BODY_SIZE = 128
CHECK_BODY_SIZE = 16
CHECK_AT = 2

#: The payload sizes the note spells out, verbatim, and the constant it ends
#: with.  `(0,35)`'s own size is the card's, so it is `len()` there.
ACK_CONTENT = "9B"
EXP_CONTENT = "82B"
STAGE_CONTENT = "1B"
STAGE_FLAGS_CONTENT = "17B"
SOURCE = "C46/movie completion"

#: Where the note's three purse numbers sit in the card.
FREE_AT = 131
PAID_FROM_END = 90
COST_FROM_END = 118

#: The `(0,34)` head byte and the `(1,70)` literal, before padding.
ACK_HEAD = b"\x00"
STAGE_BODY = b"\x01"
STAGE_FLAGS_BODY = b"\x01\x01\x00" + b"\xff" * 14


def padded(opcode: frame.Opcode, body: bytes) -> bytes:
    """A payload zero-padded to its tile's block, the way `entry.py` pads.

    The reference's own bodies are padded in place -- `(1,70)`'s 17 content
    bytes go out as 24 -- and `encrypt_body` leaves a partial tail in clear,
    so a handler has to do it itself.
    """
    return body + bytes(-len(body) % tiles.TILES[tiles.algo_id(opcode.sub)][2])


def clear_ms_body(clear_ms: int) -> bytes:
    """`(0,34)`: the clear's own clock, in milliseconds.

    The 09-28 sample alone reads as a `u16le` -- 64769, 36268, 32380 all fit
    -- but the 09-25/09-26 notes run past 2^16 (155813ms), so the field is the
    four bytes its nine-byte payload has room for.
    """
    return ACK_HEAD + struct.pack("<I", clear_ms) + bytes(4)


def card_purse(card: bytes) -> tuple[int, int, int]:
    """`free=`, `paid=`, `cost=` as the card itself spells them."""
    if len(card) <= FREE_AT:
        return (0, 0, 0)
    return (card[FREE_AT], card[-PAID_FROM_END],
            struct.unpack_from("<H", card, len(card) - COST_FROM_END)[0])


@dataclass(frozen=True, slots=True)
class Resolution:
    """One clear's five frames and its line."""

    frames: tuple[tuple[frame.Opcode, bytes], ...]
    note: str
    level: int
    experience: int


def resolution(run: DungeonRun, level: int, experience: int, clear_ms: int,
               card: bytes, *, spent: tuple[int, int] = (0, 0)) -> Resolution:
    """The five frames in the reference's wire order, and the line's prose.

    `run` is the run being cleared -- its dungeon, maze and cell are the
    line's first three fields -- and `level`/`experience` are the character
    row's, which is what `(0,37)` reports and what the clear leaves alone.
    `spent` is the skill-row netting `die.remaining` puts into the frame.
    """
    return Resolution(
        frames=((ACK_OPCODE, padded(ACK_OPCODE, clear_ms_body(clear_ms))),
                (CARD_OPCODE, padded(CARD_OPCODE, card)),
                (die.EXP_OPCODE, padded(die.EXP_OPCODE,
                                        die.exp_body(level, experience,
                                                     *die.remaining(level,
                                                                    spent)))),
                (STAGE_OPCODE, padded(STAGE_OPCODE, STAGE_BODY)),
                (STAGE_FLAGS_OPCODE,
                 padded(STAGE_FLAGS_OPCODE, STAGE_FLAGS_BODY))),
        note=note(run, level, experience, clear_ms, card),
        level=level, experience=experience)


def note(run: DungeonRun, level: int, experience: int, clear_ms: int,
         card: bytes) -> str:
    """The `DUNGEON-CLEAR-46` prose after the bare `conn=N `."""
    free, paid, cost = card_purse(card)
    return (f"dungeon={run.dungeon} maze={run.maze} "
            f"cell=({run.cell[0]},{run.cell[1]}) clear={clear_ms}ms "
            f"level={level} exp={experience} -> (0,34) {ACK_CONTENT} + "
            f"(0,37) {EXP_CONTENT} + (1,69) {STAGE_CONTENT} + "
            f"(1,70) {STAGE_FLAGS_CONTENT} + (0,35) {len(card)}B "
            f"free={free} paid={paid} cost={cost}; source={SOURCE}")


# ------------------------------------------------------------- boss check

def check_target(plain: bytes) -> int:
    """The id a `(1,117)` names, `target=` in the reference's line."""
    return struct.unpack_from("<H", plain, CHECK_AT)[0]


def check_flags(run: DungeonRun, target: int) -> tuple[bool, bool]:
    """`valid=` and `clear=` for one `(1,117)`.

    The capture's two targets are both records of the room the run is
    standing in -- 36, the flags-03 record killed at L1300 (but not by the
    kill that emptied the cell), and 68, the boss's own -- and both rooms had
    their `(0,31)` out by the time the check arrived.
    """
    valid = any(first <= target < first + len(room_records(map_id))
                for map_id, first in run.drawn.items())
    return valid, run.map_id in run.cleared


def check_note(target: int, valid: bool, clear: bool) -> str:
    """The `BOSS-CHECK-117` prose after the bare `conn=N `."""
    return f"target={target} valid={valid} clear={clear}"


# ------------------------------------------------------------- boss burst

def quest_frames(conn: sqlite3.Connection, character_id: int,
                 seeker: queststate.Seeker) \
        -> tuple[tuple[frame.Opcode, bytes], ...]:
    """`(0,342)`/`(0,291)`/`(0,21)` rebuilt from the save, in that order.

    Two chains send the triple: the boss-cell kill that meets a `clear map`
    quest's condition, and `(1,72)`'s retry line.  Both read the same three
    lists (`queststate`), so both send the same frames -- dungeon 5's
    settlement bursts exactly what the next entry's own state would.
    """
    finished = queststate.finished_ids(conn, character_id)
    entries = queststate.in_progress(conn, character_id)
    available = queststate.available_ids(seeker, finished,
                                         [q for q, _ in entries])
    return ((queststate.FINISHED_OPCODE,
             padded(queststate.FINISHED_OPCODE,
                    queststate.finished_body(finished))),
            (queststate.IN_PROGRESS_OPCODE,
             padded(queststate.IN_PROGRESS_OPCODE,
                    queststate.in_progress_body(entries))),
            (queststate.AVAILABLE_OPCODE,
             padded(queststate.AVAILABLE_OPCODE,
                    queststate.available_body(seeker.level, available))))


def boss_burst(conn: sqlite3.Connection, character_id: int, map_id: int,
               seeker: queststate.Seeker, *, key: int,
               difficulty: int) -> die.Boss | None:
    """The quest frames a boss-cell-clearing kill carries, or None.

    The kill that empties a room a `clear map` quest names is the one that
    meets the quest's condition, and the state frames report the write it
    makes: the trigger goes to 0 (`trigger=1->0`), `(0,291)` re-reads the
    in-progress list with it, and `(0,342)`/`(0,21)` the finished and
    available ones.  `seeker` carries the level the kill landed on, which is
    what `(0,21)` lists.

    The lines the frames come from -- dungeon 3's `quest=3145 dungeon=3
    difficulty=0 trigger=1->0` and dungeon 5's 3146 -- read `key=` off the
    session and `difficulty=` off the `(1,16)` entry request's own field.
    """
    quest = queststate.clear_map_quest(map_id)
    if quest is None:
        return None
    quest_id, dungeon = quest
    before = queststate.cleared_trigger(conn, character_id, quest_id)
    return die.Boss(
        frames=quest_frames(conn, character_id, seeker),
        note=(f"key={key} quest={quest_id} dungeon={dungeon} "
              f"difficulty={difficulty} trigger={before}->0"))


@dataclass(frozen=True, slots=True)
class Card:
    """A fed clear: the reference's own clock and the card it dropped."""

    clear_ms: int
    payload: bytes


__all__ = ["CLEAR_OPCODE", "CHECK_OPCODE", "CARD_OPCODE", "Card", "Resolution",
           "boss_burst", "card_purse", "check_flags", "check_note",
           "check_target", "clear_ms_body", "note", "padded", "quest_frames",
           "resolution"]
