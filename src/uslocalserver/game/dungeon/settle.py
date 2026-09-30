"""`(1,42)` SETTLEMENT-42 -- leaving the dungeon, and `(1,46)`'s flag.

The request is the 13B game header and nothing else -- a `(1,42)` has no body
at all.  The answer is the town pair again, built from the character row the
same way the town entry builds it:

    (1,42)  8B   `01` + 7 zeros.
    (0,3)   16B  the constant `01 03 00 01` + 12 zeros.
    (0,23)  16B  `movement.area_pair`'s first frame, from the *row*: the
                 capture's three leaves print `back to town=(38,1) pos=
                 (561,234)` and send exactly those five fields.
    (0,24)  20B  the pair's second frame.

So the row is where the character settles, which is why a dungeon run cannot
move it: a `(1,45)` only writes the run, and the position the client gets
back is the last town move it persisted.  The INFO line prints the dungeon
being left and `settled=`, the flag `(1,46)` set.

`(1,46)` DUNGEON-CLEAR-46 is the clear itself, and this module keeps only its
flag: `(1,42)`'s `settled=` reads True after a clear and False after a run
that was abandoned instead, and `DungeonSession.begin` resets it, which is
what the capture's three leaves show (True, then False for both dungeon 6
runs -- the second entered fresh after the first was abandoned).  The five
frames the `(1,46)` is answered with are `clear.py`'s subject.

`(1,72)` SETTLEMENT-72 -- the card screen's own close, sent right after the
flips.  The request is 16B::

    [0]    state   1 in every send that touches the run
    [1]    option  0/1/2/3
    [2]    context 1 in every send
    [3:16] thirteen zero bytes

and the answer is one of four shapes, fitted to the 09-28 capture's four
sends and the 187 lines the three other logs hold:

*   `state != 1` -- the ack alone, the run left where it stands.  The
    corpus' five `state=2` sends are all DCOD sessions, where the `state=1`
    settle that follows still reads the same run.
*   `state=1` with no run and no story behind the last clear -- the ack
    alone, `replay=True`, `dungeon=` empty.  This is the request the client
    sends 45ms after an option-2 settle, in both the 09-28 and the 09-25
    session; the post-settle `(1,35)` then moves the client at the very
    position the pair it just got named.
*   `state=1` with no run and a story behind the last clear -- the ack
    alone and **no line at all**: the capture's one silent send, the option-3
    request that follows the story settle (`run#525`, 21:13:22.101).
*   `state=1` with a run -- the ack, then the story burst if `option=1`
    finds a retry, then the town triple `(0,3)`+`(0,23)`+`(0,24)` built from
    the character row exactly as `(1,42)` builds it, and the run is left.
    4 frames, or 7 with the burst.

The ack is `01`, the attempt, the option and a zero, then twelve zeros.  The
attempt is the last clear's own -- 1 on every send but one, and 2 on the
send that follows a story (21:13:22.101); it is the story's to advance, and
whether it counts on the result or on the session is not separable from the
capture (see `card.Result.attempt`).  The option byte reads 2->2 and 3->3 on
the two flips' own commit, and 1->0 on the story; an option-0 ack is not
measured.

**The story.**  `option=1` asks the reference for a retry, and it scans the
gate's worldmap for a maze whose `questConnection` names an in-progress
quest -- `entry.retry_quest`, the same scan `(1,16)` runs.  A hit prints a
line of its own before the note::

    SETTLEMENT-72 conn=4 story quest=3146 -> quest=3147 dungeon=6; native retry pending

The first id is the target quest's `preRequiredQuests[0]`
(`queststate.prerequisite`), the second the target, the dungeon the one its
own `dungeonInfo` names -- all five of the corpus' story lines fit.  The
`native retry pending` is what the next `(1,16)` at that gate acts on, and
the burst is exactly `clear.quest_frames`' triple: the story settle's own
state frames are what the retry will need to have sent.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ...persistence.characters import CharacterSummary
from ...protocol import frame
from ..town import movement, queststate
from . import blocks, clear, entry
from .run import DungeonRun, DungeonSession

LEAVE_OPCODE = frame.Opcode(1, 42, frame.OpcodeEncoding.U8_U16LE, True)
SETTLE_OPCODE = frame.Opcode(1, 72, frame.OpcodeEncoding.U8_U16LE, True)

#: `(1,42)`'s request is the bare header; `(1,72)`'s is sixteen bytes.
LEAVE_BODY_SIZE = 0
SETTLE_BODY_SIZE = 16
STATE_AT, OPTION_AT, CONTEXT_AT = 0, 1, 2

#: The state the one settle that touches the run carries.  The corpus' five
#: `state=2` sends are DCOD sessions; what the reference does with one beyond
#: the ack is not measurable from them.
SETTLE_STATE = 1

#: The option that may carry the story burst.
RETRY_OPTION = 1

#: The ack's option byte where it is not the request's own: option 1 reads 0.
ACK_OPTIONS = {1: 0}

ACK_BODY = b"\x01" + bytes(7)


def replies(key: int, location: movement.Location) -> list[tuple[frame.Opcode, bytes]]:
    """The four frames, in the reference's order."""
    return [(LEAVE_OPCODE, ACK_BODY),
            (blocks.ACK_OPCODE, blocks.ack_body(key)),
            *movement.area_pair(key, location.town, location.area, location.x,
                                location.y, location.direction)]


def note(run: DungeonRun, settled: bool, key: int,
         location: movement.Location) -> str:
    """The `SETTLEMENT-42` prose after the bare `conn=N `."""
    return (f"leaving dungeon={run.dungeon} settled={settled}; key={key} back "
            f"to town=({location.town},{location.area}) "
            f"pos=({location.x},{location.y}); answered with (1,42) ack + "
            f"(0,3) + (0,23) + (0,24)")


# ---------------------------------------------------------- (1,72) settle

def request_fields(plain: bytes) -> tuple[int, int, int]:
    """`state=`, `option=` and `context=` -- the request's first three bytes."""
    return plain[STATE_AT], plain[OPTION_AT], plain[CONTEXT_AT]


def ack_body(attempt: int, option: int) -> bytes:
    """`(1,72)`: `01`, the attempt, the option, a zero, then twelve zeros."""
    return (bytes([0x01, attempt + 1, ACK_OPTIONS.get(option, option), 0x00])
            + bytes(12))


def settle_note(key: int, run: DungeonRun | None, state: int, option: int,
                context: int, replay: bool, frames: int) -> str:
    """The `SETTLEMENT-72` prose after the bare `conn=N `.

    `dungeon=` is the run's, and empty when there is no run to read -- both
    readings are the capture's own (`dungeon=5 ... replay=False` against
    `dungeon= state=1 option=3 ... replay=True`).
    """
    return (f"key={key} dungeon={run.dungeon if run is not None else ''} "
            f"state={state} option={option} context={context} "
            f"replay={replay} -> {frames} frame(s)")


def story_line(previous: int, quest: int, dungeon: int) -> str:
    """The extra `SETTLEMENT-72` line a retry prints, before the note."""
    return (f"story quest={previous} -> quest={quest} dungeon={dungeon}; "
            f"native retry pending")


@dataclass(frozen=True, slots=True)
class Resolution:
    """One `(1,72)`'s frames and its lines.

    `note` is None for the answer that prints nothing at all -- the story
    settle's follow-up, the capture's one silent send.  `story` is the retry
    line, which the reference logs before the note.
    """

    frames: tuple[tuple[frame.Opcode, bytes], ...]
    note: str | None
    story: str | None = None


def resolution(conn: sqlite3.Connection, session: DungeonSession,
               summary: CharacterSummary, plain: bytes) -> Resolution:
    """Everything a `(1,72)` draws, and the run it leaves.

    The ack is built before anything moves, so a story's own send still
    counts the attempt it lands on rather than the one it advances to.
    """
    state, option, context = request_fields(plain)
    run, result = session.run, session.result
    attempt = result.attempt if result is not None else 0
    ack = (SETTLE_OPCODE, ack_body(attempt, option))
    if state != SETTLE_STATE:
        return Resolution(frames=(ack,), note=settle_note(
            session.key, run, state, option, context, False, 1))
    if run is None:
        if result is not None and result.retried:
            return Resolution(frames=(ack,), note=None)
        return Resolution(frames=(ack,), note=settle_note(
            session.key, None, state, option, context, True, 1))
    frames = [ack]
    story = None
    if option == RETRY_OPTION:
        retry = entry.retry_quest(session, {q for q, _ in
                                            queststate.in_progress(
                                                conn, session.character_id)})
        if retry is not None:
            dungeon, _, quest = retry
            story = story_line(queststate.prerequisite(quest), quest, dungeon)
            frames += list(clear.quest_frames(conn, session.character_id,
                                              queststate.Seeker.of(summary)))
            if result is not None:
                result.attempt += 1
                result.retried = True
    location = movement.Location.of(summary)
    frames += [(blocks.ACK_OPCODE, blocks.ack_body(session.key)),
               *movement.area_pair(session.key, location.town, location.area,
                                   location.x, location.y, location.direction)]
    session.leave()
    return Resolution(frames=tuple(frames), story=story,
                      note=settle_note(session.key, run, state, option,
                                       context, False, len(frames)))
