#!/usr/bin/env python3
"""Diff the rewrite against the reference's dungeon session -- M3.0.

The oracle is the 2026-09-28 play session the user recorded for M3.0
(`Logs-dungeon/server-20260928.log`, conn=4 on game port 10013, 21:09:40 to
21:15:03, 612 C->S frames, zero truncated dumps).  Unlike the M2 oracles this
one is *played*, not driven: the client's own frames, in the client's own
order, at the client's own pace.

Both logs are the same shape -- `ts LEVEL TAG msg` with `PACKET` lines
carrying the frames -- so one attribution function reads both.  Walking the
lines in order, each C->S `PACKET` opens a run; the S->C frames, the
`DISPATCH` line and every prose note that follow attach to it until the next
C->S.  Frames before the first C->S are the connect group.

The replay feeds conn=4's bytes back at the offsets its log recorded, on a
copy of the baseline save.  `--scale` compresses those offsets (the session
is 5.4 minutes of mostly idle walking); the throttle-sensitive `(1,35)`
writes are the only thing that can notice, so they are counted separately.

**The baseline is not the pre-session backup.**  conn=4 plays XJianHun
(character 3), created 24 seconds into the same log on conn=2 -- character
creation is not implemented, so the row and the items it started with are
seeded by hand from the reference's own entry note::

    TOWN-ITEMS conn=4 main inventory 15 row(s) ... slot=0 id=0 count=5000,
    slot=9 id=27118 seed=872944189 dur=45, slot=65 id=1001 count=5,
    slot=363..374 (twelve stackable starter rows)
    TOWN-SPAWN conn=4 town=38 area=1 pos=(561,234) key=3
    TOWN-SELF-DATA conn=4 job=0 level=1 exp=0 ...

`--rebuild-baseline` rewrites it; `--list-only` prints the reference's run map
without replaying anything.

    python tools/diff_dungeon.py --list-only        # the map, no replay
    python tools/diff_dungeon.py                   # replay and diff everything
    python tools/diff_dungeon.py --until 40 --verbose
    python tools/diff_dungeon.py --op 1,15 --op 1,16 --verbose
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import io
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.game.dungeon import (card, clear, die, drops,  # noqa: E402
                                        reward)
from uslocalserver.game.town import charsettings  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402
from uslocalserver.server import game  # noqa: E402
from uslocalserver.server.logfile import Log  # noqa: E402

DEFAULT_ORACLE = paths.REPO_ROOT / "Logs-dungeon" / "server-20260928.log"
PRE_SESSION = (paths.REPO_ROOT / "_backups"
               / "uslocalserver-m3presession-20260928-210824.db")
BASELINE = paths.REPO_ROOT / "_backups" / "uslocalserver-m3baseline-20260928.db"
PORT = 10013
CONN = 4
CHANNELINFO = (0, 1)

_DISPATCH = re.compile(r"conn=(\d+) \((\d+),(\d+)\) -> (\d+) frame\(s\) (\d+)B "
                       r"state=(\w+)->(\w+)")
_CONN = re.compile(r"conn=\d+")

#: The character conn=4 plays, as the reference's own entry note describes it
#: at 21:09:42.337.  Level 1, exp 0, nothing equipped, gold 5000.
CHARACTER = 3

#: The two things character creation left in the row that the entry burst
#: cannot see: the tutorial dungeon `(1,16)` auto-enters, and the quest the
#: `QUEST-STARTER` line activated at 21:09:42.320.
TUTORIAL_DUNGEON = 7115
STARTER_QUEST = 3145
CHARACTER_ROW = {
    "character_id": 3, "account_id": 0, "slot_index": 2, "name": "XJianHun",
    "class_id": 0, "level": 1, "town_id": 38, "area_id": 1,
    # The character had never moved when it entered, and the entry's `(0,22)`
    # carries the row's `town_state` as its direction byte: 0.
    "position_x": 561, "position_y": 234, "town_state": 0,
    "experience": 0, "grow_type": 1, "sub_grow_type": 0,
    "ex_equip_slot_flags": 0, "bonus_sp": 0, "bonus_tp": 0,
    "favorite_position": 3, "pending_tutorial_dungeon_id": TUTORIAL_DUNGEON,
    "created_at": 1_790_600_976, "updated_at": 1_790_600_976,
}
#: (list, slot, item, count, durability, instance_value) -- the character's
#: own rows of the `TOWN-ITEMS` note, and only those: the note's twelve
#: trailing cells (363..374) are the account-material band, which the entry
#: burst appends from `account_materials` (`burst.Inventory.of`), and the
#: backup's account 0 already carries -- seeded here too they would render
#: twice (27 rows against the reference's 15).
CHARACTER_ITEMS = [
    (0, 0, 0, 5000, 0, 0),
    (0, 9, 27118, 1, 45, 872_944_189),
    (0, 65, 1001, 5, 0, 0),
]


@dataclass(slots=True)
class Frame:
    """One S->C frame: its opcode, its decrypted body and its wire size.

    `header` and `nonce` are kept for `extract_dungeon_replies.py`, which
    proves the whole frame rebuilds from the plaintext.
    """

    opcode: tuple[int, int]
    plain: bytes
    wire: int
    header: bytes = b""
    nonce: bytes = b""

    def show(self) -> str:
        return f"({self.opcode[0]},{self.opcode[1]}) body={len(self.plain)}"


@dataclass(slots=True)
class Run:
    """One C->S frame and everything the reference answered it with."""

    line: int
    ts: str
    offset: float
    opcode: tuple[int, int]
    wire: int
    body: bytes
    replies: list[Frame] = field(default_factory=list)
    notes: list[tuple[str, str, str]] = field(default_factory=list)
    dispatch: tuple[int, int, str, str] | None = None

    @property
    def key(self) -> str:
        return f"({self.opcode[0]},{self.opcode[1]})"

    @property
    def note_tags(self) -> list[str]:
        return [tag for _, tag, _ in self.notes]


def _seconds(ts: str) -> float:
    """`2026-09-28 21:09:40.406` -> seconds since 20:00:00 (offsets only)."""
    return (int(ts[11:13]) * 3600 + int(ts[14:16]) * 60 + float(ts[17:23]))


def _local_epoch(ts: str, tz: str) -> int:
    """The log's first timestamp as an epoch second, in the log's own zone."""
    return int(datetime.datetime.fromisoformat(f"{ts}{tz}").timestamp())


def plain_of(f: frame.Frame) -> bytes:
    if (f.opcode.main, f.opcode.sub) == CHANNELINFO:
        return f.body
    return tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)


def read_log(path: Path, conn: int | None) -> tuple[int, list[Frame], list[Run]]:
    """The log as (epoch, connect group, runs), in line order.

    `conn=None` reads every game connection in the file -- our own replay logs
    hold exactly one, and its number is the rewrite's to choose.
    """
    packets = {p.line_no: p for p in logs.iter_packets(path)}
    connect: list[Frame] = []
    runs: list[Run] = []
    cur: Run | None = None
    epoch = 0
    first = 0.0
    started = False
    for ln in logs.stream(path):
        if ln.tag == "PACKET":
            p = packets.get(ln.line_no)
            if p is None or p.link != "game" or p.hex is None:
                continue
            if conn is not None and p.conn != conn:
                continue
            if not started:
                epoch = _local_epoch(ln.ts, ln.tz)
                first, started = _seconds(ln.ts), True
            if p.direction == "C->S":
                if p.truncated:
                    raise SystemExit(f"{path}:{ln.line_no}: truncated C->S dump")
                cur = Run(line=ln.line_no, ts=ln.ts,
                          offset=_seconds(ln.ts) - first, opcode=p.opcode,
                          wire=p.hex.full_size, body=p.frame_bytes)
                runs.append(cur)
            else:
                f = frame.parse(frame.Link.GAME_S2C, p.frame_bytes, strict=False,
                                expect_size=p.hex.full_size)
                entry = Frame(opcode=(f.opcode.main, f.opcode.sub), plain=plain_of(f),
                              wire=p.hex.full_size,
                              header=p.frame_bytes[:frame.header_len(frame.Link.GAME_S2C)],
                              nonce=p.frame_bytes[12:15])
                (connect if cur is None else cur.replies).append(entry)
        elif ln.tag == "DISPATCH":
            m = _DISPATCH.match(ln.msg)
            if m and cur is not None and (conn is None or int(m.group(1)) == conn):
                cur.dispatch = (int(m.group(4)), int(m.group(5)),
                                m.group(6), m.group(7))
        elif not re.match(r"^\s*$", ln.msg):
            if cur is None:
                continue
            if conn is not None and not _CONN.search(ln.msg):
                continue
            if conn is not None and not ln.msg.startswith(f"conn={conn}"):
                continue
            cur.notes.append((ln.level, ln.tag, ln.msg))
    return epoch, connect, runs


# -------------------------------------------------------------------- feed

#: The `(1,39)` note's exp line: the gain and the total it lands on.
_DIE_EXP = re.compile(r"\+(\d+) exp \(base=\d+, contractBonus=\d+\) -> total=(\d+) ")
_DIE_DROPS = re.compile(r"drops=\[([^\]]*)\]")


def request_plain(run: Run) -> bytes:
    """A C->S run's decrypted body -- the key the handler reads its feed by."""
    parsed = frame.parse(frame.Link.GAME_C2S, run.body, strict=False)
    return tiles.decrypt_body(tiles.algo_id(run.opcode[1]), parsed.body)


def _drop_facts(note: str, frame_body: bytes) -> tuple[drops.Fact, ...]:
    """The `(0,38)` records as `drops.Fact`s, each row's pool from the note."""
    kinds = ["gold" if part.split(":", 1)[1].startswith("0x")
             else part.rsplit("/", 1)[1]
             for part in _DIE_DROPS.search(note).group(1).split(",") if part]
    return tuple(drops.Fact(item=item, value=value, kind=kinds[i])
                 for i, (item, value) in enumerate(drops.records(frame_body)))


#: The card note's purse, reward list and uuid:
#: `run=b67cba62... balance=5066 rewards=0x34,406010081x1`.
_CARD_BALANCE = re.compile(r"balance=(\d+)")
_CARD_REWARDS = re.compile(r"rewards=([^ ]+)")
_CARD_RUN = re.compile(r"run=([0-9a-f]{32})")

#: The `(1,34)` note's own experience: `exp +2770 (base=1200, contract=0,
#: story=1570)`.  It is the gain, not the total -- the finish moves the row
#: from wherever the kills left it (`reward.Write.exp`).
_FINISH_EXP = re.compile(r"exp \+(\d+) \(base=\d+, contract=\d+, story=\d+\)")


def reward_feed(runs: list[Run]) -> dict[bytes, list[reward.Write]]:
    """M3.4's fed inputs: the rows and experience each `(1,34)` left.

    The rows are the `(0,14)` records themselves -- the frame lists exactly
    the reward rows, with the merged totals a stack merge leaves -- and the
    experience is the note's own `exp +`.  A plain maps to a *list* and the
    replay hands them back in order, one per send: the reference's request
    bytes need not be unique for the same reason the cards' are not.
    """
    feed: dict[bytes, list[reward.Write]] = {}
    for run in runs:
        if run.opcode != (1, 34):
            continue
        note = next((n[2] for n in run.notes if n[1] == "QUEST-FINISH-34"), None)
        rows = tuple(record for f in run.replies if f.opcode == (0, 14)
                     for record in reward.refresh_records(f.plain))
        exp = _FINISH_EXP.search(note) if note is not None else None
        if rows or exp is not None:
            feed.setdefault(request_plain(run), []).append(reward.Write(
                rows=rows, exp=int(exp.group(1)) if exp is not None else None))
    return feed


def commit_feed(runs: list[Run]) -> dict[bytes, list[card.Grant]]:
    """M3.6's fed inputs: per `(1,71)`, the reference's uuid and its write.

    The rows are read off the `(0,13)` list by the ids the note's `rewards=`
    names (the `0x..` entry is gold, not an item) and the purse is its
    `balance=` -- the state the run left, not the delta it moved by.  The
    uuid is the line's own, which no live server can match; the rows and the
    purse are the same pair `reward_feed`'s quest half builds.

    A plain maps to a *list* for the card's reason: the commit request is
    eight bytes of side index, so a session's two side-0 commits are
    byte-identical and the run's identity lives in the server.
    """
    feed: dict[bytes, list[card.Grant]] = {}
    for run in runs:
        if run.opcode != (1, 71):
            continue
        note = next((n[2] for n in run.notes if n[1] == "DUNGEON-CARD-71"), None)
        body = next((f.plain for f in run.replies if f.opcode == (0, 13)), None)
        if note is None or body is None:
            continue
        wanted = {int(part.split("x")[0])
                  for part in _CARD_REWARDS.search(note).group(1).split(",")
                  if part and not part.startswith("0x")}
        feed.setdefault(request_plain(run), []).append(card.Grant(
            run_id=bytes.fromhex(_CARD_RUN.search(note).group(1)),
            write=reward.Write(
                gold=int(_CARD_BALANCE.search(note).group(1)),
                rows=tuple(record for record in reward.list_records(body)
                           if record.item_id in wanted))))
    return feed


#: The clear line's own clock and card size: `clear=64769ms ... (0,35) 286B`.
_CLEAR_MS = re.compile(r"clear=(\d+)ms")
_CLEAR_CARD = re.compile(r"\(0,35\) (\d+)B")


def clear_feed(runs: list[Run]) -> dict[bytes, clear.Card]:
    """M3.5's fed inputs: per `(1,46)`, the reference's own clock and card.

    The clock is the line's `clear=`, and the card is the `(0,35)` reply's
    body cut to the size the line states -- what the tile cipher left past
    that is padding, and the note counts the card, not the padding.
    """
    feed: dict[bytes, clear.Card] = {}
    for run in runs:
        if run.opcode != (1, 46):
            continue
        note = next((n[2] for n in run.notes if n[1] == "DUNGEON-CLEAR-46"),
                    None)
        card = next((f.plain for f in run.replies if f.opcode == (0, 35)), None)
        if note is None or card is None:
            continue
        size = int(_CLEAR_CARD.search(note).group(1))
        feed[request_plain(run)] = clear.Card(
            clear_ms=int(_CLEAR_MS.search(note).group(1)), payload=card[:size])
    return feed


def kill_feed(runs: list[Run]) -> dict[bytes, die.Play]:
    """M3.3's fed inputs: per answered `(1,39)`, what the kill left and the
    experience the character stood at before it.

    The drop records spell their item and value out and the note names each
    row's pool; the experience is `total=` minus the kill's own gain, so a
    reward between two kills (the tutorial clear's) is carried by the next
    kill's feed rather than derived.  A kill that grants nothing -- a story
    actor, an objective -- carries the running total forward, which is all
    the chain's two no-exp branches read.
    """
    feed: dict[bytes, die.Play] = {}
    total = 0
    for run in runs:
        if run.opcode != (1, 39):
            continue
        note = next((n[2] for n in run.notes if n[1] == "COMBAT-DIE-39"), None)
        answered = next((f for f in run.replies if f.opcode == (0, 38)), None)
        if note is None or answered is None:
            continue
        exp = _DIE_EXP.search(note)
        exp_before = total
        if exp:
            total = int(exp.group(2))
            exp_before = total - int(exp.group(1))
        feed[request_plain(run)] = die.Play(
            exp_before=exp_before, drops=_drop_facts(note, answered.plain))
    return feed


def note_text(msg: str) -> str:
    """A note with the one field the diff cannot compare folded out: the
    connection number."""
    return _CONN.sub("conn=N", msg)


def replayed(notes) -> list[tuple[str, str, str]]:
    """The notes the server is supposed to replay, `conn=` folded out.

    `game.UNREPLAYABLE_TAGS` is a deliberate difference, not a failure: the
    capture's own teardown -- `DISCONNECT socket error ConnectionReset`,
    `after 438.4s rx=...B`, `state released` -- describes the session the
    reference logged, and echoing it would report the capture's counters as
    this run's.
    """
    return [n for n in notes if n[1] not in game.UNREPLAYABLE_TAGS]


# ------------------------------------------------------------------ baseline

def quickslots_payload(oracle: Path) -> bytes:
    """The character's `character_quickslots` row, off the reference's push.

    The row is written by character creation, which happened inside the
    oracle run, so the pre-session backup has none -- and the rewrite has no
    creator to make one.  The reference's `(0,376)` at entry is the row plus
    the push's 12-byte trailer, so the row is the frame minus its tail.
    """
    for p in logs.iter_packets(oracle):
        # S->C records carry no opcode -- the reference's own dump line has
        # only the bytes -- so the frame is parsed to find the push.
        if p.direction != "S->C" or p.hex is None:
            continue
        f = frame.parse(frame.Link.GAME_S2C, p.frame_bytes, strict=False,
                        expect_size=p.hex.full_size)
        if (f.opcode.main, f.opcode.sub) != (0, 376):
            continue
        return plain_of(f)[:-(len(charsettings.PUSH_TRAILER))]
    raise SystemExit(f"{oracle}: no (0,376) push to take the payload from")


def make_baseline(src: Path, dst: Path, oracle: Path) -> Path:
    """The pre-session backup plus the character conn=4 plays.

    Character creation happened inside the oracle log (conn=2, 21:09:34), and
    the rewrite has no creator, so the row, its fifteen items and its
    quickslot row are seeded from the reference's own `TOWN-ITEMS` /
    `TOWN-SPAWN` / `TOWN-SELF-DATA` note at 21:09:42.337 and its `(0,376)`
    frame.  Everything else -- the account, the other two
    characters, the tables -- comes from the backup untouched.
    """
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(src) + suffix)
        if p.exists():
            q = Path(str(dst) + suffix)
            if q.exists():
                q.unlink()
            shutil.copy2(p, q)
    db = sqlite3.connect(str(dst))
    try:
        with db:
            cols = [c[1] for c in db.execute("pragma table_info(characters)")]
            names = [c for c in CHARACTER_ROW if c in cols]
            db.execute(f"insert into characters ({', '.join(names)}) "
                       f"values ({', '.join('?' * len(names))})",
                       [CHARACTER_ROW[c] for c in names])
            icols = [c[1] for c in db.execute("pragma table_info(character_items)")]
            for lst, slot, item, count, dur, seed in CHARACTER_ITEMS:
                row = {"character_id": CHARACTER, "list_type": lst,
                       "slot_index": slot, "item_id": item, "count": count,
                       "durability": dur, "instance_value": seed,
                       "updated_at": CHARACTER_ROW["created_at"]}
                names = [c for c in row if c in icols]
                db.execute(f"insert into character_items ({', '.join(names)}) "
                           f"values ({', '.join('?' * len(names))})",
                           [row[c] for c in names])
            # The starter quest is a progress row and nothing else: the
            # reference's accept row for it landed in the same second as the
            # entry burst but *after* the state line read its snapshot, so
            # the line reads `(of 0 ever accepted)` while the frame already
            # lists the quest (`TOWN-QUEST-STATE` has the whole story).
            db.execute("insert into character_quest_progress (character_id, "
                       "quest_id, trigger_value, answer_index, "
                       "counter_initialized) values (?, ?, 1, -1, 0)",
                       (CHARACTER, STARTER_QUEST))
            qcols = [c[1] for c in db.execute("pragma table_info(character_quickslots)")]
            qrow = {"character_id": CHARACTER, "payload": quickslots_payload(oracle),
                    "updated_at": CHARACTER_ROW["created_at"]}
            qnames = [c for c in qrow if c in qcols]
            db.execute(f"insert into character_quickslots ({', '.join(qnames)}) "
                       f"values ({', '.join('?' * len(qnames))})",
                       [qrow[c] for c in qnames])
            db.execute("update character_id_allocator set "
                       "next_character_id = 4 where next_character_id < 4")
    finally:
        db.close()
    return dst


def baseline_ready(path: Path) -> bool:
    """Whether the baseline carries the seeded character -- a half-built file
    from an aborted run must not be mistaken for a finished one."""
    if not path.exists():
        return False
    db = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        n = db.execute("select count(*) from characters where character_id = ?",
                       (CHARACTER,)).fetchone()[0]
        m = db.execute("select count(*) from character_items where character_id = ?",
                       (CHARACTER,)).fetchone()[0]
        q = db.execute("select count(*) from character_quickslots "
                       "where character_id = ?", (CHARACTER,)).fetchone()[0]
        p = db.execute("select count(*) from character_quest_progress "
                       "where character_id = ?", (CHARACTER,)).fetchone()[0]
        t = db.execute("select pending_tutorial_dungeon_id from characters "
                       "where character_id = ?", (CHARACTER,)).fetchone()
        return (bool(n) and m == len(CHARACTER_ITEMS) and bool(q) and bool(p)
                and t is not None and t[0] == TUTORIAL_DUNGEON)
    finally:
        db.close()


def save_copy(src: Path) -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-dungeon-diff-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(src) + suffix)
        if p.exists():
            shutil.copy2(p, Path(str(dst) + suffix))
    return dst


# -------------------------------------------------------------------- replay

class SimClock:
    """`time.time()` and `time.monotonic()` as the replay's own clock.

    The reference's handlers stamped their frames with *its* clock, and the
    `(1,4)` reply carries `now` in the clear, so replaying at real speed would
    put the day's skew into every timestamp-bearing frame and into
    `updated_at`.  The clock follows the log's recorded offsets unscaled while
    the sleep between frames is scaled -- the handlers see the pace the
    reference saw, the run takes a tenth of the time.

    It is `time.monotonic` too, and that is load-bearing: the town move
    throttle compares against it, and at a tenth of the pace an uncompressed
    clock would let three writes through where the reference made seventeen
    -- so the row would hold the wrong position and every `(0,23)` built from
    it (the `(1,15)` burst's, the `(1,42)` pair's) would disagree.
    """

    def __init__(self, epoch: int) -> None:
        self.epoch = epoch
        self.offset = 0.0

    def __call__(self) -> float:
        return self.epoch + self.offset


async def replay(save: Path, runs: list[Run], epoch: int, scale: float,
                 kills: dict[bytes, die.Play],
                 rewards: dict[bytes, list[reward.Write]],
                 clears: dict[bytes, clear.Card],
                 commits: dict[bytes, list[card.Grant]]) -> bytes:
    """Feed the oracle's bytes back at the pace its log recorded, scaled."""
    log = Log(stream=io.StringIO())
    server = game.GameServer("127.0.0.1", {PORT: game.GAME_PORTS[PORT]},
                             game.GameScript.load(), log, save_db=save,
                             unix_seconds=epoch, write_gap=0.0,
                             oracle_kills=kills, oracle_rewards=rewards,
                             oracle_clears=clears, oracle_commits=commits)
    await server.start()
    clock = SimClock(epoch)
    real_time, real_monotonic = time.time, time.monotonic
    loop = asyncio.get_running_loop()
    # asyncio asks `time.monotonic` for its own deadlines, so the loop is
    # pinned to the real one before the handlers get the sim clock: a scaled
    # gap is a *negative* one on the log's timeline.
    loop.time = real_monotonic
    time.time = clock
    time.monotonic = clock
    try:
        port = server.ports_bound()[0]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        base = loop.time()
        for run in runs:
            await asyncio.sleep(max(0.0, base + run.offset * scale - loop.time()))
            clock.offset = run.offset
            writer.write(run.body)
            await writer.drain()
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(1 << 16), timeout=1.0)
            except (asyncio.TimeoutError, ConnectionResetError):
                break
            if not chunk:
                break
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return log._fh.getvalue().encode("utf-8", "replace")
    finally:
        time.time = real_time
        time.monotonic = real_monotonic
        server.close()
        log.close()


# -------------------------------------------------------------------- report

#: The one field of a reply the two servers cannot make agree: a `(0,29)`'s
#: four seed bytes, drawn per run (`DungeonRun.seed`).  The capture's two
#: entries into dungeon 6's maze 1 differ there and agree on everything else,
#: which is what makes them a per-run draw rather than a per-maze constant.
SEED_AT = {(0, 29): slice(3, 7)}


def _comparable(f: Frame) -> tuple:
    plain = f.plain
    cut = SEED_AT.get(tuple(f.opcode))
    if cut is not None:
        plain = plain[:cut.start] + bytes(cut.stop - cut.start) + plain[cut.stop:]
    return (f.opcode, plain)


def same_replies(ref: list[Frame], ours: list[Frame]) -> bool:
    return [_comparable(f) for f in ref] == [_comparable(f) for f in ours]


def compare(o: "Options", ref: list[Run], ours: list[Run], epoch: int) -> int:
    """Diff run by run; return the number of unexplained mismatches.

    Three outcomes per run: `match` (frames, notes and dispatch all agree),
    `silent` (the reference answered and the rewrite answered nothing --
    a handler that has not been written) and `differs` (both answered, and
    they disagree -- the interesting one).
    """
    tally: dict[str, list[int]] = {}
    differ: list[tuple[int, Run, Run]] = []
    states: list[tuple[str, str, str]] = []
    for i, (a, b) in enumerate(zip(ref, ours)):
        bucket = tally.setdefault(a.key, [0, 0, 0, 0])
        bucket[0] += 1
        if a.opcode != b.opcode:
            differ.append((i, a, b))
            bucket[3] += 1
            continue
        ok = same_replies(a.replies, b.replies)
        if a.dispatch and b.dispatch and a.dispatch[:2] != b.dispatch[:2]:
            ok = False
        if ([note_text(n[2]) for n in replayed(a.notes)]
                != [note_text(n[2]) for n in replayed(b.notes)]):
            ok = False
        if a.dispatch and b.dispatch and a.dispatch[2:] != b.dispatch[2:]:
            states.append((a.key, "/".join(a.dispatch[2:]),
                           "/".join(b.dispatch[2:])))
        if ok:
            bucket[1] += 1
        elif not b.replies and not b.dispatch:
            bucket[2] += 1
        else:
            bucket[3] += 1
            differ.append((i, a, b))

    print(f"\n{'request':>10} {'runs':>5} {'match':>6} {'silent':>7} "
          f"{'differ':>7}   reference reply shape")
    for key, (n, matched, silent, bad) in sorted(tally.items()):
        shapes = sorted({len(r.replies) for r in ref if r.key == key})
        tags = sorted({t for r in ref if r.key == key for t in r.note_tags})
        print(f"{key:>10} {n:>5} {matched:>6} {silent:>7} {bad:>7}   "
              f"frames {shapes}" + (f"  notes {','.join(tags)}" if tags else ""))

    if states:
        print("\n-- state transitions the rewrite reports differently --")
        seen = set()
        for key, a, b in states:
            if (key, a, b) in seen:
                continue
            seen.add((key, a, b))
            print(f"  {key:>10}  reference {a}   rewrite {b}")

    if differ and o.verbose:
        print(f"\n-- {len(differ)} differing run(s) --")
        for i, a, b in differ:
            print(f"\nrun {i}  line {a.line}  {a.ts[11:]}  {a.key}  "
                  f"wire={a.wire} body={len(a.body)}")
            if a.opcode != b.opcode:
                print(f"    opcode: reference {a.key}  rewrite {b.key}")
                continue
            _one("replies", [(f.opcode, f.plain) for f in a.replies],
                 [(f.opcode, f.plain) for f in b.replies])
            _one("notes", [f"{n[0]} {n[1]} {note_text(n[2])}" for n in replayed(a.notes)],
                 [f"{n[0]} {n[1]} {note_text(n[2])}" for n in replayed(b.notes)])
            _one("dispatch",
                 [str(a.dispatch)] if a.dispatch else ["<none>"],
                 [str(b.dispatch)] if b.dispatch else ["<none>"])
    elif differ:
        print(f"\n{len(differ)} differing run(s); --verbose for the detail")
    return sum(v[3] for v in tally.values())


def _one(what: str, want: list, got: list) -> None:
    if want == got:
        print(f"    {what}: {len(want)} match")
        return
    print(f"    {what}: reference {len(want)}, rewrite {len(got)}")
    for i in range(max(len(want), len(got))):
        x = want[i] if i < len(want) else None
        y = got[i] if i < len(got) else None
        if x != y:
            print(f"      [{i}] reference: {_show(x)}")
            print(f"      [{i}] rewrite:   {_show(y)}")
            return


def _show(x) -> str:
    if isinstance(x, tuple) and len(x) == 2 and isinstance(x[1], bytes):
        return f"({x[0][0]},{x[0][1]}) plain={x[1].hex()[:96]}"
    return str(x)


class Options:
    verbose = False


def compare_connect(ref: list[Frame], ours: list[Frame]) -> None:
    """The pre-run frames -- just the `(0,1)` bootstrap, built from the replay
    clock rather than replayed, so it is the clock's own check."""
    if len(ref) != len(ours):
        print(f"connect group: reference {len(ref)}, rewrite {len(ours)}")
        return
    for a, b in zip(ref, ours):
        if a.opcode == b.opcode and a.plain == b.plain:
            print(f"connect group: {len(ref)} frame(s) match")
            return
        print(f"connect group: ({a.opcode[0]},{a.opcode[1]}) {len(a.plain)}B "
              f"differs from ({b.opcode[0]},{b.opcode[1]}) {len(b.plain)}B")
        for i in range(min(len(a.plain), len(b.plain))):
            if a.plain[i] != b.plain[i]:
                print(f"    first difference at {i}: reference "
                      f"{a.plain[i:i + 16].hex()} rewrite {b.plain[i:i + 16].hex()}")
                return


def list_only(connect: list[Frame], runs: list[Run]) -> None:
    print(f"connect group: {len(connect)} frame(s)")
    for f in connect:
        print(f"  ({f.opcode[0]},{f.opcode[1]}) wire={f.wire} "
              f"body={len(f.plain)}")
    print(f"\n{len(runs)} C->S frame(s):")
    seen: dict[str, int] = {}
    for r in runs:
        seen[r.key] = seen.get(r.key, 0) + 1
    for key, n in sorted(seen.items(), key=lambda kv: -kv[1]):
        rs = [r for r in runs if r.key == key]
        shapes = sorted({len(r.replies) for r in rs})
        tags = sorted({t for r in rs for t in r.note_tags})
        states = sorted({"/".join(r.dispatch[2:]) for r in rs if r.dispatch})
        print(f"  {key:>10} x{n:<4} frames {shapes}"
              + (f"  states {','.join(states)}" if states else "")
              + (f"\n             notes {','.join(tags)}" if tags else ""))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    ap.add_argument("--baseline", type=Path, default=BASELINE)
    ap.add_argument("--rebuild-baseline", action="store_true")
    ap.add_argument("--list-only", action="store_true")
    ap.add_argument("--until", type=int, default=None,
                    help="stop after this many runs")
    ap.add_argument("--op", action="append", default=[], metavar="M,S",
                    help="only diff these request opcodes (repeatable)")
    ap.add_argument("--scale", type=float, default=0.1,
                    help="multiply the recorded gaps (default 0.1)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)
    Options.verbose = args.verbose

    if args.rebuild_baseline or not baseline_ready(args.baseline):
        if not PRE_SESSION.exists():
            raise SystemExit(f"the pre-session backup is gone: {PRE_SESSION}")
        make_baseline(PRE_SESSION, args.baseline, args.oracle)
        print(f"baseline built: {args.baseline.relative_to(paths.REPO_ROOT)}")

    epoch, connect, ref = read_log(args.oracle, CONN)
    print(f"{args.oracle.name}: conn={CONN}  {len(ref)} run(s)  "
          f"epoch={epoch}  span={ref[-1].offset:.1f}s")
    if args.list_only:
        list_only(connect, ref)
        return 0

    # Every feed reads the *whole* session: a kill's experience stands on
    # every kill before it, and a commit's purse on every finish before it.
    kills = kill_feed(ref)
    rewards = reward_feed(ref)
    clears = clear_feed(ref)
    commits = commit_feed(ref)
    print(f"kill feed: {len(kills)} answered (1,39); "
          f"reward feed: {len(rewards)} (1,34); "
          f"clear feed: {len(clears)} (1,46); "
          f"commit feed: {len(commits)} (1,71)")

    # `--op` narrows the *comparison*, not the replay: a handler's state --
    # the ground the kills left, the bag the rewards moved -- is built by the
    # runs the filter drops, so sending only the wanted frames would compare
    # a session the capture never played.
    runs = ref
    if args.until is not None:
        runs = [r for r in ref
                if r.line <= ref[min(args.until, len(ref)) - 1].line]
    wanted = {tuple(int(x) for x in o.split(",")) for o in args.op}
    print(f"replaying {len(runs)} frame(s) at scale {args.scale} "
          f"(~{runs[-1].offset * args.scale:.0f}s)")

    save = save_copy(args.baseline)
    try:
        text = asyncio.run(replay(save, runs, epoch, args.scale, kills, rewards,
                                  clears, commits))
    finally:
        shutil.rmtree(save.parent, ignore_errors=True)

    _, our_connect, ours = read_log_bytes(text)
    compare_connect(connect, our_connect)
    if len(ours) != len(runs):
        print(f"!! the rewrite logged {len(ours)} C->S frame(s), "
              f"the replay sent {len(runs)}")
    feed = [r for r in runs if not wanted or r.opcode in wanted]
    ours = [r for r in ours if not wanted or r.opcode in wanted]
    return 1 if compare(args, feed, ours, epoch) else 0


def read_log_bytes(text: bytes) -> tuple[int, list[Frame], list[Run]]:
    """`read_log` over an in-memory log the replay just wrote."""
    tmp = Path(tempfile.mkdtemp(prefix="dfo-dungeon-log-")) / "replay.log"
    tmp.write_bytes(text)
    try:
        return read_log(tmp, None)
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
