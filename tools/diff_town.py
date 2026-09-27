#!/usr/bin/env python3
"""Diff the rewrite's `(1,35)` / `(1,36)` handling against the reference's.

The oracle log holds the five driven sessions of `tools/probe_town.py` against
the real server (2026-09-27, `packetHexMaxBytes` raised so every dump is
whole).  Each session opens with the *corpus* replay -- the client's own frames,
`(1,35)` moves and the five `(1,36)` teleports of its town-loading chain
included -- and then carries the probe's constructed injects.  This tool
replays each session's C->S bytes verbatim, at the timestamps the reference's
own log recorded for them, on a copy of the baseline save.

The timestamps are the load-bearing part.  The reference's `(1,35)` handler is
throttled to one write per 2s, *and* it processes frames one at a time (a
write costs it ~30ms), so the gap its timer measured between two sends is the
gap its log shows.  Replaying at those recorded gaps reproduces the timer's
view of the session on a rewrite that processes much faster; replaying at the
client's own send pace would not.

Replayed in order against one save copy, the sessions chain the way the
reference's did (conn=2 starts where conn=1 left off), which is what lets the
`from=` column and the final row be checked at all.

Compared per session, in the oracle's order:

  * every `TOWN-MOVE-35` / `TOWN-AREA-36` INFO line -- that is the throttle
    attribution *and* the values written, since a throttled move logs nothing;
  * every `(0,23)` / `(0,24)` S->C frame, byte for byte, plaintext included;
  * every `(1,36)` DISPATCH line.

Then the save's `characters` row against the last location the reference's own
last line says it wrote.  `updated_at` is a wall clock on both sides and is
reported, not compared.

    python tools/diff_town.py
    python tools/diff_town.py --conn 2          # sessions 1..2, diff 2 only
"""
from __future__ import annotations

import argparse
import asyncio
import io
import re
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402
from uslocalserver.server import game  # noqa: E402
from uslocalserver.server.logfile import Log  # noqa: E402

DEFAULT_ORACLE = paths.REPO_ROOT / "Logs-townprobe" / "server-20260927.log"
PORT = 10013
CHARACTER = 1
AREA = (1, 36)
ACKS = frozenset({(0, 23), (0, 24)})
TOWN_TAGS = ("TOWN-MOVE-35", "TOWN-AREA-36")
_WANTED = frozenset(("PACKET", "DISPATCH") + TOWN_TAGS)

#: A location as the reference states one: the AREA line carries all five
#: values; a MOVE line carries the position and facing only.
_MOVE = re.compile(r"pos=\((-?\d+),(-?\d+)\) dir=(\d+)")
_AREA = re.compile(r"to=\((\d+),(\d+)\) pos=\((-?\d+),(-?\d+)\) dir=(\d+)")
#: Our own log lines: ts, level, tag, message (the tag is space-padded).
_OUR_LINE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+ [+-]\d\d:\d\d "
                       r"(\w+)\s+(\S+)\s+(.*)$")
_PROSE = re.compile(r"^conn=\d+ (.*)$")


@dataclass(slots=True)
class Session:
    """One oracle connection, reduced to what gets replayed and compared."""
    conn: int
    c2s: list[tuple[float, bytes]] = field(default_factory=list)
    acks: list[bytes] = field(default_factory=list)
    lines: list[tuple[str, str]] = field(default_factory=list)
    dispatches: list[str] = field(default_factory=list)
    span: float = 0.0

    @property
    def entries(self) -> int:
        """How many `(1,143)` town entries the session carries -- each one adds
        the entry pair to the ack count without a `(1,36)` DISPATCH of its own."""
        return sum(1 for _, raw in self.c2s
                   if (f := frame.parse(frame.Link.GAME_C2S, raw)).opcode.main == 1
                   and f.opcode.sub == 143)

    def last_location(self) -> tuple[int, int, int, int, int] | None:
        """(town, area, x, y, dir) as the session's last town line leaves it."""
        loc: tuple[int, int, int, int, int] | None = None
        for tag, prose in self.lines:
            if tag == "TOWN-AREA-36" and (m := _AREA.search(prose)):
                loc = tuple(int(g) for g in m.groups())
            elif tag == "TOWN-MOVE-35" and loc and (m := _MOVE.search(prose)):
                loc = (loc[0], loc[1]) + tuple(int(g) for g in m.groups())
        return loc


def _seconds(ts: str) -> float:
    """`2026-09-27 18:54:32.864 +08:00` -> seconds since 18:00:00, offsets
    only (the log's own day/hour are the same throughout and cancel)."""
    return (int(ts[11:13]) * 3600 + int(ts[14:16]) * 60 + float(ts[17:23]))


def oracle_sessions(path: Path) -> list[Session]:
    """The log's game sessions, in order, with the reference's town statements.

    Scoped by line range, not by `conn=`: the sessions ran back to back against
    one live save, and each one's C->S bytes are replayed as they were.
    """
    scopes = [s for s in logs.sessions(path) if s.kind == "game"]
    packets = {p.line_no: p for p in logs.iter_packets(path)}
    by_conn: dict[int, Session] = {}

    def scope_of(lineno: int) -> Session | None:
        for s in scopes:
            if s.first <= lineno <= s.last:
                return by_conn.setdefault(s.conn, Session(conn=s.conn))
        return None

    for ln in logs.stream(path):
        if ln.tag not in _WANTED:
            continue
        if (scope := scope_of(ln.line_no)) is None:
            continue
        if ln.tag == "PACKET":
            p = packets.get(ln.line_no)
            if p is None or p.link != "game" or p.hex is None:
                continue
            if p.direction == "C->S":
                if p.truncated:
                    raise SystemExit(f"line {ln.line_no}: truncated C->S dump")
                scope.c2s.append((_seconds(ln.ts), p.frame_bytes))
            else:
                f = frame.parse(frame.Link.GAME_S2C, p.frame_bytes, strict=False,
                                expect_size=p.hex.full_size)
                if (f.opcode.main, f.opcode.sub) in ACKS:
                    scope.acks.append(tiles.decrypt_body(
                        tiles.algo_id(f.opcode.sub), f.body))
        elif ln.tag in TOWN_TAGS:
            m = _PROSE.match(ln.msg)
            scope.lines.append((ln.tag, m.group(1) if m else ln.msg))
        elif (m := _PROSE.match(ln.msg)) and m.group(1).startswith(f"({AREA[0]},{AREA[1]})"):
            scope.dispatches.append(m.group(1))

    out = list(by_conn.values())
    for s in out:
        if s.c2s:
            base = s.c2s[0][0]
            s.c2s = [(t - base, raw) for t, raw in s.c2s]
            s.span = s.c2s[-1][0]
    return out


def read_row(path: Path):
    db = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    try:
        return db.execute(
            "select town_id, area_id, position_x, position_y, town_state, "
            "updated_at from characters where character_id = ?",
            (CHARACTER,)).fetchone()
    finally:
        db.close()


def save_copy(src: Path) -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-town-diff-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(src) + suffix)
        if p.exists():
            shutil.copy2(p, Path(str(dst) + suffix))
    return dst


async def replay(save: Path, session: Session) -> tuple[bytes, str]:
    """Feed one session's bytes back at the pace its log recorded.

    The schedule is absolute from the session's first frame, so a rewrite that
    answers faster than the reference did changes nothing -- the frames still
    land where the log says they landed.
    """
    log = Log(stream=io.StringIO())
    server = game.GameServer("127.0.0.1", {PORT: game.GAME_PORTS[PORT]},
                             game.GameScript.load(), log, save_db=save,
                             unix_seconds=1_789_824_022, write_gap=0.0)
    await server.start()
    try:
        port = server.ports_bound()[0]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        loop = asyncio.get_running_loop()
        base = loop.time()
        for offset, raw in session.c2s:
            await asyncio.sleep(max(0.0, base + offset - loop.time()))
            writer.write(raw)
            await writer.drain()
        got = bytearray()
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(1 << 16), timeout=1.0)
            except (asyncio.TimeoutError, ConnectionResetError):
                break
            if not chunk:
                break
            got += chunk
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return bytes(got), log._fh.getvalue()
    finally:
        server.close()
        log.close()


def our_log_lines(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    lines: list[tuple[str, str]] = []
    dispatches: list[str] = []
    for raw in text.splitlines():
        m = _OUR_LINE.match(raw)
        if not m:
            continue
        tag, msg = m.group(2), m.group(3)
        prose = _PROSE.match(msg)
        body = prose.group(1) if prose else msg
        if tag in TOWN_TAGS:
            lines.append((tag, body))
        elif tag == "DISPATCH" and body.startswith(f"({AREA[0]},{AREA[1]})"):
            dispatches.append(body)
    return lines, dispatches


def our_acks(payload: bytes) -> list[bytes]:
    stream = frame.FrameStream(frame.Link.GAME_S2C)
    stream.feed(payload)
    out = []
    while (f := stream.next_frame()) is not None:
        if (f.opcode.main, f.opcode.sub) in ACKS:
            out.append(tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body))
    return out


def _show(x) -> str:
    if isinstance(x, bytes):
        return x.hex()
    if isinstance(x, tuple):
        return f"{x[0]} {x[1]}".strip() if len(x) == 2 else " | ".join(map(str, x))
    return str(x)


def compare(what: str, want: list, got: list, problems: list[str]) -> None:
    if want == got:
        print(f"        {len(got)} {what} match")
        return
    problems.append(f"{what}: reference {len(want)}, rewrite {len(got)}")
    for i in range(max(len(want), len(got))):
        a = want[i] if i < len(want) else None
        b = got[i] if i < len(got) else None
        if a != b:
            print(f"        [{i}] reference: {_show(a)}")
            print(f"        [{i}] rewrite:   {_show(b)}")
            break


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    ap.add_argument("--save", type=Path, default=paths.SAVE_DB,
                    help="baseline save; the sessions chain on one copy of it")
    ap.add_argument("--conn", type=int, default=None,
                    help="replay sessions 1..N, diff only N")
    args = ap.parse_args(argv)

    sessions = oracle_sessions(args.oracle)
    print(f"{args.oracle.name}: {len(sessions)} session(s)")
    for s in sessions:
        print(f"  conn={s.conn}  {len(s.c2s)} C->S  {len(s.acks)} ack  "
              f"{len(s.lines)} town line(s)  {s.span:.1f}s")
    print(f"baseline row: {read_row(args.save)}")

    save = save_copy(args.save)
    refused = 0
    try:
        for s in sessions:
            if args.conn is not None and s.conn > args.conn:
                break
            payload, text = asyncio.run(replay(save, s))
            if args.conn is not None and s.conn != args.conn:
                continue
            print(f"\nconn={s.conn}  {len(s.c2s)} request(s), {s.span:.1f}s")
            lines, dispatches = our_log_lines(text)
            problems: list[str] = []
            compare("INFO line(s)", s.lines, lines, problems)
            compare("ack frame(s)", [b.hex() for b in s.acks],
                    [b.hex() for b in our_acks(payload)], problems)
            compare("DISPATCH line(s)", s.dispatches, dispatches, problems)
            if len(s.acks) != 2 * (len(dispatches) + s.entries):
                problems.append(f"ack/entry count: {len(s.acks)} frames for "
                                f"{len(dispatches)} (1,36) + {s.entries} (1,143)")
            refused += len(problems)
        final = read_row(save)
    finally:
        shutil.rmtree(save.parent, ignore_errors=True)

    last = sessions[-1].last_location()
    print(f"\nfinal row:  {final}")
    print(f"last line:  {last}  (town, area, x, y, dir)")
    if last is not None and final is not None and tuple(final)[:5] != last:
        print("!! the row does not end where the reference's last line left it")
        refused += 1
    print(f"\n{refused} unexplained mismatch(es)")
    return 1 if refused else 0


if __name__ == "__main__":
    raise SystemExit(main())
