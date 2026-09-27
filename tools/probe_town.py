#!/usr/bin/env python3
"""Drive the reference's `(1,35)` TOWN-MOVE / `(1,36)` TOWN-AREA with
*constructed* C->S frames, at controlled times.

The corpus answers the static questions -- both bodies' layouts are read off
the C->S hex and the reference's own parsed INFO lines (M2.4 recon).  Three
things it cannot answer are timing and write-attribution questions:

* `(1,35)` is throttled.  Consecutive INFO lines are never closer than
  2.001s in any of the three logs, a 1 Hz client walks away with a persist
  every second line, and one burst (09-26 22:16:39.97) persists *nothing*
  for seven sends.  This probe separates "2 s since the last persist" from
  the burst's explanation.
* which columns each handler writes.  The save is read back with `--db`,
  after the session, so the last write wins and the earlier ones are
  invisible -- hence one distinctive coordinate per scenario and a scenario
  per question.
* whether the request's trailing 11 bytes are validated or echoed.

Scenarios (`--scenario`, one session each):

    throttle  A move, 0.2s later B, 2.2s later C, 0.25s later D.
              Expect INFO for A and C only, and the save on C's values --
              D's later coordinates are what proves D never wrote.
    area      one (1,36) to a distinctive town/area, then a move 0.3s later.
              Expect the (0,23)+(0,24) pair, the save on the area's values,
              and a throttled move (the AREA write resets the 2 s timer).
    edge      (1,36) to town/area 0 at (0,0), then a move to (65535,65535).

The reference must already be running with its per-user `server.json` pointing
`diagnostics.logDirectory` at a fresh file and `packetHexMaxBytes` raised --
see `_m23/fix_server_json.py`.  Back the `uslocalserver.db*` set up first and
restore it after: every scenario writes the save.

    python tools/probe_town.py --scenario throttle --db
"""
from __future__ import annotations

import argparse
import asyncio
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402

CORPUS = paths.LOGS_DIR / "server-20260926.log"
MOVE_SUB = 35
AREA_SUB = 36
FIRST_SEQ = 220
SAVE = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\uslocalserver.db")


def move_body(x: int, y: int, direction: int, param: int) -> bytes:
    """8B: u16le x, u16le y, u8 dir, u8 param, u16 zero."""
    return struct.pack("<HHBBH", x, y, direction, param, 0)


def area_body(to_town: int, to_area: int, x: int, y: int, direction: int,
              trailer: bytes) -> bytes:
    """24B: u32le town, u32le area, u16le x, u16le y, u8 dir, 11B trailer."""
    if len(trailer) != 11:
        raise ValueError(f"trailer is 11B, got {len(trailer)}")
    return struct.pack("<IIHHB", to_town, to_area, x, y, direction) + trailer


def build(sub: int, body: bytes, seq: int) -> bytes:
    opcode = frame.Opcode(1, sub, frame.OpcodeEncoding.U8_U16LE, True)
    return frame.build(frame.Link.GAME_C2S, opcode,
                       tiles.encrypt_body(tiles.algo_id(sub), body),
                       seq=seq, trailer=bytes(4) + struct.pack("<H", seq))


def echo_trailer(town: int, area: int, extra: int = 0) -> bytes:
    """The shape every captured trailer has: from-town, from-area, then a
    third u32 whose value tracks something not yet understood."""
    return struct.pack("<II", town, area) + struct.pack("<I", extra)[:3]


#: `(delay_before, sub, body, note)` per scenario.  The first delay is long
#: enough to outlive the capture's own last persist: the server keeps draining
#: the replayed burst after the client stops sending (each DB-writing frame
#: costs ~30ms), so its last write lands ~2s after the burst goes out and the
#: 3s of the first probe still fell inside that timer.  6s clears it.
SCENARIOS: dict[str, tuple[tuple[float, int, bytes, str], ...]] = {
    "throttle": (
        (6.0, MOVE_SUB, move_body(1111, 222, 6, 190), "A expect persist"),
        (0.2, MOVE_SUB, move_body(3333, 444, 1, 100), "B expect throttle"),
        (2.2, MOVE_SUB, move_body(5555, 666, 2, 160), "C expect persist"),
        (0.25, MOVE_SUB, move_body(7777, 888, 3, 100), "D expect throttle"),
    ),
    "area": (
        (6.0, AREA_SUB, area_body(222, 3, 777, 888, 4, echo_trailer(11, 22, 33)),
         "E expect persist + 2 frames"),
        (0.3, MOVE_SUB, move_body(1234, 5678, 7, 190), "F expect throttle"),
    ),
    "edge": (
        (6.0, AREA_SUB, area_body(0, 0, 0, 0, 0, echo_trailer(0, 0, 0)),
         "G town/area 0 at (0,0)"),
        (2.2, MOVE_SUB, move_body(65535, 65535, 255, 255), "H u16 max, dir 255"),
    ),
    "signed": (
        (6.0, AREA_SUB, area_body(1, 1, 65535, 40000, 200, echo_trailer(0, 0, 0)),
         "I x=65535 y=40000: i16 parse and reply re-encoding"),
        (2.2, MOVE_SUB, move_body(32768, 1, 0, 200), "J x=32768 boundary"),
    ),
}


def capture_frames(corpus: Path) -> list[bytes]:
    s = logs.corpus_session(corpus, "game")
    return [p.frame_bytes for p in logs.iter_packets(corpus)
            if p.hex is not None and p.link == "game" and p.direction == "C->S"
            and s.first <= p.line_no <= s.last]


def replace_seq(raw: bytes, seq: int) -> bytes:
    return raw[:11] + struct.pack("<H", seq) + raw[13:]


def splice(corpus: Path, injects: list[bytes]) -> list[bytes]:
    frames = capture_frames(corpus)
    last = frames[-1]
    if (last[0], struct.unpack_from("<H", last, 1)[0]) != (1, 3):
        raise SystemExit(f"capture no longer ends with (1,3): "
                         f"({last[0]},{struct.unpack_from('<H', last, 1)[0]})")
    return frames[:-1] + injects + [replace_seq(last, FIRST_SEQ + len(injects))]


async def exchange(host: str, port: int, payloads: list[bytes],
                   delays: dict[int, float], idle: float) -> tuple[bytes, list[str]]:
    """Send `payloads`; before index i, sleep `delays.get(i, 0.002)`."""
    reader, writer = await asyncio.open_connection(host, port)
    got = bytearray()
    marks: list[str] = []

    async def pump():
        for i, raw in enumerate(payloads):
            await asyncio.sleep(delays.get(i, 0.002))
            writer.write(raw)
            await writer.drain()
            if i in delays:
                marks.append(f"  sent inject at index {i} (delay {delays[i]}s)")
        await asyncio.sleep(1.0)

    sender = asyncio.create_task(pump())
    try:
        await asyncio.wait_for(sender, timeout=120.0)
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(1 << 16), timeout=idle)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            got += chunk
    finally:
        if not sender.done():
            sender.cancel()
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    return bytes(got), marks


def report_s2c(data: bytes) -> None:
    stream = frame.FrameStream(frame.Link.GAME_S2C)
    stream.feed(data)
    n = 0
    while (f := stream.next_frame()) is not None:
        plain = tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)
        if f.opcode.sub in (23, 24):
            print(f"    [{n:>3}] {f.opcode} body={len(f.body)}B plain={plain.hex()}")
        n += 1
    print(f"  ({n} S->C frame(s) total)")


def show_db(character_id: int) -> None:
    import sqlite3
    db = sqlite3.connect(f"file:{SAVE}?mode=ro", uri=True)
    cols = [c[1] for c in db.execute("pragma table_info(characters)")]
    row = db.execute("select * from characters where character_id = ?",
                     (character_id,)).fetchone()
    print("  characters:", dict(zip(cols, row)) if row else None)
    print("  previous_village:",
          db.execute("select * from character_previous_village where character_id = ?",
                     (character_id,)).fetchall())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scenario", choices=sorted(SCENARIOS), default="throttle")
    ap.add_argument("--host", default="192.168.1.6")
    ap.add_argument("--port", type=int, default=10013)
    ap.add_argument("--corpus", type=Path, default=CORPUS)
    ap.add_argument("--character", type=int, default=1)
    ap.add_argument("--db", action="store_true", help="print the save after")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--idle", type=float, default=6.0)
    args = ap.parse_args(argv)

    steps = SCENARIOS[args.scenario]
    injects = [build(sub, body, FIRST_SEQ + i)
               for i, (_, sub, body, _) in enumerate(steps)]
    print(f"scenario {args.scenario}: {len(steps)} inject(s), "
          f"seqs {FIRST_SEQ}..{FIRST_SEQ + len(injects) - 1}")
    for i, ((delay, sub, body, note), raw) in enumerate(zip(steps, injects)):
        parsed = frame.parse(frame.Link.GAME_C2S, raw)
        back = tiles.decrypt_body(tiles.algo_id(sub), parsed.body)
        same = "ok" if back == body else f"MISMATCH {back.hex()}"
        print(f"  [{i}] +{delay}s ({1},{sub}) {len(raw)}B body={body.hex()} "
              f"reparse={same}  {note}")
    if args.dry_run:
        print("dry run: nothing sent")
        return 0

    payloads = splice(args.corpus, injects)
    base = len(payloads) - 1 - len(injects)
    delays = {base + i: delay for i, (delay, _, _, _) in enumerate(steps)}
    print(f"\nreplaying {len(payloads)} frames to {args.host}:{args.port}, "
          f"injects at {base}..{base + len(injects) - 1} ...")
    got, marks = asyncio.run(exchange(args.host, args.port, payloads, delays, args.idle))
    for m in marks:
        print(m)
    report_s2c(got)
    if args.db:
        show_db(args.character)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
