#!/usr/bin/env python3
"""Drive the rewritten server with the captured session, to produce a log to diff.

`tools/diff_packets.py` needs two logs; this produces the second one.  It
brings up the channel link and the one game port the corpus used, then replays
the capture's exact C->S frames -- 3 channel requests on 7001, then the 221
game requests on 10013 -- reading the S->C stream concurrently, because the
42KB town burst can otherwise fill the socket buffer and deadlock a
send-it-all-then-read client against a server blocked in `drain()`.

    python tools/replay_capture.py                     # -> Logs/server-rewrite.log
    python tools/diff_packets.py <ref> <new> --session channel --session game

`--external` drops the servers and replays at somebody else's: point it at the
reference and the frames it truncated in the capture come back whole, in the
reference's own log.  That is the only way to recover them -- the capture is the
sole log with packet dumps, and its 4096B cap is what cut them.  Two settings
have to move first, in the per-user `server.json` the server is started with
(`--config`, which is not the copy sitting in the server directory):

* `diagnostics.packetHexMaxBytes` above the largest frame (65536 is ample);
* `diagnostics.logDirectory` pointing **outside** the reference's own `Logs/`.
  That directory is the corpus -- several tests scan everything in it -- and a
  replay is not a session anyone played.  `dfo-server/Logs/` is the place.

    python tools/replay_capture.py --external --host 192.168.1.6 --send-gap 0.002
    python tools/extract_game_replies.py --json --completion Logs/reference-replay-*.log

The ports are the captured ones and the bind is loopback, so the log's
`channel:7001` / `game:10013` lines read like the capture's.  `conn=` comes out
matching too (channel=1, game=2) because both servers share one `ConnectionIds`
in the same order the reference connected them.

The CHANNELINFO's field 11 is a unix timestamp, so that one body is generated
from the live clock and cannot equal the capture's day-old one.  The diff
compares body *sizes*, so it does not care; `tests/test_game_server.py` pins
the clock when it wants the bytes.

The log is always written at DEBUG: the packet dumps are the entire point of it.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.server import channel, game  # noqa: E402
from uslocalserver.server.ids import ConnectionIds  # noqa: E402
from uslocalserver.server.logfile import Log  # noqa: E402

CORPUS = paths.LOGS_DIR / "server-20260926.log"
CHANNEL_PORT = channel.CHANNEL_PORT
GAME_PORT = 10013
IDLE_SECONDS = 1.0


def session_c2s(ref: Path, kind: str) -> list[bytes]:
    """Every C->S frame the corpus sent on one link, in wire order."""
    s = logs.corpus_session(ref, kind)
    return [p.frame_bytes for p in logs.iter_packets(ref)
            if p.hex is not None and p.link == kind and p.direction == "C->S"
            and s.first <= p.line_no <= s.last]


async def exchange(host: str, port: int, payloads: list[bytes],
                   idle: float, send_gap: float = 0.0) -> tuple[int, int]:
    """Send every payload, read until the peer has been quiet for `idle`s.

    Returns `(sent, received)` bytes.  A real client never closes between
    requests and neither does the server, so silence is the end-of-replies
    signal; the write gap is 5-12ms, three orders of magnitude under `idle`.
    """
    reader, writer = await asyncio.open_connection(host, port)
    sent = sum(len(p) for p in payloads)
    got = 0

    async def pump():
        for raw in payloads:
            writer.write(raw)
            await writer.drain()
            if send_gap:
                await asyncio.sleep(send_gap)

    sender = asyncio.create_task(pump())
    try:
        await asyncio.wait_for(sender, timeout=30.0)
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(1 << 16), timeout=idle)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            got += len(chunk)
    finally:
        if not sender.done():
            sender.cancel()
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    return sent, got


async def replay_external(args: argparse.Namespace) -> int:
    """Replay at a server we did not start -- the reference, to make it dump
    the bodies its own capture truncated.  Nothing here writes a log: the
    trace we want is the one the target writes for itself.
    """
    for kind, port in (("channel", CHANNEL_PORT), ("game", GAME_PORT)):
        payloads = session_c2s(args.corpus, kind)
        sent, got = await exchange(args.host, port, payloads, args.idle, args.send_gap)
        print(f"{kind}:{port}  replayed {len(payloads)} frames, {sent}B sent, {got}B back")
    return 0


async def replay(args: argparse.Namespace) -> int:
    if args.external:
        return await replay_external(args)

    log_path = Path(args.log) if args.log else paths.REPO_ROOT / "Logs" / "server-rewrite.log"
    log = Log(log_path, level="DEBUG")
    ids = ConnectionIds()
    srv = channel.ChannelServer(args.host, CHANNEL_PORT, channel.ChannelReplies.load(),
                                log, ids=ids, write_gap=args.gap_ms / 1000)
    gsrv = game.GameServer(args.host, {GAME_PORT: game.GAME_PORTS[GAME_PORT]},
                           game.GameScript.load(), log, ids=ids,
                           write_gap=args.gap_ms / 1000)
    await srv.start()
    await gsrv.start()
    try:
        for kind, port in (("channel", CHANNEL_PORT), ("game", GAME_PORT)):
            payloads = session_c2s(args.corpus, kind)
            sent, got = await exchange(args.host, port, payloads, args.idle, args.send_gap)
            print(f"{kind}:{port}  replayed {len(payloads)} frames, {sent}B sent, {got}B back")
        # Handlers write their own `DISCONNECT` in a `finally` that only runs
        # once the peer's FIN has been read.  Nothing below awaits, so without
        # this the log closes underneath them and their last lines are lost --
        # and the game session's range would end before its final reply.
        await asyncio.sleep(args.settle)
    finally:
        gsrv.close()
        srv.close()
        log.info("LISTEN", "all listeners stopped; 0 connection(s) still draining")
        log.close()
    print(f"wrote {log_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default loopback), or with --external the "
                         "address to replay at")
    ap.add_argument("--external", action="store_true",
                    help="replay at an already-running server instead of starting "
                         "one; writes no log of its own")
    ap.add_argument("--send-gap", type=float, default=0.0, metavar="SECONDS",
                    help="pause between C->S writes (default 0; the reference "
                         "wants a few ms or it sees a burst no client produces)")
    ap.add_argument("--log", default=None,
                    help="log file (default <repo>/Logs/server-rewrite.log)")
    ap.add_argument("--corpus", type=Path, default=CORPUS,
                    help=f"reference log to replay (default {CORPUS.name})")
    ap.add_argument("--gap-ms", type=float, default=game.WRITE_GAP_SECONDS * 1000,
                    help="S->C write gap for both links")
    ap.add_argument("--idle", type=float, default=IDLE_SECONDS,
                    help=f"seconds of silence that end a link (default {IDLE_SECONDS})")
    ap.add_argument("--settle", type=float, default=0.2,
                    help="seconds to let the handlers finish their DISCONNECT lines")
    args = ap.parse_args(argv)
    return asyncio.run(replay(args))


if __name__ == "__main__":
    raise SystemExit(main())
