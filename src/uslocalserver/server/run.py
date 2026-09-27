"""Start the rewritten server.

    python -m uslocalserver.server.run --host 127.0.0.1 --port 7001

M1 is being built up link by link; this brings up the channel link and the
game links behind it, sharing one `ConnectionIds` so `conn=` numbering keeps
matching the reference.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .. import paths
from ..protocol import channelinfo
from . import channel, game
from .ids import ConnectionIds
from .logfile import Log


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default="0.0.0.0", help="bind address")
    p.add_argument("--port", type=int, default=channel.CHANNEL_PORT,
                   help=f"channel port (default {channel.CHANNEL_PORT})")
    p.add_argument("--game-port", type=int, action="append", default=None,
                   help=f"repeatable, exactly {len(game.GAME_PORTS)} times: bind the game "
                        "links on these ports instead, keeping each port's channel in "
                        "sorted order.  The launcher shifts the whole block when the "
                        "defaults are busy; the client follows the launcher.")
    p.add_argument("--log", default=None,
                   help="log file (default <repo>/Logs/server-rewrite.log)")
    p.add_argument("--save", type=Path, default=paths.SAVE_DB,
                   help=f"save database to read and write (default {paths.SAVE_DB}); "
                        "'none' keeps the write handlers off and replays only")
    p.add_argument("--write-gap-ms", type=float,
                   default=channel.WRITE_GAP_SECONDS * 1000,
                   help="minimum gap between channel S->C writes; protocol "
                        "requirement, see server.reference.json")
    p.add_argument("--game-write-gap-ms", type=float,
                   default=game.WRITE_GAP_SECONDS * 1000,
                   help="minimum gap between game S->C writes")
    p.add_argument("--quiet", action="store_true",
                   help="drop DEBUG PACKET dumps from the log")
    return p


async def _main(args: argparse.Namespace) -> None:
    log_path = Path(args.log) if args.log else paths.REPO_ROOT / "Logs" / "server-rewrite.log"
    log = Log(log_path, level="INFO" if args.quiet else "DEBUG")
    replies = channel.ChannelReplies.load()
    script = game.GameScript.load()
    advertise = channelinfo.local_address()
    ids = ConnectionIds()
    ports = game.remap_ports(args.game_port) if args.game_port else game.GAME_PORTS
    save = None if str(args.save).lower() == "none" else args.save
    srv = channel.ChannelServer(args.host, args.port, replies, log,
                                ids=ids,
                                write_gap=args.write_gap_ms / 1000)
    gsrv = game.GameServer(args.host, ports, script, log,
                           ids=ids,
                           write_gap=args.game_write_gap_ms / 1000,
                           advertise_host=advertise, save_db=save)
    await srv.start()
    await gsrv.start()
    # The reference's own startup block, in its own order: listeners first,
    # then one START line and one STAGE line that name every link this server
    # answers on.  `login_ok_port` is advertised, never bound.
    log.info("START", f"bind={args.host} advertise={advertise} channel={args.port} "
                      f"game={sorted(ports)} "
                      f"login_ok_port={game.LOGIN_OK_PORT} "
                      f"write_gap=channel:{args.write_gap_ms:g}ms/"
                      f"game:{args.game_write_gap_ms:g}ms")
    log.info("STAGE", f"channel script={replies.plain_size('SCRIPT_ACK')}B "
                      f"directory={replies.plain_size('CHANNEL_ACK')}B; "
                      f"channel + login + roster + town-entry protocol active")
    if (mismatch := channel.block_warning(replies, args.port)) is not None:
        log.warn("BODIES", mismatch)
    log.info("GAME", f"script: {len(script)} C->S opcodes, {script.reply_count} replies, "
                     f"{len(script.unanswered())} answered never; source={script.source}")
    print(f"channel listening on {args.host}:{args.port}, game on "
          f"{args.host}:{sorted(ports)}; save={save or 'none (replay only)'}; "
          f"logging to {log_path}", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        gsrv.close()
        srv.close()
        log.info("LISTEN", "all listeners stopped; 0 connection(s) still draining")
        log.close()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
