#!/usr/bin/env python3
"""Hold the rewrite armed and take over the port block the launcher just chose.

The launcher owns the port choice, so a live swap cannot squat a fixed port.
Measured 2026-09-27: it starts the reference on the default block (7001 +
10011-10021) when that is free and shifts the whole block when it is busy
(60652, 62676, 53922, 57491, 49321 all seen), then rewrites the client's
server list to match -- the client follows the launcher and nothing else.
Squatting 7001 therefore does not intercept: it only makes the launcher pick
another block, and the client goes with it.

What works is to mirror the block, in the ~20s between the reference binding
it and the client connecting: the reference announces itself in its own log
(`INFO START ... bind=H channel=N game=[...]`), and this process then

  1. connects to the reference's channel port and replays the three fixed
     client requests -- byte-identical in every captured session (the `(0,11)`
     one's 32B body included, so no challenge/response is in play) -- and
     collects the three S->C bodies it answers with;
  2. kills the reference (`taskkill /F /IM`; only the holder can free the ports);
  3. binds the same host and ports and serves the client with those bodies.

Step 1 is not optional.  The third body, CHANNEL_ACK, is this launch's
directory -- it carries the port block the launcher just picked -- and one
replayed from an older session has the client take the stale endpoints and
drop the connection without a sound (measured 2026-09-27: three such drops).
Only the reference can generate the fresh one, and it is alive for exactly
those seconds.  The other two bodies are stable across sessions and come
along for free.

The probe returns the bodies *sealed*: the two big ones are day-keyed
(`zlib(AES-128-ECB(plaintext))`, see `server.channel`).  They are unsealed
here with the day the CONNECT_ACK token names, so the keeper holds plaintext
and re-seals it against the live clock like every other path -- a takeover
that straddles midnight keeps working instead of replaying yesterday's key.

Everything slow -- imports, the 143KB reply script, the channel blobs -- is
loaded before arming, so a takeover is one probe plus one taskkill plus one
bind, against a client that connects 20s later (START -> client channel
CONNECT measured 19.9-23.7s over 13 sessions).

    python tools/live_swap.py           # arm; swap on the next START line
    python tools/live_swap.py --now     # swap on the block already in the log

Attach skips to EOF: every START line already in the log predates the swap.
It keeps watching afterwards, because when the block the launcher wants is
ours it shifts again -- each announcement is another block to mirror, and the
previous listeners stay up (the launcher may still send the client to one of
them).

The log written is the rewrite's standard `Logs/server-rewrite.log`, so the
session that follows is read with the same tools as any other rewrite run.
"""
from __future__ import annotations

import argparse
import asyncio
import re
import socket
import subprocess
import sys
import zlib
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from uslocalserver import paths
from uslocalserver.protocol import channelinfo, frame
from uslocalserver.server import channel, game
from uslocalserver.server.ids import ConnectionIds
from uslocalserver.server.logfile import Log

EXE_NAME = "USLocalServer.Server.exe"

#: One announcement, in the reference's own startup block.  `bind` is mirrored
#: too: the capture binds 192.168.1.6 and the client's config points there.
START_RE = re.compile(
    r"\bINFO\s+START\b.*?bind=(\S+)\s.*?channel=(\d+)\s+game=\[([0-9,\s]+)\]")

#: `--now` reads this much of the log's tail to find the last announcement.
TAIL_TAKE_BYTES = 2 << 20

#: The channel exchange a client always performs, as `(request, reply, name,
#: request_body)`.  The requests are byte-identical in every session on record
#: (6/6 `(0,11)` lines in server-20260926/27.log, one distinct value for each
#: of the three), which is what makes replaying them a valid stand-in for the
#: client.  Reply opcodes are pinned too: a mismatch means the capture caught
#: something else and must not be served.
PROBE = (
    ((0, 11), (124, 12), "CONNECT_ACK",
     bytes.fromhex("f2f7f142f7dea0499f6bf6129fe6184fb76651875835f147e7940427c0d0aca3")),
    ((0, 9), (124, 10), "SCRIPT_ACK", b""),
    ((0, 1), (124, 3), "CHANNEL_ACK", b""),
)

#: Long enough for the reference's own 12ms-per-frame pacing, short enough that
#: a dead reference does not eat into the ~20s before the client arrives.
PROBE_TIMEOUT = 5.0


def parse_start(line: str) -> tuple[str, int, list[int]] | None:
    """`(host, channel_port, game_ports)` from a START line, else None."""
    m = START_RE.search(line)
    if not m:
        return None
    ports = [int(p) for p in m.group(3).split(",") if p.strip()]
    return m.group(1), int(m.group(2)), ports


def _taskkill() -> int:
    """Kill every reference server.  taskkill's rc 128 means none was running."""
    return subprocess.run(["taskkill", "/F", "/IM", EXE_NAME],
                          capture_output=True).returncode


def _port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True


class LogTail:
    """New lines of the newest `server-<date>.log`, following a midnight roll."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path: Path | None = None
        self.pos = 0
        self.buf = b""

    def _newest(self) -> Path | None:
        logs = sorted(self.directory.glob("server-*.log"))
        return logs[-1] if logs else None      # server-YYYYMMDD.log sorts by date

    def skip_to_end(self) -> Path | None:
        self.path = self._newest()
        if self.path is not None:
            self.pos = self.path.stat().st_size
        return self.path

    def poll(self) -> list[str]:
        newest = self._newest()
        if newest is None:
            return []
        if newest != self.path or newest.stat().st_size < self.pos:
            self.path, self.pos, self.buf = newest, 0, b""
        with open(newest, "rb") as fh:
            fh.seek(self.pos)
            data = fh.read()
        self.pos += len(data)
        self.buf += data
        *lines, self.buf = self.buf.split(b"\n")
        return [ln.decode("utf-8", "replace") for ln in lines]


def _op(main: int, sub: int) -> frame.Opcode:
    return frame.Opcode(main, sub, frame.OpcodeEncoding.U16BE, False)


def _plain(body: bytes, day: str) -> tuple[bytes, int]:
    """`(plaintext, reference-style plain size)` for one probed body.

    The two sealed bodies unseal under the day the exchange's CONNECT_ACK
    names; the padded length is what the rewrite reports -- the reference's own
    `plain=` is 1..15 bytes shorter and only its log has it.
    """
    if body[:1] == b"\x78":
        try:
            plain = channel.unseal(body, day)
            return plain, len(plain)
        except (zlib.error, ValueError):
            pass
    return body, len(body)


async def probe_replies(host: str, port: int, log: Log) -> channel.ChannelReplies | None:
    """Ask the live reference for the three bodies it would send the client.

    `None` (with a WARN) if it cannot be reached or answers with anything
    other than the expected three frames; the caller then has to choose
    between a stale directory and no takeover at all.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError) as e:
        log.warn("SWAP", f"probe: cannot reach {host}:{port}: {type(e).__name__}: {e}")
        return None
    got: list[frame.Frame] = []
    stream = frame.FrameStream(frame.Link.CHANNEL_S2C)
    try:
        for req, _reply, _name, body in PROBE:
            writer.write(frame.build(frame.Link.CHANNEL_C2S, _op(*req), body))
        await writer.drain()
        while len(got) < len(PROBE):
            chunk = await asyncio.wait_for(reader.read(65536), PROBE_TIMEOUT)
            if not chunk:
                break
            stream.feed(chunk)
            while (f := stream.next_frame()) is not None:
                got.append(f)
    except (OSError, asyncio.TimeoutError, frame.ProtocolError) as e:
        log.warn("SWAP", f"probe: {type(e).__name__}: {e}")
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    want = [reply for _req, reply, _name, _body in PROBE]
    if [f.opcode.key() for f in got] != want:
        log.warn("SWAP", f"probe: expected {want}, got "
                         f"{[f.opcode.key() for f in got]}")
        return None
    day = got[0].body[4:12].decode("ascii", "replace")   # CONNECT_ACK's token
    out: dict[int, channel.Reply] = {}
    for f, (req, _reply, name, _body) in zip(got, PROBE):
        key = int.from_bytes(_op(*req).to_bytes(), "big")
        plain, plain_len = _plain(f.body, day)
        out[key] = channel.Reply(request_raw=key, opcode=f.opcode, name=name,
                                 plain=plain, plain_len=plain_len,
                                 sealed=f.body[:1] == b"\x78")
    log.info("SWAP", f"probe: {host}:{port} handed over day={day} "
                     + ", ".join(f"{r.name} {len(r.plain)}B" for r in out.values()))
    return channel.ChannelReplies(out, source=f"live probe of {host}:{port}")


class Keeper:
    def __init__(self, args: argparse.Namespace, log: Log) -> None:
        self.host_override = args.host
        self.log = log
        self.replies = channel.ChannelReplies.load()
        self.script = game.GameScript.load()
        self.advertise = channelinfo.local_address()
        self.ids = ConnectionIds()
        self.write_gap = args.write_gap_ms / 1000
        self.game_write_gap = args.game_write_gap_ms / 1000
        self.serving: dict[int, tuple] = {}

    async def take(self, host: str, chan_port: int, game_ports: list[int]) -> None:
        if chan_port in self.serving:
            self.log.info("SWAP", f"channel={chan_port} is already ours; ignoring")
            return
        host = self.host_override or host
        # Before the kill, while the only thing that can mint this launch's
        # directory is still alive.
        captured = await probe_replies(host, chan_port, self.log)
        self.log.info("SWAP", f"reference announced bind={host} channel={chan_port} "
                              f"game={sorted(game_ports)}; killing {EXE_NAME}")
        rc = await asyncio.to_thread(_taskkill)
        self.log.info("SWAP", f"taskkill /F /IM {EXE_NAME} -> rc={rc}")
        for _ in range(50):
            if await asyncio.to_thread(_port_free, host, chan_port):
                break
            await asyncio.sleep(0.1)
        else:
            self.log.warn("SWAP", f"channel port {chan_port} never freed; binding anyway")
        replies = captured if captured is not None else self.replies
        if captured is None:
            self.log.warn("SWAP", "no fresh directory: serving "
                                  f"{self.replies.source or 'the checked-in replies'}; "
                                  "the client will take stale endpoints and stall")
        ports = game.remap_ports(game_ports)
        srv = channel.ChannelServer(host, chan_port, replies, self.log,
                                    ids=self.ids, write_gap=self.write_gap,
                                    advertise=self.advertise)
        gsrv = game.GameServer(host, ports, self.script, self.log, ids=self.ids,
                               write_gap=self.game_write_gap,
                               advertise_host=self.advertise)
        await srv.start()
        await gsrv.start()
        self.serving[chan_port] = (srv, gsrv)
        self.log.info("SWAP", f"rewrite listening: channel={chan_port} "
                              f"game={sorted(ports)} host={host}")
        print(f"[live-swap] took over channel={chan_port} "
              f"game={sorted(ports)} on {host}", flush=True)

    async def watch(self, tail: LogTail) -> None:
        while True:
            for line in tail.poll():
                hit = parse_start(line)
                if hit is None:
                    continue
                try:
                    await self.take(*hit)
                except Exception as e:      # a bad block must not disarm us
                    self.log.warn("SWAP", f"takeover failed: {type(e).__name__}: {e}")
            await asyncio.sleep(0.05)

    def close(self) -> None:
        for srv, gsrv in self.serving.values():
            gsrv.close()
            srv.close()


def _last_start(directory: Path) -> tuple[str, int, list[int]] | None:
    logs = sorted(directory.glob("server-*.log"))
    if not logs:
        return None
    path = logs[-1]
    with open(path, "rb") as fh:
        fh.seek(max(0, path.stat().st_size - TAIL_TAKE_BYTES))
        text = fh.read().decode("utf-8", "replace")
    hits = [hit for hit in (parse_start(ln) for ln in text.splitlines()) if hit]
    return hits[-1] if hits else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default=None,
                   help="bind address overriding the reference's announcement")
    p.add_argument("--now", action="store_true",
                   help="take over the block already in the log, then keep watching")
    p.add_argument("--log", default=None,
                   help="log file (default <repo>/Logs/server-rewrite.log)")
    p.add_argument("--write-gap-ms", type=float,
                   default=channel.WRITE_GAP_SECONDS * 1000)
    p.add_argument("--game-write-gap-ms", type=float,
                   default=game.WRITE_GAP_SECONDS * 1000)
    p.add_argument("--quiet", action="store_true")
    return p


async def _main(args: argparse.Namespace) -> None:
    log_path = Path(args.log) if args.log else paths.REPO_ROOT / "Logs" / "server-rewrite.log"
    log = Log(log_path, level="INFO" if args.quiet else "DEBUG")
    keeper = Keeper(args, log)
    tail = LogTail(paths.LOGS_DIR)
    attached = tail.skip_to_end()
    log.info("SWAP", f"armed; watching {attached} from EOF "
                     f"({tail.pos}B in); host={args.host or 'from the announcement'}")
    print(f"[live-swap] armed; watching {attached} from byte {tail.pos}", flush=True)
    if args.now:
        hit = _last_start(paths.LOGS_DIR)
        if hit is None:
            log.warn("SWAP", "--now given but the log holds no START line")
        else:
            log.info("SWAP", f"--now: taking over the last announced block {hit}")
            try:
                await keeper.take(*hit)
            except Exception as e:
                log.warn("SWAP", f"takeover failed: {type(e).__name__}: {e}")
    try:
        await keeper.watch(tail)
    finally:
        keeper.close()
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
