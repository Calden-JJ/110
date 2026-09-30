#!/usr/bin/env python3
"""Live relay: captures a real session by sitting in its path.

The team's 0.4.4 server ships with diagnostics compiled out -- its logs hold
no packet dumps -- so a live session can only be read by relaying it.  The
client learns its game-server address from the server's own config
(`advertiseAddress`, which the channel directory re-stamps), so
`--edit-advertise 127.0.0.3` points the client at this relay (config backed
up to `server.json.bak-before-relay`) and every byte is forwarded verbatim to
the real server while both directions are framed with the rewrite's codec.

    capture_start.cmd        edit config + listen  (Ctrl-C stops)
    restart the 0.4.4 server, play through it
    capture_stop.cmd         put the config back, restart the server again

Writes, per connection, under `Logs-capture/<stamp>/`:

    conn<N>.log       readable frames; game bodies decrypted via tiles
    conn<N>.raw.hex   every frame's exact wire bytes

The first game-s2c frame is `(0,1)` CHANNELINFO: decoded here, checked
against the static key blob, and -- if the live server ships a different
blob -- used to re-key `tiles` for the rest of the capture.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from uslocalserver.protocol import channelinfo, frame
from uslocalserver.protocol.crypto import KEY_BLOB
from uslocalserver.protocol.crypto import tiles

DEFAULT_CONFIG = Path(r"E:\DFO_2.31.1.117\DFO110-0.4.4\Server\server.json")
BAK_SUFFIX = ".bak-before-relay"
MAX_FRAME = 4 << 20
DISPLAY_CAP = 4096  # bytes of plain/raw hex shown per frame in conn<N>.log


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _load_ports(config: Path) -> tuple[int, list[int], str]:
    cfg = json.loads(config.read_text(encoding="utf-8"))
    game = []
    for server in cfg.get("channelServers", ()):
        for ch in server.get("channels", ()):
            game.append(int(ch["gamePort"]))
    return int(cfg["channelPort"]), sorted(set(game)), str(cfg.get("bindAddress", "127.0.0.2"))


# -- config editing ----------------------------------------------------------

def edit_advertise(config: Path, address: str) -> None:
    raw = config.read_text(encoding="utf-8")
    cfg = json.loads(raw)
    old = cfg.get("advertiseAddress")
    if old == address:
        print(f"[cfg] advertiseAddress already {address}")
        return
    bak = config.with_name(config.name + BAK_SUFFIX)
    if not bak.exists():
        shutil.copy2(config, bak)
        print(f"[cfg] backup -> {bak.name}")
    else:
        print(f"[cfg] backup already exists ({bak.name}), keeping it")
    cfg["advertiseAddress"] = address
    config.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[cfg] advertiseAddress {old} -> {address}; restart the 0.4.4 server for it to take")


def restore_config(config: Path) -> None:
    bak = config.with_name(config.name + BAK_SUFFIX)
    if not bak.exists():
        print(f"[cfg] no backup at {bak.name}; nothing to restore")
        return
    shutil.copy2(bak, config)
    bak.unlink()
    print("[cfg] restored; restart the 0.4.4 server for it to take")


# -- framing tap -------------------------------------------------------------

class Tap:
    """One direction's incremental framer with gap resync."""

    def __init__(self, link: frame.Link, sink, gap_sink) -> None:
        self.link = link
        self.sink = sink
        self.gap_sink = gap_sink
        self.buf = bytearray()
        self.gap = 0

    def feed(self, data: bytes) -> None:
        self.buf += data
        self._drain()

    def _drain(self) -> None:
        while True:
            size = frame.declared_size(self.link, self.buf)
            if size is None:
                return
            if not (frame.header_len(self.link) <= size <= MAX_FRAME):
                self._drop(1)
                continue
            if len(self.buf) < size:
                return
            chunk = bytes(self.buf[:size])
            mark = ""
            try:
                parsed = frame.parse(self.link, chunk, strict=True)
            except frame.ProtocolError:
                try:
                    parsed = frame.parse(self.link, chunk, strict=False)
                    mark = "~"
                except frame.ProtocolError:
                    self._drop(1)
                    continue
            del self.buf[:size]
            self._flush_gap()
            self.sink(parsed, chunk, mark)

    def _drop(self, n: int) -> None:
        self.gap += n
        del self.buf[:n]

    def _flush_gap(self) -> None:
        if self.gap:
            self.gap_sink(self.gap)
            self.gap = 0


# -- one connection ----------------------------------------------------------

def _varint(data: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        b = data[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i
        shift += 7


class Connection:
    def __init__(self, cid: int, port: int, peer, out_dir: Path) -> None:
        self.cid = cid
        self.port = port
        self.peer = peer
        self.log = (out_dir / f"conn{cid}.log").open("w", encoding="utf-8")
        self.raw = (out_dir / f"conn{cid}.raw.hex").open("w", encoding="utf-8")
        self.frames = 0
        self.bytes = 0
        self._line(f"=== conn{cid} port={port} peer={peer} at {datetime.now():%H:%M:%S}")

    def _line(self, text: str) -> None:
        self.log.write(text + "\n")
        self.log.flush()

    def touch(self, n: int) -> None:
        self.bytes += n

    def frame_line(self, direction: str, parsed, chunk: bytes, mark: str, plain: bytes | None) -> None:
        self.frames += 1
        ts = f"{datetime.now():%H:%M:%S.%f}"[:-3]
        body = len(parsed.body)
        head = f"{ts} {direction} {parsed.opcode} wire={len(chunk)} body={body}{mark}"
        if plain is not None:
            shown = plain[:DISPLAY_CAP].hex()
            extra = f"(+{len(plain) - DISPLAY_CAP}B)" if len(plain) > DISPLAY_CAP else ""
            self._line(f"{head} plain={shown}{extra}")
        else:
            shown = parsed.body[:DISPLAY_CAP].hex()
            extra = f"(+{body - DISPLAY_CAP}B)" if body > DISPLAY_CAP else ""
            self._line(f"{head} bodyhex={shown}{extra}")
        self.raw.write(f"{ts} {direction} {chunk.hex()}\n")
        self.raw.flush()

    def gap_line(self, direction: str, n: int) -> None:
        self._line(f"{datetime.now():%H:%M:%S.%f}"[:-3] + f" {direction} GAP {n}B dropped (resync)")

    def note(self, text: str) -> None:
        self._line(text)

    def close(self, rx: int, tx: int) -> None:
        self._line(f"=== conn{self.cid} closed after {time.monotonic() - self.t0:.1f}s "
                   f"frames={self.frames} relayed={rx}+{tx}B")
        self.log.close()
        self.raw.close()

    t0 = 0.0


class _Blob:
    """A captured key blob in place of the static Path."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read_bytes(self) -> bytes:
        return self._data


def _chaninfo_fields(plain: bytes) -> dict:
    i, out = 4, {}
    while i < len(plain):
        key, i = _varint(plain, i)
        field, wire = key >> 3, key & 7
        if wire == 2:
            ln, i = _varint(plain, i)
            out[field] = plain[i:i + ln]
            i += ln
        elif wire == 0:
            value, i = _varint(plain, i)
            out[field] = value
        else:
            break
    return out


def make_sink(conn: Connection, direction: str, link: frame.Link):
    static_blob = KEY_BLOB.read_bytes()

    def sink(parsed, chunk: bytes, mark: str) -> None:
        plain = None
        if parsed.opcode.sub == 1 and parsed.opcode.main == 0 and direction == "S2C" \
                and link is frame.Link.GAME_S2C:
            plain = channelinfo.decode(parsed.body)
            fields = _chaninfo_fields(plain)
            blob = fields.get(3, b"")
            host = fields.get(12, b"").split(b"\x00", 1)[0].decode("ascii", "replace")
            conn.note(f"  (0,1) CHANNELINFO server={fields.get(7)} channel={fields.get(8)} "
                      f"host={host!r} unix={fields.get(11)} blob={len(blob)}B "
                      f"{'== static' if blob == static_blob else 'DIFFERS -> re-keyed'}")
            if blob and blob != static_blob:
                tiles.KEY_BLOB = _Blob(blob)
        elif link in (frame.Link.GAME_C2S, frame.Link.GAME_S2C):
            plain = tiles.decrypt_body(parsed.opcode.sub % 14, parsed.body)
        conn.frame_line(direction, parsed, chunk, mark, plain)

    return sink


async def pump(reader, writer, tap: Tap, conn: Connection, direction: str, counter: list) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            tap.feed(data)
            counter[0] += len(data)
    except (ConnectionResetError, ConnectionAbortedError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


class Relay:
    def __init__(self, target: str, out_dir: Path) -> None:
        self.target = target
        self.out_dir = out_dir
        self.cid = 0

    async def handle(self, reader, writer, port: int, is_channel: bool) -> None:
        self.cid += 1
        conn = Connection(self.cid, port, writer.get_extra_info("peername"), self.out_dir)
        conn.t0 = time.monotonic()
        try:
            t_reader, t_writer = await asyncio.open_connection(self.target, port)
        except OSError as exc:
            conn.note(f"!!! cannot reach {self.target}:{port}: {exc}")
            writer.close()
            return
        rx, tx = [0], [0]
        up = Tap(frame.Link.CHANNEL_C2S if is_channel else frame.Link.GAME_C2S,
                 make_sink(conn, "C2S", frame.Link.CHANNEL_C2S if is_channel else frame.Link.GAME_C2S),
                 lambda n: conn.gap_line("C2S", n))
        down = Tap(frame.Link.CHANNEL_S2C if is_channel else frame.Link.GAME_S2C,
                   make_sink(conn, "S2C", frame.Link.CHANNEL_S2C if is_channel else frame.Link.GAME_S2C),
                   lambda n: conn.gap_line("S2C", n))
        await asyncio.gather(
            pump(reader, t_writer, up, conn, "C2S", rx),
            pump(t_reader, writer, down, conn, "S2C", tx),
        )
        conn.close(rx[0], tx[0])
        print(f"[conn{conn.cid}] port={port} closed: {conn.frames} frames, relayed {rx[0]}+{tx[0]}B")

    async def serve(self, listen: str, port: int, is_channel: bool) -> None:
        server = await asyncio.start_server(
            lambda r, w: self.handle(r, w, port, is_channel), listen, port)
        kind = "channel" if is_channel else "game"
        print(f"[listen] {listen}:{port} ({kind}) -> {self.target}:{port}")
        return server


async def run(args) -> None:
    channel_port, game_ports, bind = _load_ports(args.config)
    target = args.target or bind
    if args.edit_advertise:
        edit_advertise(args.config, args.edit_advertise)
    listen = args.listen or args.edit_advertise or "127.0.0.3"
    out_dir = Path(args.out) / _stamp()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[out] {out_dir}")

    relay = Relay(target, out_dir)
    servers = []
    for port, is_channel in [(channel_port, True)] + [(p, False) for p in game_ports]:
        try:
            servers.append(await relay.serve(listen, port, is_channel))
        except OSError as exc:
            print(f"[listen] {listen}:{port} FAILED: {exc}")
            print("         (port taken on this address -- is another server running?)")
    print("\n准备好了：重启 0.4.4 服务端，然后像平时一样进游戏（打怪掉物、捡一件、可选 boss）。")
    print("抓取完成后按 Ctrl-C；然后运行 capture_stop.cmd 恢复配置，再重启服务端。\n")
    try:
        await asyncio.Event().wait()
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(s.wait_closed() for s in servers), return_exceptions=True)
        print(f"[done] captures in {out_dir}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--listen", default=None, help="address to listen on (default: --edit-advertise value)")
    parser.add_argument("--target", default=None, help="address the real server is on (default: bindAddress)")
    parser.add_argument("--out", default=str(ROOT / "Logs-capture"))
    parser.add_argument("--edit-advertise", default=None, metavar="ADDR",
                        help="back up the config and set advertiseAddress to ADDR")
    parser.add_argument("--restore-config", action="store_true", help="put the config back and exit")
    args = parser.parse_args()
    if args.restore_config:
        restore_config(args.config)
        return 0
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[stop] capture ended")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
