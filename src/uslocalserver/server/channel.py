"""The channel server (port 7001): the first link a client ever opens.

The whole exchange is three request/reply pairs, captured verbatim in
`data/channel/replies.json`:

    (0,11)  32B  ->  (124,12) CONNECT_ACK   36B plain
    (0,9)    0B  ->  (124,10) SCRIPT_ACK  1202B zlib -> 1392B
    (0,1)    0B  ->  (124,3)  CHANNEL_ACK  340B zlib ->  416B

The two compressed payloads are opaque: they survive zlib as high entropy, no
tile cipher at any offset opens them, they are not in the exe, and the
reference regenerates them (`plain=` stays 1384B/412B while the wire size moves
with the block, 351/352/353 and 1213).  Measured over every capture on 09-27
(8) plus one on 09-26:

* SCRIPT_ACK is byte-identical across all of one day's captures (8/8 on 09-27)
  and differs across days (1383/1392 bytes).
* CHANNEL_ACK depends on **the port block and the day**: the three captures
  sharing the default block (7001 + 10011-10021) on 09-27 are byte-identical,
  the five shifted blocks that day (60652, 62676, 53922, 57491, 49321) all
  differ (127-128/416 bytes), and the same default block on 09-26 differs in
  414/416 bytes.

So both bodies sit under a day-rotating key, and CHANNEL_ACK's plaintext
additionally carries this launch's endpoints -- replaying a same-day capture
from a *different* block is what made the early takeovers drop silently.
`replies.json` is therefore only valid for the block and day it came from;
`tools/live_swap.py` sidesteps this by asking the live reference for the fresh
bodies during takeover.  Regenerate the checked-in copy with
`tools/extract_channel_replies.py` (newest log) before offline replays.

CONNECT_ACK is the one body of the three that is not opaque, and its date is
generated rather than replayed.  See `_with_today`.

The channel link has no state machine: the reference logs every C->S packet as
`state=Connected->Connected`.

The one thing that must not be "optimised away" is the write gap.  Two S->C
frames arriving in the same `recv()` are discarded by the client: it parses
the stream and expects one packet per read.  The reference uses 12ms here and
documents the failure as "the client draws the server row but never gets an
endpoint".  This is a protocol requirement, not pacing -- and a bare
`asyncio.sleep(0.012)` does not satisfy it on Windows; `pacing.sleep_gap` is
the form that holds.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .. import paths
from ..protocol import frame
from .ids import ConnectionIds
from .logfile import Log
from .pacing import sleep_gap

CHANNEL_PORT = 7001
CHANNEL_STATE = "Connected"
WRITE_GAP_SECONDS = 0.012


@dataclass(frozen=True, slots=True)
class Reply:
    request_raw: int
    opcode: frame.Opcode
    name: str
    body: bytes
    plain_len: int

    @property
    def wire_size(self) -> int:
        return frame.header_len(frame.Link.CHANNEL_S2C) + len(self.body)


class ChannelReplies:
    """The captured replies, indexed by the C->S opcode that triggers each."""

    def __init__(self, replies: dict[int, Reply], *, source: str = "",
                 block: int | None = None) -> None:
        self._by_request = replies
        self.source = source
        self.block = block

    @classmethod
    def load(cls, path: Path | None = None) -> "ChannelReplies":
        p = path or (paths.DATA_DIR / "channel" / "replies.json")
        doc = json.loads(p.read_text(encoding="utf-8"))
        out: dict[int, Reply] = {}
        for rec in doc["frames"]:
            raw = int(rec["request_raw"], 16)
            out[raw] = Reply(
                request_raw=raw,
                opcode=frame.Opcode(rec["reply_main"], rec["reply_sub"],
                                    frame.OpcodeEncoding.U16BE, False),
                name=rec["name"],
                body=bytes.fromhex(rec["body_hex"]),
                plain_len=rec["plain_len"],
            )
        return cls(out, source=doc.get("source", ""), block=doc.get("block"))

    def match(self, opcode: frame.Opcode) -> Reply | None:
        return self._by_request.get(int.from_bytes(opcode.to_bytes(), "big"))

    def __iter__(self):
        return iter(self._by_request.values())

    def plain_size(self, name: str) -> int:
        for r in self._by_request.values():
            if r.name == name:
                return r.plain_len
        raise KeyError(name)


def block_warning(replies: ChannelReplies, port: int) -> str | None:
    """CHANNEL_ACK carries the endpoints of the block it was captured from.

    Replaying one from another block is not a wire error -- the client accepts
    all three ACKs and then resets without a word, which is why the mismatch is
    checked at startup and said out loud (measured 2026-09-27: a 57491-block
    body against a 7001-block server dropped the client right after CHANNEL_ACK).
    """
    if replies.block is None or replies.block == port:
        return None
    return (f"CHANNEL_ACK was captured from block {replies.block}, this server binds "
            f"{port} -- the client resets right after the third ACK; regenerate with "
            f"tools/extract_channel_replies.py --block {port}")


class ChannelServer:
    def __init__(self, host: str, port: int, replies: ChannelReplies, log: Log,
                 *, ids: ConnectionIds | None = None,
                 write_gap: float = WRITE_GAP_SECONDS,
                 today: str | None = None) -> None:
        self.host = host
        self.port = port
        self.replies = replies
        self.log = log
        self.ids = ids or ConnectionIds()
        self.write_gap = write_gap
        #: `YYYYMMDD` for CONNECT_ACK, or None to read the live clock per
        #: connection -- a server that runs past midnight must not keep
        #: yesterday's date.  Pinned by the tests, like the game server pins
        #: the CHANNELINFO timestamp.
        self.today = today
        self._server: asyncio.AbstractServer | None = None
        self._sessions: dict[str, int] = {}

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.log.info("LISTEN", f"channel bound on {self.host}:{self.port} "
                                f"spec=channel-c2s(header=11B, length@2:u32le)")

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    def close(self) -> None:
        if self._server is not None:
            self._server.close()

    @property
    def sockets(self):
        return [] if self._server is None else list(self._server.sockets or [])

    # ---------------------------------------------------------- connection

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        conn = self.ids.take()
        peer_ip, peer_port = writer.get_extra_info("peername")[:2]
        self._sessions[peer_ip] = self._sessions.get(peer_ip, 0) + 1
        self.log.info("CONNECT", f"conn={conn} channel:{self.port} peer={peer_ip}:{peer_port} "
                                 f"session={peer_ip} state={CHANNEL_STATE} "
                                 f"conns_on_session={self._sessions[peer_ip]}")
        self.log.debug("CHANNEL", f"conn={conn} awaiting client request; "
                                  f"script={self.replies.plain_size('SCRIPT_ACK')}B "
                                  f"directory={self.replies.plain_size('CHANNEL_ACK')}B")

        stream = frame.FrameStream(frame.Link.CHANNEL_C2S)
        loop = asyncio.get_running_loop()
        started = loop.time()
        rx = tx = frames = 0
        error: BaseException | None = None
        closed = False
        try:
            while not closed:
                data = await reader.read(65536)
                if not data:
                    break
                rx += len(data)
                stream.feed(data)
                while (f := stream.next_frame()) is not None:
                    frames += 1
                    self.log.packet(conn, frame.Link.CHANNEL_C2S, f.rebuild(),
                                    from_client=True,
                                    state=f"{CHANNEL_STATE}->{CHANNEL_STATE}")
                    reply = self.replies.match(f.opcode)
                    if reply is None:
                        self.log.warn("CHANNEL", f"conn={conn} unknown channel message "
                                                 f"({f.opcode.main},{f.opcode.sub}); no response")
                        continue
                    body = reply.body
                    if reply.name == "CONNECT_ACK":
                        body = _with_today(body, self.today or _today())
                    wire = frame.build(frame.Link.CHANNEL_S2C, reply.opcode, body)
                    await sleep_gap(self.write_gap)
                    writer.write(wire)
                    await writer.drain()
                    tx += len(wire)
                    self.log.packet(conn, frame.Link.CHANNEL_S2C, wire, from_client=False)
                    self.log.info("CHANNEL", f"conn={conn} sent {reply.name} wire={len(wire)}B")
        except (frame.ProtocolError, OSError) as e:
            error = e
        finally:
            if error is not None:
                self.log.info("DISCONNECT", f"conn={conn} socket error "
                                            f"{_error_name(error)}")
            elapsed = loop.time() - started
            self._sessions[peer_ip] -= 1
            self.log.info("DISCONNECT",
                          f"conn={conn} after {elapsed:.1f}s rx={rx}B tx={tx}B frames={frames} "
                          f"session={peer_ip} state={CHANNEL_STATE} "
                          f"conns_on_session={self._sessions[peer_ip]}")
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


def _today() -> str:
    return date.today().strftime("%Y%m%d")


def _with_today(body: bytes, today: str) -> bytes:
    """The CONNECT_ACK body with its date field replaced.

    The body is `u32le 0` + `YYYYMMDD` + `000008` + 18 zero bytes, captured as
    `20260926000008`.  Only those eight digits are live: the reference sent
    `20260926` on the capture's day and `20260927` when the same build was
    replayed the day after, so it reads `DateTime.Now` and not its own build
    stamp -- `INFO BUILD` says `built 2026-09-26 21:10:50` in both sessions.
    The `000008` tail is identical in both runs; semantics unknown, replayed.
    """
    return body[:4] + today.encode("ascii") + body[12:]


def _error_name(e: BaseException) -> str:
    if isinstance(e, ConnectionResetError):
        return "ConnectionReset"
    return type(e).__name__
