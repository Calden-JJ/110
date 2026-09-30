"""The channel server (port 7001): the first link a client ever opens.

The whole exchange is three request/reply pairs, and all three bodies are
reproducible offline -- the day key behind them is solved (2026-09-29):

    (0,11)  32B  ->  (124,12) CONNECT_ACK   36B plain, carries the day token
    (0,9)    0B  ->  (124,10) SCRIPT_ACK  1360B plain -> AES-128-ECB -> zlib
    (0,1)    0B  ->  (124,3)  CHANNEL_ACK  496B plain -> AES-128-ECB -> zlib

Both big bodies are `zlib(AES-128-ECB(zero-pad-to-16(content), key))` with
`key = ("yyyyMMdd" + "000008")` NUL-padded to 16 ASCII bytes -- the very token
CONNECT_ACK ships in the clear, so the client can derive the same key.  The
reference builds the seed at 0x58d420, slices `[..16]` at 0x58d660 and encrypts
at 0x58d680 (`CipherMode.ECB`, `PaddingMode.None`); the cipher is the tile
set's own stock AES-128 (`protocol.crypto`).

Their *content* does not rotate.  CHANNEL_ACK is generated from the config
alone -- u32le section count, then per section 16B server name + u32 0 + u32le
channel count, then 48B records of 16B `#ch.N`, u32 0, u32le maxUsersPerChannel,
u32 0, 16B advertiseAddress, u32le gamePort -- and SCRIPT_ACK is the
`[dungeon]`/`[server]` script the same channel list spells out.  Measured over
09-27..29: one config, one plaintext; only the key moved with the day.

`replies.json` therefore stores the plaintext (`plain_hex`, sized like the
reference's own `plain=`), the day it was captured on, and a SHA-256 of that
capture's inflated ciphertext so the checked-in copy stays verifiable.  Sends
re-key it against the live clock: no per-day re-sampling.  Regenerate with
`tools/extract_channel_replies.py` only when the channel config moves.

CHANNEL_ACK's content still carries the endpoints of the block it came from, so
a copy captured on another block is refused silently by the client -- that is
what `block_warning` is for, and why `tools/live_swap.py` probes the running
reference instead of reading the file.  The address half of "endpoints" no
longer bites: the directory's advertiseAddress is re-stamped at send time
(`with_advertise`); the ports are the half that still pins a body to its block.

CONNECT_ACK's date is the one field read from the clock; see `_with_today`.

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
import zlib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .. import paths
from ..protocol import frame
from ..protocol.crypto import aes128_decrypt, aes128_encrypt, ecb_decrypt, ecb_encrypt
from .ids import ConnectionIds
from .logfile import Log
from .pacing import sleep_gap

CHANNEL_PORT = 7001
CHANNEL_STATE = "Connected"
WRITE_GAP_SECONDS = 0.012

#: CONNECT_ACK's token is `yyyyMMdd` + this suffix; the two big bodies are keyed
#: with the first 16 bytes of the same string.  In the exe: 0x58d420 appends the
#: suffix, 0x58d660 takes `[..16]`, 0x58d680 encrypts with it.
SEED_SUFFIX = "000008"
KEY_BYTES = 16

#: One channel record of CHANNEL_ACK's directory: 16B `#ch.N`, u32 0, u32le
#: maxUsersPerChannel, u32 0, 16B advertiseAddress, u32le gamePort.
RECORD_SIZE = 48
ADVERTISE_OFFSET = 28
ADVERTISE_LEN = 16
CHANNEL_NAME = "#ch."


def day_key(day: str) -> bytes:
    """The day's AES-128 key and CONNECT_ACK's token: `yyyyMMdd` + `000008`.

    The reference formats the date into a 32-byte scratch string, appends the
    suffix and hands the first 16 bytes to the cipher as a key, so the key is
    `b"20260929000008\\0\\0"` -- ASCII, not UTF-16.  Checked against captures
    from 09-27, 09-28 and 09-29: each day's own key turns that day's two
    bodies back into printable content.
    """
    return (day + SEED_SUFFIX).ljust(KEY_BYTES, "\0").encode("ascii")


def seal(content: bytes, day: str) -> bytes:
    """The wire body: zero-pad to 16, AES-128-ECB, zlib.

    The cipher is the 14-tile set's own `AES-128` (`protocol.crypto`), which is
    stock FIPS-197 -- checked against the captures, not just against itself.
    """
    key = day_key(day)
    return zlib.compress(ecb_encrypt(aes128_encrypt,
                                     content + b"\0" * (-len(content) % 16), key, 16))


def unseal(body: bytes, day: str) -> bytes:
    """`seal` backwards; the zero padding stays on, so `seal` round-trips."""
    return ecb_decrypt(aes128_decrypt, zlib.decompress(body), day_key(day), 16)


def with_advertise(directory: bytes, host: str) -> bytes:
    """CHANNEL_ACK's directory with every advertiseAddress set to `host`.

    The capture names the address the reference answered on -- 192.168.1.6 on
    09-27, 192.168.2.226 on 09-29, a DHCP move between the two -- and the
    client dials the directory's address, not the one it opened the channel
    on (that is why a stale block's body is refused after the third ACK).  A
    shipped body therefore has to be re-addressed at send time, the same way
    its date is re-keyed; `run.py` passes the address its game server
    advertises in CHANNELINFO.

    Returns `directory` unchanged unless the walk lands exactly on its end
    with every record named `#ch.` -- a stale address is recoverable, a
    mangled directory is not.
    """
    out = bytearray(directory)
    sections = int.from_bytes(out[:4], "little")
    if not 1 <= sections <= 64:
        return directory
    name = CHANNEL_NAME.encode()
    off = 4
    for _ in range(sections):
        off += 16                                        # section name
        off += 4                                         # u32 0
        channels = int.from_bytes(out[off:off + 4], "little")
        off += 4
        for _ in range(channels):
            if out[off:off + len(name)] != name:
                return directory
            out[off + ADVERTISE_OFFSET:off + ADVERTISE_OFFSET + ADVERTISE_LEN] = (
                host.encode()[:ADVERTISE_LEN].ljust(ADVERTISE_LEN, b"\0"))
            off += RECORD_SIZE
    # only the pad-to-16 tail may remain: a walk that overshoots a truncated
    # body must not be mistaken for one that ended early
    if not 0 <= len(directory) - off < 16 or directory[off:].strip(b"\0"):
        return directory
    return bytes(out)


@dataclass(frozen=True, slots=True)
class Reply:
    request_raw: int
    opcode: frame.Opcode
    name: str
    plain: bytes
    plain_len: int
    sealed: bool = False


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
                plain=bytes.fromhex(rec["plain_hex"]),
                plain_len=rec["plain_len"],
                sealed=rec["sealed"],
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
                 today: str | None = None,
                 advertise: str | None = None) -> None:
        self.host = host
        self.port = port
        self.replies = replies
        self.log = log
        self.ids = ids or ConnectionIds()
        self.write_gap = write_gap
        #: Address stamped into CHANNEL_ACK's directory, or None to replay the
        #: capture's own.  The launcher passes the one `run.py` advertises in
        #: CHANNELINFO, so both links name the same host.
        self.advertise = advertise
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
                    day = self.today or _today()
                    # the day is also the key, so a server that runs past midnight
                    # re-keys on the next connection -- as it must, the token and
                    # the key have to agree or the client decrypts garbage.
                    if reply.sealed:
                        plain = reply.plain
                        if self.advertise and reply.name == "CHANNEL_ACK":
                            plain = with_advertise(plain, self.advertise)
                        body = seal(plain, day)
                    elif reply.name == "CONNECT_ACK":
                        body = _with_today(reply.plain, day)
                    else:
                        body = reply.plain
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
    The `000008` tail is `SEED_SUFFIX`: the token it completes is the seed the
    client derives the other two bodies' key from.
    """
    return body[:4] + today.encode("ascii") + body[12:]


def _error_name(e: BaseException) -> str:
    if isinstance(e, ConnectionResetError):
        return "ConnectionReset"
    return type(e).__name__
