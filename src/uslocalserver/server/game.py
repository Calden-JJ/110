"""The game server (ports 10011-10021): the link the client lives on.

Where the channel link is three request/reply pairs, this one is a state
machine with a captured script behind each C->S opcode:

    Connected  --(1,1554)-->  Handshaken     handshake probe
    Handshaken --(1,1)-->     Authenticated  login, 2 frames
    Authenticated --(1,8)-->  RosterReady    role list, 1792B
    RosterReady --(1,4)-->    CharacterSelected
    CharacterSelected --(1,143)--> InTown    33 frames, 42464B -- the town entry
    InTown     --(1,848) / (1,433) / (1,637) / (1,36) / (1,140) / ... keep it

Every transition above is read off the capture's `DEBUG DISPATCH` lines, not
guessed.  `(1,2126)` is the loud exception: sent 162 times in one session and
answered never, which is why the capture's UNHANDLED list is dominated by it.

Bodies come out of `data/game/replies.json` *decrypted*, so this module has to
put them back on the wire itself:

    body = tiles.encrypt_body(sub % 14, reply.plain)
    wire = frame.build_s2c(opcode, body, nonce=reply.nonce)

That is deliberate.  The channel server replays opaque bytes because its two
zlib payloads really are opaque; here the cipher is understood, so a broken
tile or a wrong header field has to show up as a mismatch rather than hide
behind a stored blob.

The `(0,1)` CHANNELINFO that greets every connection is generated instead of
replayed -- see `protocol.channelinfo` -- for the same reason and one more:
its field 11 is a unix timestamp, and a replayed one would be a day stale.

The 5 ms write gap is a protocol requirement, not pacing.  `server.reference.json`
records the failure mode: two S->C frames landing in one client `recv()` are
discarded, and the client's trace formatter over-runs its state machine --
which is what the `(1,217)` overrun reports trace back to.  It is enforced
with `pacing.sleep_gap`; a bare `asyncio.sleep` fires early on Windows.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from .. import paths
from ..game.item import inventory, refresh
from ..game.town import movement
from ..persistence import accounts, characters, schema
from ..protocol import channelinfo, frame
from ..protocol.crypto import tiles
from .ids import ConnectionIds
from .logfile import Log
from .pacing import sleep_gap

#: `port -> (db_server, protocol_server, channel_no, channel_name)`.
#:
#: The endpoint half is the save database's `channels` table, which is where
#: the reference looks it up too -- its schema comment says the port-to-channel
#: reverse lookup "is the hot path on game accept: once the client is connected
#: to some game port the server must immediately resolve server_no/channel_no
#: from here to build the first packet".  `server.reference.json` is *not* the
#: topology: it lists ch10 on 10013 and ch84/91/82, but not ch81 on 10018 or
#: ch83 on 10017, both of which the save has and the capture routed to, and
#: its siroco block (10014-10016) is bound by nobody -- the reference's own
#: startup log has exactly these eight `game bound on` lines.  Only the
#: `db_server -> protocol server` renaming comes from that file: db_server 0
#: is "cain" and answers as protocol server 1.
#:
#: `channel_name` is display prose for the ROUTE log line only -- `channels`
#: stores `#ch.N` and the reference's names are not recoverable from any
#: config, so the two the capture exercised are recorded and the rest fall
#: back to `#ch.N`, which is what the wire uses anyway.
GAME_PORTS: dict[int, tuple[int, int, int, str | None]] = {
    10011: (0, 1, 1, None),
    10012: (0, 1, 6, None),
    10013: (0, 1, 10, "Bel Myre"),
    10017: (0, 1, 83, None),
    10018: (0, 1, 81, "Ispins, The Usurped Lands"),
    10019: (0, 1, 84, None),
    10020: (0, 1, 91, None),
    10021: (0, 1, 82, None),
}


def remap_ports(new_ports) -> dict[int, tuple[int, int, int, str | None]]:
    """`GAME_PORTS` on a different block, order preserved.

    The launcher shifts the whole block when the defaults are busy -- measured
    2026-09-27: 10011-10021 -> 49322-49329 -- and `ROUTE ... game port 49324 ->
    channel=10 (Bel Myre)` proves the Nth port keeps the Nth channel, so a
    positional remap is the whole mapping.
    """
    if len(new_ports) != len(GAME_PORTS):
        raise ValueError(f"expected {len(GAME_PORTS)} ports, got {len(new_ports)}")
    return {new: GAME_PORTS[old]
            for new, old in zip(sorted(new_ports), sorted(GAME_PORTS))}

#: Reported to the client inside the `(1,1)` LOGIN_OK body; the server does not
#: listen on it.  Measured on the capture's 56B body: the advertised host sits
#: at `[13:24]` behind a one-byte length, and this value is the u32le at both
#: `[24]` and `[28]`.  The body itself is replayed, so the constant is not what
#: puts it on the wire -- it records the dependency and feeds the startup line.
LOGIN_OK_PORT = 7200

WRITE_GAP_SECONDS = 0.005
INITIAL_STATE = "Connected"
CHANNELINFO_OPCODE = frame.Opcode(0, 1, frame.OpcodeEncoding.U8_U16LE, True)

#: `WARN UNHANDLED ... has no handler plain=` dumps at most this many bytes,
#: then `...(+NNB)`.  Measured: no note in the capture ever prints more.
PLAIN_DUMP_LIMIT = 96

#: Tags whose lines are statements about the *session* rather than about a
#: response, and which this server therefore writes itself.  `_handle`'s
#: `finally` measures its own lifetime and counters, so replaying the capture's
#: `DISCONNECT after 438.4s rx=68793B tx=47679B` -- which the `(1,3)` run's
#: note list carries, because `(1,3)` is the last request before teardown --
#: would report someone else's numbers as ours, and the `GAME ... state
#: released` summary likewise describes a session that has not ended yet.
#: `STUN` is unreplayable for the older reason: no STUN listener here, so
#: nothing was ever dropped.  Everything else in the script is a statement
#: about a response this server really did build.
UNREPLAYABLE_TAGS = frozenset({"STUN", "DISCONNECT", "GAME"})


@dataclass(frozen=True, slots=True)
class Reply:
    main: int
    sub: int
    transform: str                     # "tileN" | "rol8xor"
    plain: bytes | None                # None when generated rather than replayed
    nonce: bytes
    truncated: bool
    missing: int

    @property
    def opcode(self) -> frame.Opcode:
        return frame.Opcode(self.main, self.sub, frame.OpcodeEncoding.U8_U16LE, True)


@dataclass(frozen=True, slots=True)
class Run:
    """What one C->S frame drew: prose, then frames, then the state it left."""
    state: tuple[str, str] | None
    notes: tuple[tuple[str, str, str], ...]         # (level, tag, template)
    replies: tuple[Reply, ...]


@dataclass(frozen=True, slots=True)
class Script:
    main: int
    sub: int
    runs: tuple[Run, ...]

    def run(self, nth: int) -> Run:
        """The `nth` time this opcode was sent.  Repeats the last run rather
        than running dry: `(1,2126)` is answered never but sent 162 times in
        the capture, and a client that sends it a 163rd time still expects the
        same silence."""
        return self.runs[min(nth, len(self.runs) - 1)]


class GameScript:
    """The captured reply script, indexed by the C->S opcode that triggers it."""

    def __init__(self, scripts: dict[tuple[int, int], Script], *,
                 connect: tuple[Reply, ...] = (), source: str = "") -> None:
        self._by_request = scripts
        self.connect = connect
        self.source = source

    @classmethod
    def load(cls, path: Path | None = None) -> "GameScript":
        p = path or (paths.DATA_DIR / "game" / "replies.json")
        doc = json.loads(p.read_text(encoding="utf-8"))
        out: dict[tuple[int, int], Script] = {}
        for rec in doc["scripts"]:
            key = (rec["request_main"], rec["request_sub"])
            out[key] = Script(key[0], key[1], tuple(
                Run(state=tuple(r["state"]) if r["state"] else None,
                    notes=tuple((n[0], n[1], n[2]) for n in r["notes"]),
                    replies=tuple(_reply(f) for f in r["replies"]))
                for r in rec["runs"]))
        return cls(out, connect=tuple(_reply(f) for f in doc.get("connect_frames", ())),
                   source=doc.get("source", ""))

    def match(self, main: int, sub: int) -> Script | None:
        return self._by_request.get((main, sub))

    def __len__(self) -> int:
        return len(self._by_request)

    @property
    def reply_count(self) -> int:
        return sum(len(r.replies) for s in self._by_request.values() for r in s.runs)

    def unanswered(self) -> list[tuple[int, int]]:
        return sorted(k for k, s in self._by_request.items()
                      if not any(r.replies for r in s.runs))


def _reply(f: dict) -> Reply:
    # `plain_hex` is null only for the generated (rol8xor) frame.  An empty
    # body -- and the capture has one, `(0,124)` -- is `""`, which is falsy:
    # testing truthiness here would send the CHANNELINFO twice instead.
    plain = None if f["plain_hex"] is None else bytes.fromhex(f["plain_hex"])
    if plain is None and f["transform"] != "rol8xor":
        raise ValueError(f"({f['main']},{f['sub']}) is {f['transform']} but has no body")
    if plain is not None and f["transform"] == "rol8xor":
        raise ValueError(f"({f['main']},{f['sub']}) is generated but carries a body")
    return Reply(main=f["main"], sub=f["sub"], transform=f["transform"], plain=plain,
                 nonce=bytes.fromhex(f["nonce"]),
                 truncated=f["truncated"], missing=f["missing_bytes"])


def _dump_plain(plain: bytes) -> str:
    """The reference's `plain=` shape: 96 bytes then `...(+NNB)`."""
    if len(plain) <= PLAIN_DUMP_LIMIT:
        return plain.hex()
    return f"{plain[:PLAIN_DUMP_LIMIT].hex()}...(+{len(plain) - PLAIN_DUMP_LIMIT}B)"


class GameServer:
    def __init__(self, host: str, ports: dict[int, tuple[int, int, int, str | None]],
                 script: GameScript, log: Log, *, ids: ConnectionIds | None = None,
                 write_gap: float = WRITE_GAP_SECONDS,
                 advertise_host: str | None = None,
                 unix_seconds: int | None = None,
                 save_db: Path | str | None = None) -> None:
        self.host = host
        self.ports = ports
        self.script = script
        self.log = log
        self.ids = ids or ConnectionIds()
        self.write_gap = write_gap
        self.advertise_host = advertise_host or channelinfo.local_address()
        # Field 11 of the CHANNELINFO is the only input the server picks for
        # itself; pinning it is what lets a replay be compared against the
        # capture byte for byte instead of up to a second of clock skew.
        self.unix_seconds = unix_seconds
        # The save is opened at `start()`, not here: a server that cannot read
        # its save should fail before it binds a port.  Left out entirely, the
        # write handlers stay off and every opcode is answered by the replay
        # script, which is what M1 was.
        self.save_db = Path(save_db) if save_db is not None else None
        self._db: sqlite3.Connection | None = None
        self._account: int | None = None
        self._servers: dict[int, asyncio.AbstractServer] = {}
        self._sessions: dict[str, int] = {}

    async def start(self) -> None:
        if self.save_db is not None:
            self._db = schema.connect(self.save_db)
            self._account = accounts.sole_account(self._db)
        for port in sorted(self.ports):
            self._servers[port] = await asyncio.start_server(
                self._handle_for(port), self.host, port)
            self.log.info("LISTEN", f"game bound on {self.host}:{port} "
                                    f"spec=game-c2s(header=13B, length@3:u32le)")

    async def serve_forever(self) -> None:
        if not self._servers:
            await self.start()
        async with asyncio.TaskGroup() as tg:
            for srv in self._servers.values():
                tg.create_task(srv.serve_forever())

    def close(self) -> None:
        for srv in self._servers.values():
            srv.close()

    @property
    def sockets(self):
        return [s for srv in self._servers.values() for s in (srv.sockets or ())]

    def ports_bound(self) -> list[int]:
        return sorted(s.getsockname()[1] for s in self.sockets)

    # ---------------------------------------------------------- connection

    def _handle_for(self, port: int):
        async def handler(reader, writer):
            await self._handle(reader, writer, port)
        return handler

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter, port: int) -> None:
        db_server, server, channel, name = self.ports[port]
        conn = self.ids.take()
        peer_ip, peer_port = writer.get_extra_info("peername")[:2]
        self._sessions[peer_ip] = self._sessions.get(peer_ip, 0) + 1
        self.log.info("CONNECT", f"conn={conn} game:{port} peer={peer_ip}:{peer_port} "
                                 f"session={peer_ip} state={INITIAL_STATE} "
                                 f"conns_on_session={self._sessions[peer_ip]}")
        self.log.info("ROUTE", f"conn={conn} game port {port} -> db_server={db_server} "
                               f"server={server} channel={channel} "
                               f"({name or f'#ch.{channel}'})")

        stream = frame.FrameStream(frame.Link.GAME_C2S)
        loop = asyncio.get_running_loop()
        started = loop.time()
        rx = tx = frames = 0
        state = INITIAL_STATE
        character: int | None = None
        town: movement.TownSession | None = None
        cursors: dict[tuple[int, int], int] = {}
        error: BaseException | None = None
        closed = False
        try:
            await self._send_channelinfo(writer, conn, server, channel)
            while not closed:
                data = await reader.read(65536)
                if not data:
                    break
                rx += len(data)
                stream.feed(data)
                while (f := stream.next_frame()) is not None:
                    frames += 1
                    key = (f.opcode.main, f.opcode.sub)
                    self.log.packet(conn, frame.Link.GAME_C2S, f.rebuild(),
                                    from_client=True, state=f"{state}->{state}")
                    if key == (1, 4):
                        # The character this session belongs to, for every
                        # handler that writes.  `(1,4)`'s request body is 16
                        # zero bytes in the capture: a selection slot, not an id.
                        character = self._select_character(
                            tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body))
                        town = self._town_session(character)
                    if key == inventory.OPCODE.key() and character is not None:
                        tx += await self._item_move(writer, conn, f.body, character, state)
                        continue
                    if town is not None:
                        if key == movement.MOVE_OPCODE.key():
                            await self._town_move(conn, f.body, town)
                            continue
                        if key == movement.AREA_OPCODE.key():
                            tx += await self._town_area(writer, conn, f.body, town, state)
                            continue
                    script = self.script.match(*key)
                    if script is None:
                        self.log.warn("GAME", f"conn={conn} no script for {f.opcode}; "
                                              f"no response")
                        continue
                    nth = cursors.get(key, 0)
                    cursors[key] = nth + 1
                    run = script.run(nth)
                    if key == movement.ENTRY_OPCODE.key() and character is not None:
                        run = self._town_entry(run, character)
                    self._log_notes(conn, f, run)
                    sent = nbytes = 0
                    for reply in run.replies:
                        wire = self._encode(reply)
                        await sleep_gap(self.write_gap)
                        writer.write(wire)
                        await writer.drain()
                        sent += 1
                        nbytes += len(wire)
                        tx += len(wire)
                        self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
                    if run.state:
                        state = run.state[1]
                        self.log.debug("DISPATCH", f"conn={conn} {f.opcode} -> "
                                                   f"{sent} frame(s) {nbytes}B "
                                                   f"state={run.state[0]}->{run.state[1]}")
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
                          f"session={peer_ip} state={state} "
                          f"conns_on_session={self._sessions[peer_ip]}")
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    # ------------------------------------------------------------ handlers

    def _select_character(self, plain: bytes) -> int | None:
        """The slot comes first in the decrypted body; the ciphertext's first
        byte is *not* it (that misread picks slot 28 and strands the session)."""
        if self._db is None or self._account is None:
            return None
        slot_index = plain[0] if plain else 0
        summary = characters.at_slot(self._db, self._account, slot_index)
        if summary is None:
            self.log.warn("SELECTION-4", f"no character in slot {slot_index}")
            return None
        return summary.character_id

    def _town_entry(self, run: Run, character: int) -> Run:
        """The `(1,143)` run with its three row-built frames regenerated.

        The capture's copies carry the coordinates of the session that was
        captured; the reference reads the row as it enters, which is what makes
        a character that walked first spawn where it walked to.  Everything
        else in the 33-frame burst is replayed as captured.
        """
        summary = characters.by_id(self._db, character)
        location = movement.Location.of(summary)
        pair = movement.area_pair(location.town, location.area, location.x,
                                  location.y, location.direction)
        built = {movement.ENTRY_PAIR_AT: pair[0],
                 movement.ENTRY_PAIR_AT + 1: pair[1],
                 movement.ENTRY_SPAWN_AT: (movement.SPAWN_OPCODE,
                                           movement.spawn_body(location))}
        for at, (opcode, _) in built.items():
            reply = run.replies[at]
            if (reply.main, reply.sub) != (opcode.main, opcode.sub):
                raise ValueError(f"(1,143) frame {at} is ({reply.main},{reply.sub}), "
                                 f"not {opcode}")
        spawn = f"conn={{conn}} {location.describe()} key={summary.slot_index + 1}"
        return Run(state=run.state,
                   notes=tuple((level, tag, spawn if tag == "TOWN-SPAWN" else template)
                               for level, tag, template in run.notes),
                   replies=tuple(replace(reply, plain=built[i][1], nonce=b"")
                                 if i in built else reply
                                 for i, reply in enumerate(run.replies)))

    def _town_session(self, character: int | None) -> movement.TownSession | None:
        """The per-connection town state, seeded from the selected row.

        `location` is what the reference's `TOWN-SPAWN` reads at entry and
        what its `TOWN-AREA-36` line prints as `from=`.
        """
        if self._db is None or character is None:
            return None
        summary = characters.by_id(self._db, character)
        return None if summary is None else movement.TownSession.of(summary)

    async def _town_move(self, conn: int, body: bytes,
                         town: movement.TownSession) -> None:
        """`(1,35)`: a write at most once per `PERSIST_INTERVAL`, never a reply.

        A throttled move is invisible on purpose -- no write, no INFO line.
        Neither outcome logs a DISPATCH line; the reference has none for this
        opcode at all.
        """
        move = movement.Move.parse(
            tiles.decrypt_body(tiles.algo_id(movement.MOVE_OPCODE.sub), body))
        now = time.monotonic()
        if not town.persist_due(now):
            return
        movement.write_move(self._db, town.character_id, move, now=int(time.time()))
        town.persisted(now)
        self.log.info("TOWN-MOVE-35",
                      f"conn={conn} {movement.move_line(town, move)}")

    async def _town_area(self, writer: asyncio.StreamWriter, conn: int, body: bytes,
                         town: movement.TownSession, state: str) -> int:
        """`(1,36)`: writes the location, answers with the (0,23)+(0,24) pair,
        and arms the move throttle for the next `PERSIST_INTERVAL`."""
        plain = tiles.decrypt_body(tiles.algo_id(movement.AREA_OPCODE.sub), body)
        move = movement.AreaMove.parse(plain)
        line = movement.area_line(town, move)
        movement.write_area(self._db, town.character_id, move, now=int(time.time()))
        town.persisted(time.monotonic())
        town.town, town.area = move.town, move.area
        self.log.info("TOWN-AREA-36", f"conn={conn} {line}")
        sent = nbytes = 0
        for opcode, plain_body in movement.area_pair(move.town, move.area, move.x,
                                                     move.y, move.direction):
            wire = self._encode_generated(opcode, plain_body)
            await sleep_gap(self.write_gap)
            writer.write(wire)
            await writer.drain()
            sent += 1
            nbytes += len(wire)
            self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {movement.AREA_OPCODE} -> "
                                   f"{sent} frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _item_move(self, writer: asyncio.StreamWriter, conn: int, body: bytes,
                         character: int, state: str) -> int:
        """`(1,19)`: answer from the save and write the move back.

        The lines before the frames are the reference's own, tag and prose
        included, so a rewrite session can be diffed against an oracle one.
        """
        plain = tiles.decrypt_body(tiles.algo_id(inventory.OPCODE.sub), body)
        request = inventory.MoveRequest.parse(plain)
        self.log.info("ITEM-MOVE-19", f"conn={conn} {request.describe()} "
                                      f"plain={_dump_plain(plain)}")
        outcome = inventory.execute(self._db, character, request)
        frames = [(inventory.OPCODE, request.ack(ok=outcome.ok, code=outcome.code))]
        note = outcome.note
        if outcome.ok and request.cross_container:
            # After the write, so the slot frames and the record stream both
            # read the state the move left behind.
            summary = characters.by_id(self._db, character)
            refreshed = refresh.build(self._db, character, request, summary)
            frames += refreshed.frames
            note = f"{note}; {refresh.NOTE_SUFFIX.format(worn=refreshed.worn)}"
        self.log.info(outcome.tag, f"conn={conn} {note}")
        if outcome.ok and request.cross_container:
            # The reference's own line right after an accepted cross move.
            # Constant over all six captures, two worn-set sizes included;
            # what it derives from is not known.
            self.log.info("EQUIPMENT-SPECIFICITY",
                          f"conn={conn} character={character} converted=0 "
                          f"points=101 group=0 options=0")
        sent = nbytes = 0
        for opcode, plain_body in frames:
            wire = self._encode_generated(opcode, plain_body)
            await sleep_gap(self.write_gap)
            writer.write(wire)
            await writer.drain()
            sent += 1
            nbytes += len(wire)
            self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {inventory.OPCODE} -> {sent} frame(s) "
                                   f"{nbytes}B state={state}->{state}")
        return nbytes

    # ------------------------------------------------------------- sending

    async def _send_channelinfo(self, writer: asyncio.StreamWriter, conn: int,
                                server: int, channel: int) -> None:
        body = channelinfo.build(server, channel, self.advertise_host,
                                 self.unix_seconds)
        wire = frame.build_s2c(CHANNELINFO_OPCODE, body, nonce=self._connect_nonce)
        writer.write(wire)
        await writer.drain()
        self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.info("CHANNELINFO", f"conn={conn} sent first packet wire={len(wire)}B "
                                     f"plain={len(body)}B; session ciphers initialized")

    @property
    def _connect_nonce(self) -> bytes | None:
        """The captured `(0,1)` nonce, reused.  It is independent of the body,
        so regenerating the body does not invalidate it -- and nothing says the
        client checks it either way."""
        return self.script.connect[0].nonce if self.script.connect else None

    def _encode(self, reply: Reply) -> bytes:
        if reply.plain is None:
            raise ValueError(f"({reply.main},{reply.sub}) is generated, not replayed")
        body = tiles.encrypt_body(tiles.algo_id(reply.sub), reply.plain)
        # An empty nonce marks a reply whose body this server built over the
        # capture's: the captured three bytes went with the captured body.
        return frame.build_s2c(reply.opcode, body,
                               nonce=reply.nonce or os.urandom(3))

    def _encode_generated(self, opcode: frame.Opcode, plain: bytes) -> bytes:
        """A frame this server built rather than replayed, so there is no
        captured nonce to pass through: the reference sends three fresh bytes
        at `[12:15]` on every frame (`0x581030`, whose `rand8` is in there)."""
        body = tiles.encrypt_body(tiles.algo_id(opcode.sub), plain)
        return frame.build_s2c(opcode, body, nonce=os.urandom(3))

    def _log_notes(self, conn: int, f: frame.Frame, run: Run) -> None:
        for level, tag, template in run.notes:
            if tag in UNREPLAYABLE_TAGS:
                continue
            msg = template.format(conn=conn, n=len(f.body), plain=_dump_plain(
                tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)))
            self.log.line(level, tag, msg)


def _error_name(e: BaseException) -> str:
    if isinstance(e, ConnectionResetError):
        return "ConnectionReset"
    return type(e).__name__
