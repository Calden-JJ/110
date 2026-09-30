"""The game server (ports 10011-10021): the link the client lives on.

Where the channel link is three request/reply pairs, this one is a state
machine with a captured script behind each C->S opcode:

    Connected  --(1,1554)-->  Handshaken     handshake probe
    Handshaken --(1,1)-->     Authenticated  login, 2 frames
    Authenticated --(1,8)-->  RosterReady    role list, 1792B
    RosterReady --(1,4)-->    CharacterSelected
    CharacterSelected --(1,143)/(1,666)--> InTown   the town entry: the 33-frame
                     burst on whichever of the two the client sends first (char
                     1 sent `(1,143)`, the 09-28 dungeon character `(1,666)`),
                     and a one-frame ack for either one sent from InTown
    RosterReady --(1,848)/(1,433)/(1,637)--> RosterReady, and the same opcodes
    plus (1,140)/(1,707), (1,36), (1,35) keep InTown at InTown

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
from ..game.account import clientsettings
from ..game.character import roleselection, selection, tutorialflags
# The dungeon modules are aliased: `entry`, `run` and `select` are all names
# this module already uses for something else.
from ..game.dungeon import blocks as dungeon_blocks
from ..game.dungeon import card as dungeon_card
from ..game.dungeon import cardpool as dungeon_cardpool
from ..game.dungeon import clear as dungeon_clear
from ..game.dungeon import die as dungeon_die
from ..game.dungeon import droppool as dungeon_droppool
from ..game.dungeon import entry as dungeon_entry
from ..game.dungeon import loaded as dungeon_loaded
from ..game.dungeon import pickup as dungeon_pickup
from ..game.dungeon import reward as dungeon_reward
from ..game.dungeon import run as dungeon_run
from ..game.dungeon import select as dungeon_select
from ..game.dungeon import settle as dungeon_settle
from ..game.item import cargo, fame, giant, inventory, refresh, use
from ..game.shop import buy, cera, redeem, sell
from ..game.town import burst, charsettings, movement, queststate
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

    def run(self, nth: int, from_state: str | None = None) -> Run:
        """The `nth` time this opcode was sent.  Repeats the last run rather
        than running dry: `(1,2126)` is answered never but sent 162 times in
        the capture, and a client that sends it a 163rd time still expects the
        same silence.

        `from_state` -- passed only for the town-entry opcodes -- prefers the
        run whose captured `state[0]` is that state, because that is the only
        thing separating the burst from the ack: `(1,143)` is a 33-frame burst
        from `CharacterSelected` and a 16-byte ack from `InTown`.  A run with
        no recorded state never matches, so a one-run opcode is unaffected
        whichever way it is called.
        """
        if from_state is not None:
            for run in self.runs:
                if run.state and run.state[0] == from_state:
                    return run
        return self.runs[min(nth, len(self.runs) - 1)]


class GameScript:
    """The captured reply script, indexed by the C->S opcode that triggers it."""

    def __init__(self, scripts: dict[tuple[int, int], Script], *,
                 connect: tuple[Reply, ...] = (),
                 bursts: dict[tuple[int, int, int], Run] | None = None,
                 source: str = "") -> None:
        self._by_request = scripts
        self._bursts = bursts if bursts is not None else {}
        self.connect = connect
        self.source = source

    @classmethod
    def load(cls, path: Path | None = None, *,
             bursts_path: Path | None = None) -> "GameScript":
        p = path or (paths.DATA_DIR / "game" / "replies.json")
        doc = json.loads(p.read_text(encoding="utf-8"))
        out: dict[tuple[int, int], Script] = {}
        for rec in doc["scripts"]:
            key = (rec["request_main"], rec["request_sub"])
            out[key] = Script(key[0], key[1], tuple(_run_of(r) for r in rec["runs"]))
        return cls(out, connect=tuple(_reply(f) for f in doc.get("connect_frames", ())),
                   bursts=load_bursts(bursts_path if bursts_path is not None
                                      else p.parent / "town_bursts.json"),
                   source=doc.get("source", ""))

    def burst(self, key: int, main: int, sub: int) -> Run | None:
        """The town-entry run captured from the character in slot `key - 1`,
        if there is one (`game.town.burst` explains why the character's own
        list matters)."""
        return self._bursts.get((key, main, sub))

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


def _run_of(r: dict) -> Run:
    return Run(state=tuple(r["state"]) if r["state"] else None,
               notes=tuple((n[0], n[1], n[2]) for n in r["notes"]),
               replies=tuple(_reply(f) for f in r["replies"]))


def load_bursts(path: Path) -> dict[tuple[int, int, int], Run]:
    """The per-character town-entry runs, keyed by `(slot key, main, sub)`.

    Generated by `tools/extract_town_bursts.py`; a missing file is not an error
    -- the corpus run is then replayed for every character, which is what the
    server did before any per-character capture existed.
    """
    if not path.exists():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    return {(rec["key"], rec["request_main"], rec["request_sub"]): _run_of(rec)
            for rec in doc["bursts"]}


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
    """The reference's `plain=` shape: 96 bytes then `...(+NNB)`.

    Upper case: every one of the corpus's 1204 lettered `plain=` dumps is
    upper and none is lower, while all 1620 `hex=` dumps are the other way.
    """
    if len(plain) <= PLAIN_DUMP_LIMIT:
        return plain.hex().upper()
    return (f"{plain[:PLAIN_DUMP_LIMIT].hex().upper()}"
            f"...(+{len(plain) - PLAIN_DUMP_LIMIT}B)")


class GameServer:
    def __init__(self, host: str, ports: dict[int, tuple[int, int, int, str | None]],
                 script: GameScript, log: Log, *, ids: ConnectionIds | None = None,
                 write_gap: float = WRITE_GAP_SECONDS,
                 advertise_host: str | None = None,
                 unix_seconds: int | None = None,
                 save_db: Path | str | None = None,
                 oracle_kills: dict[bytes, "dungeon_die.Play"] | None = None,
                 oracle_rewards: dict[bytes, "list[dungeon_reward.Write]"] | None = None,
                 oracle_clears: dict[bytes, "dungeon_clear.Card"] | None = None,
                 oracle_commits: dict[bytes, "list[dungeon_card.Grant]"] | None = None
                 ) -> None:
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
        # The `(1,39)` chain's two underivable inputs -- what each kill left
        # on the ground and the experience the character stood at before it
        # (the tutorial clear's reward is the capture's only other source) --
        # keyed by the request's own decrypted body.  Empty, the chain reads
        # the save and rolls nothing (`dungeon.die.Play`).
        self.oracle_kills = oracle_kills or {}
        # The `(1,34)` rows the same way: the reward chain that lands them is
        # the quest module's, and until it exists a replay is handed what the
        # reference wrote, keyed by the request's decrypted body
        # (`dungeon.reward.Write`).
        self.oracle_rewards = oracle_rewards or {}
        # The `(1,46)` chain's two underivable inputs the same way: the clear's
        # own clock and the card it dropped, keyed by the request's decrypted
        # body.  Unfed, the clock is the run's and the card empty
        # (`dungeon_clear.Card`).
        self.oracle_clears = oracle_clears or {}
        # The `(1,71)` commits the same way, one list per request because a
        # session's two side-0 sends are the same eight bytes: what the card
        # dropped and the uuid behind its line are the reference's, so a
        # replay is handed them (`dungeon_card.Grant`).
        self.oracle_commits = oracle_commits or {}
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
        dungeon: dungeon_run.DungeonSession | None = None
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
                        dungeon = self._dungeon_session(character, town)
                    if key == inventory.OPCODE.key() and character is not None:
                        tx += await self._item_move(writer, conn, f.body, character, state)
                        continue
                    if (key == clientsettings.SAVE_OPCODE.key()
                            and self._account is not None):
                        tx += await self._client_settings_save(writer, conn,
                                                               f.body, character,
                                                               state, dungeon)
                        continue
                    if key == use.OPCODE.key() and character is not None:
                        tx += await self._item_use(writer, conn, f.body,
                                                   character, state)
                        continue
                    if key == buy.OPCODE.key() and character is not None:
                        tx += await self._npc_buy(writer, conn, f.body,
                                                  character, state)
                        continue
                    if key == sell.OPCODE.key() and character is not None:
                        tx += await self._npc_sell(writer, conn, f.body,
                                                   character, state)
                        continue
                    if key == cera.OPCODE.key() and character is not None:
                        tx += await self._cera_buy(writer, conn, f.body,
                                                   character, state)
                        continue
                    if key == cera.POLL_OPCODE.key() and self._account is not None:
                        tx += await self._cera_poll(writer, conn, state)
                        continue
                    if key == redeem.OPCODE.key():
                        tx += await self._npc_redeem(writer, conn, state, dungeon)
                        continue
                    if town is not None:
                        if key == movement.MOVE_OPCODE.key():
                            await self._town_move(conn, f.body, town)
                            continue
                        if key == movement.AREA_OPCODE.key():
                            tx += await self._town_area(writer, conn, f.body, town, state)
                            continue
                        if key == movement.PREV_VILLAGE_OPCODE.key():
                            tx += await self._town_prev_village(writer, conn, town, state)
                            continue
                    if dungeon is not None:
                        if key == dungeon_select.SELECT_OPCODE.key():
                            tx += await self._dungeon_select(writer, conn, f.body,
                                                             dungeon, state)
                            continue
                        if key == dungeon_entry.ENTER_OPCODE.key():
                            tx += await self._dungeon_enter(writer, conn, f.body,
                                                            dungeon, character, state)
                            continue
                        if key == dungeon_loaded.LOADED_OPCODE.key():
                            tx += await self._dungeon_loaded(writer, conn, dungeon, state)
                            continue
                        if key == dungeon_loaded.MOVE_OPCODE.key():
                            tx += await self._dungeon_move(writer, conn, f.body,
                                                           dungeon, state)
                            continue
                        if key == dungeon_die.DIE_OPCODE.key():
                            tx += await self._dungeon_die(writer, conn, f.body,
                                                          dungeon, character, state)
                            continue
                        if key == dungeon_pickup.PICKUP_OPCODE.key():
                            tx += await self._dungeon_pickup(writer, conn, f.body,
                                                             dungeon, character,
                                                             state)
                            continue
                        if key == dungeon_clear.CLEAR_OPCODE.key():
                            tx += await self._dungeon_clear(writer, conn, f.body,
                                                            dungeon, character,
                                                            state)
                            continue
                        if key == dungeon_clear.CHECK_OPCODE.key():
                            tx += await self._dungeon_check(writer, conn, f.body,
                                                            dungeon, state)
                            continue
                        if key == dungeon_settle.LEAVE_OPCODE.key():
                            tx += await self._dungeon_leave(writer, conn, dungeon, state)
                            continue
                        if key == dungeon_card.STAGE_OPCODE.key():
                            tx += await self._card_stage(writer, conn, dungeon,
                                                         dungeon_card.STAGE_OPCODE,
                                                         state)
                            continue
                        if key == dungeon_card.STAGE_FLAGS_OPCODE.key():
                            tx += await self._card_stage(
                                writer, conn, dungeon,
                                dungeon_card.STAGE_FLAGS_OPCODE, state)
                            continue
                        if key == dungeon_card.COMMIT_OPCODE.key():
                            tx += await self._card_commit(writer, conn, f.body,
                                                          dungeon, character,
                                                          state)
                            continue
                        if key == dungeon_settle.SETTLE_OPCODE.key():
                            tx += await self._dungeon_settle(writer, conn, f.body,
                                                             dungeon, character,
                                                             state)
                            continue
                    if key == queststate.ACCEPT_OPCODE.key() and character is not None:
                        self._quest_accept(f.body, character)
                        # No `continue`: the accept's own frames and its
                        # `QUEST-ACCEPT-31` line are the replay's for now --
                        # M3.1 writes the state the retry scan reads and
                        # leaves the reward chain to a later milestone.
                    elif key == queststate.FINISH_OPCODE.key() and character is not None:
                        self._quest_finish(f.body, character)
                    # The town entry is chosen by state, not by opcode: the
                    # first of `(1,143)`/`(1,666)` sent from `CharacterSelected`
                    # draws the burst and either one sent from `InTown` is a
                    # one-frame ack.  That is a fact about the connection, not
                    # about the save, so the run is picked by state even with no
                    # character -- the burst is then replayed as captured.
                    entry = key in movement.ENTRY_KEYS
                    entry_burst = entry and state == movement.ENTRY_FROM
                    # `(1,666)` is also one of the six constant acks, so the
                    # burst has to be routed before that table gets a look.
                    if (self._db is not None and selection.handles(key)
                            and not entry_burst):
                        # The roster/town acks: constants, no state change --
                        # `game.character.selection` has the evidence.
                        run = self._selection_ack(key, f.body, state)
                    else:
                        script = self.script.match(*key)
                        if script is None:
                            self.log.warn("GAME", f"conn={conn} no script for "
                                                  f"{f.opcode}; no response")
                            continue
                        nth = cursors.get(key, 0)
                        cursors[key] = nth + 1
                        run = script.run(nth,
                                         from_state=state if entry else None)
                        if entry_burst and character is not None:
                            run = self._town_entry(conn, key, run, character)
                        elif key == (1, 4) and character is not None:
                            run = self._selection(conn, run, character)
                    # `(1,143)`'s flag line is the run's first in both of its
                    # shapes, and the row it writes is the run's own business,
                    # not the script's.
                    if key == tutorialflags.OPCODE.key():
                        run = self._tutorial_flag(conn, f, run, character)
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

    def _selection_ack(self, key: tuple[int, int], body: bytes, state: str) -> Run:
        """A roster/town ack: one constant frame, the state unchanged.

        `(1,433)`'s note prints how many entries its request carried, so the
        body is decrypted for the family even though five of the six ignore
        it.
        """
        ack = selection.ack(key, tiles.decrypt_body(tiles.algo_id(key[1]), body))
        return Run(state=(state, state),
                   notes=(("INFO", ack.tag, ack.note),),
                   replies=(Reply(ack.opcode.main, ack.opcode.sub,
                                  f"tile{tiles.algo_id(ack.opcode.sub)}",
                                  ack.body, b"", False, 0),))


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

    def _selection(self, conn: int, run: Run, character: int) -> Run:
        """The `(1,4)` run with three of its four frames regenerated.

        The push is a pure function of the account's settings row --
        `u32le(492)` + the row + 8 zero bytes.  The 1296B body is the captured
        template with its six regions written from the selected row, the
        account's contracts and the clock, and `(0,1370)` is the row's
        `character_story_digest.last_level` (`game.character.roleselection`).
        Only `(0,2082)` is replayed as captured.
        """
        if self._account is None:
            return run
        summary = characters.by_id(self._db, character)
        if summary is None:
            self.log.warn("SELECTION-4",
                          f"conn={conn} character={character} is not in the "
                          f"save; replaying the captured body")
            return run
        # One `now` for both the body and its line, the way the reference
        # builds a run in one pass.
        pick = roleselection.Pick.of(self._db, self._account, summary,
                                     int(time.time()))
        level = characters.story_level(self._db, character)
        built = {roleselection.RUN_AT: (roleselection.OPCODE, pick.body()),
                 roleselection.STORY_AT: (roleselection.STORY_OPCODE,
                                          roleselection.story_body(level))}
        lines = {"SELECTION-4": f"conn={{conn}} {pick.note()}",
                 "TUTORIAL-FLAGS": f"conn={{conn}} {pick.flags_note()}",
                 "STORY-DIGEST":
                     f"conn={{conn}} {roleselection.story_note(character, level)}"}
        options = clientsettings.load(self._db, self._account)
        if options is None:
            self.log.warn("CLIENT-SETTINGS",
                          f"conn={conn} account={self._account} has no "
                          f"account_client_settings row; replaying the captured "
                          f"push")
        else:
            push = clientsettings.push_body(options)
            built[clientsettings.SELECTION_AT] = (clientsettings.PUSH_OPCODE, push)
            lines["CLIENT-SETTINGS"] = (
                f"conn={{conn}} {clientsettings.push_line(options, len(push))}")
        for at, (opcode, _) in built.items():
            reply = run.replies[at]
            if (reply.main, reply.sub) != (opcode.main, opcode.sub):
                raise ValueError(f"(1,4) frame {at} is ({reply.main},{reply.sub}), "
                                 f"not {opcode}")
        return Run(state=run.state,
                   notes=tuple((level, tag, lines.get(tag, template))
                               for level, tag, template in run.notes),
                   replies=tuple(replace(reply, plain=built[i][1], nonce=b"")
                                 if i in built else reply
                                 for i, reply in enumerate(run.replies)))

    def _own_entry(self, key: int, request: tuple[int, int]) -> Run | None:
        """The character's own entry run for `request`, if there is one.

        The captures are stored under one of the two entry opcodes, but the
        two draw the same frame list -- one is the other behind its own leading
        ack -- so a character captured through `(1,143)` can still be answered
        on `(1,666)`.  It has to be: the alternative is the corpus run, whose
        bag frames are another character's, which is the mismatch that crashed
        the client.
        """
        run = self.script.burst(key, *request)
        if run is not None or request != burst.OTHER_ENTRY:
            return run
        run = self.script.burst(key, *burst.CAPTURED_ENTRY)
        if run is None:
            return None
        ack = burst.OTHER_ENTRY_ACK
        return Run(state=run.state, notes=run.notes,
                   replies=(Reply(request[0], request[1],
                                  f"tile{tiles.algo_id(request[1])}", ack,
                                  b"", False, 0),) + run.replies)

    def _town_entry(self, conn: int, request: tuple[int, int], run: Run,
                    character: int) -> Run:
        """The town-entry run with its eleven built frames regenerated.

        The run is the entering character's *own*: `(1,143)`/`(1,666)` draw the
        selected character's frame list, and the save's three enter with 33, 31
        and 30 frames -- so the burst is looked up by that character's slot key
        rather than replayed from the corpus, whose list belongs to whichever
        character was captured (`game.town.burst` has the shapes).  `locate`
        then finds the frames to rebuild in it, addressed by opcode, because
        their indices move from list to list.

        Eight of those are the row-built frames the server rebuilt before --
        quickslots, the quest trio, the area pair, the spawn and the cera
        balance.  The other three are the ones no replayed copy could carry:
        the two USERINFO faces, which name the selected character and list its
        worn set, and the main inventory, whose `(0,13)` frame both captures
        *cut* (the log's hex dumps stop at 4096 bytes and it is 7265B for one
        character, 4130B for another), so a replayed copy would be half a
        frame.

        The notes that describe those frames are rewritten the same way.
        Everything else in the burst is replayed as captured -- the remaining
        `(0,13)` bag frames included, which are the captured character's own.
        """
        summary = characters.by_id(self._db, character)
        key = summary.slot_index + 1
        own = self._own_entry(key, request)
        if own is not None:
            run = own
        else:
            self.log.warn("TOWN-ENTRY",
                          f"conn={conn} character={character} key={key} has no "
                          f"captured {request} burst; replaying the corpus one")
        at = burst.locate(run.replies)
        named = burst.self_character(run.replies[at["userinfo"]].plain)
        if named != character:
            self.log.warn("TOWN-ENTRY",
                          f"conn={conn} {request} names character {named} where "
                          f"its small USERINFO should name {character}")
        location = movement.Location.of(summary)
        pair = movement.area_pair(key, location.town, location.area, location.x,
                                  location.y, location.direction)
        payload = charsettings.load(self._db, character)
        if payload is None:
            self.log.warn("TOWN-QUICKSLOT",
                          f"conn={conn} character={character} has no "
                          f"character_quickslots row; pushing defaults")
            payload = charsettings.default_payload()
        balance = accounts.cera(self._db, self._account) or 0
        finished = queststate.finished_ids(self._db, character)
        in_progress = queststate.in_progress(self._db, character)
        accepted = queststate.accepted_count(self._db, character)
        active = [q for q, _ in in_progress]
        available = queststate.available_ids(queststate.Seeker.of(summary),
                                             finished, active)
        nodes = queststate.worldmap_nodes(summary.town_id)
        worn = refresh.equipment(self._db, character)
        levels = giant.creature_levels(self._db, character)
        version = fame.compute(self._db, character)
        bag = burst.Inventory.of(self._db, character)
        built = {
            "quickslots": (charsettings.PUSH_OPCODE,
                           charsettings.push_body(payload)),
            "finished": (queststate.FINISHED_OPCODE,
                         queststate.finished_body(finished)),
            "in_progress": (queststate.IN_PROGRESS_OPCODE,
                            queststate.in_progress_body(in_progress)),
            "available": (queststate.AVAILABLE_OPCODE,
                          queststate.available_body(summary.level, available)),
            "pair0": pair[0],
            "pair1": pair[1],
            "spawn": (movement.SPAWN_OPCODE, movement.spawn_body(location, key)),
            "cera": (cera.BALANCE_OPCODE, cera.balance_body(balance)),
            "userinfo": (refresh.OPCODE_USERINFO,
                         refresh.userinfo_body(summary, worn, levels, version)),
            "giant": (refresh.OPCODE_USERINFO,
                      giant.body(summary, worn, levels,
                                 giant.runes(self._db, character), version)),
            "inventory": (burst.LIST_OPCODE, bag.body()),
        }
        by_index = {at[name]: value for name, value in built.items()}
        quests = queststate.quests_line(summary.town_id, nodes, len(available),
                                        active, len(finished), summary.level)
        lines = {
            "TOWN-SPAWN":
                f"conn={{conn}} {location.describe()} key={key}",
            "TOWN-QUEST-STATE":
                f"conn={{conn}} {queststate.state_line(finished, in_progress, accepted)}",
            "TOWN-QUESTS": f"conn={{conn}} {quests}",
            "TOWN-CERA": f"conn={{conn}} {cera.town_line(self._account, balance)}",
            "TOWN-ITEMS": f"conn={{conn}} {bag.note()}",
            "TOWN-APPEARANCE":
                f"conn={{conn}} {giant.appearance_note(worn, levels)}",
            "TOWN-SELF-DATA": f"conn={{conn}} {giant.self_data_note(summary)}",
        }
        return Run(state=run.state,
                   notes=tuple((level, tag, lines.get(tag, template))
                               for level, tag, template in run.notes),
                   replies=tuple(replace(reply, nonce=b"",
                                         plain=dungeon_clear.padded(*by_index[i]))
                                 if i in by_index else reply
                                 for i, reply in enumerate(run.replies)))

    def _tutorial_flag(self, conn: int, f: frame.Frame, run: Run,
                       character: int | None) -> Run:
        """`(1,143)`'s flag: store the row, and swap the replayed line for it.

        The handler reads the request before it decides what the request is,
        so the line is the run's first whichever shape the state picked -- the
        town-entry burst or the duplicate's one-frame ack.  Both shapes carry
        the line as a captured note, which is what this replaces; the write
        itself has no business being in the capture's data.
        """
        if self._db is None or character is None:
            return run
        plain = tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)
        report = tutorialflags.parse(plain)
        if report is None:
            return run
        tag, prose = tutorialflags.record(self._db, character,
                                          self._character_key(character), report)
        return replace(run, notes=tuple(
            (level, note_tag,
             f"conn={{conn}} {prose}" if note_tag == tutorialflags.TAG else template)
            for level, note_tag, template in run.notes))

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

        A throttled move is invisible on purpose -- no write, no INFO line, and
        no re-arming either: the timer starts at a write, not at a send.  A
        move that would not change the row is skipped the same way, and also
        does not arm the timer.

        The session's in-memory position moves either way: the reference's
        own does, and a room entry saves it as the way back -- the 09-30
        session's throttled (1,35) is exactly what the next entry saved.
        """
        move = movement.Move.parse(
            tiles.decrypt_body(tiles.algo_id(movement.MOVE_OPCODE.sub), body))
        town.x, town.y, town.direction = move.x, move.y, move.direction
        now = time.monotonic()
        if not town.persist_due(now):
            return
        if not movement.changed(characters.by_id(self._db, town.character_id), move):
            return
        movement.write_move(self._db, town.character_id, move, now=int(time.time()))
        town.persisted(now)
        self.log.info("TOWN-MOVE-35",
                      f"conn={conn} {movement.move_line(town, move)}")

    async def _town_area(self, writer: asyncio.StreamWriter, conn: int, body: bytes,
                         town: movement.TownSession, state: str) -> int:
        """`(1,36)`: writes the location, answers with the (0,23)+(0,24) pair,
        and arms the move throttle for the next `PERSIST_INTERVAL`.

        An entry *into* 赛利亚房间 also saves the way back: the source
        `(town, area)` and the session's in-memory position and facing go to
        `character_previous_village`, where the room's lower exit (`(1,1418)`)
        reads them.  That is the reference's own split -- it snapshots at the
        `(1,36)`, not at the `(1,1418)`: the escape's coordinates are the ones
        a `(1,35)` left *before* the room was entered.
        """
        plain = tiles.decrypt_body(tiles.algo_id(movement.AREA_OPCODE.sub), body)
        move = movement.AreaMove.parse(plain)
        line = movement.area_line(town, move)
        came_from = town.location()
        movement.write_area(self._db, town.character_id, move, now=int(time.time()))
        town.persisted(time.monotonic())
        if (move.town, move.area) == movement.ROOM:
            movement.save_previous_village(self._db, town.character_id, came_from)
        town.town, town.area = move.town, move.area
        town.x, town.y, town.direction = move.x, move.y, move.direction
        self.log.info("TOWN-AREA-36", f"conn={conn} {line}")
        sent, nbytes = await self._write_frames(writer, conn, movement.area_pair(
            town.key, move.town, move.area, move.x, move.y, move.direction))
        self.log.debug("DISPATCH", f"conn={conn} {movement.AREA_OPCODE} -> "
                                   f"{sent} frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _town_prev_village(self, writer: asyncio.StreamWriter, conn: int,
                                 town: movement.TownSession, state: str) -> int:
        """`(1,1418)`: 赛利亚房间's lower exit -- teleport to the saved way back.

        The row is what the last room entry wrote; a character with none --
        logged in inside the room, never walked in -- lands at the room's own
        town door instead, and the line says `origin=default` where the
        reference's 40 lines all say `saved`.  The request body is empty and
        unread, the answer is the `(1,36)` pair, and the destination row is
        written like a `(1,36)`'s (the reference's save ends up holding the
        escape landing).

        The reference answered one and ignored a same-tick duplicate (09-30
        15:57:52, 20ms apart); answering both is harmless -- the second reads
        the row the first wrote and lands where the character stands.
        """
        where = movement.previous_village(self._db, town.character_id)
        origin = "saved"
        if where is None:
            where, origin = movement.ROOM_TOWN_DOOR, "default"
        movement.write_location(self._db, town.character_id, where,
                                now=int(time.time()))
        self.log.info("PREV-VILLAGE-1418",
                      f"conn={conn} {movement.prev_village_line(town, where, origin)}")
        town.town, town.area = where.town, where.area
        town.x, town.y, town.direction = where.x, where.y, where.direction
        sent, nbytes = await self._write_frames(writer, conn, movement.area_pair(
            town.key, where.town, where.area, where.x, where.y, where.direction))
        self.log.debug("DISPATCH", f"conn={conn} {movement.PREV_VILLAGE_OPCODE} -> "
                                   f"{sent} frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    # ------------------------------------------------------------ dungeon

    def _dungeon_session(self, character: int | None,
                         town: movement.TownSession | None) \
            -> dungeon_run.DungeonSession | None:
        """The per-connection dungeon state, seeded from the selected row.

        It mirrors the town session's key and town: `(1,15)` looks its gate up
        in the session's `(town, area)`, which is why it cannot exist without
        one.
        """
        if self._db is None or character is None or town is None:
            return None
        summary = characters.by_id(self._db, character)
        return None if summary is None else dungeon_run.DungeonSession.of(summary, town)

    def _character_key(self, character: int) -> int:
        """The character's own number: the `slot_index + 1` every frame opens
        with -- `TOWN-SPAWN`, the town pair, the dungeon burst.

        On this save every character's id is its slot plus one, so the two
        readings cannot be told apart; `refresh.py` records the same
        ambiguity for the `(0,2)` header, and `character_id` is what the
        giant writes for the same number.
        """
        summary = characters.by_id(self._db, character)
        return summary.slot_index + 1

    async def _write_frames(self, writer: asyncio.StreamWriter, conn: int,
                            frames) -> tuple[int, int]:
        """Send a handler's own `[(opcode, body)]` in order, logging each.

        The handlers that build frames rather than replay the script's write
        them the same way `_handle` does -- the log is where the diff reads
        them from, so a frame that skips `log.packet` is a frame that never
        happened.
        """
        sent = nbytes = 0
        for opcode, plain in frames:
            wire = self._encode_generated(opcode, plain)
            await sleep_gap(self.write_gap)
            writer.write(wire)
            await writer.drain()
            sent += 1
            nbytes += len(wire)
            self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        return sent, nbytes

    async def _dungeon_select(self, writer: asyncio.StreamWriter, conn: int,
                              body: bytes, session: dungeon_run.DungeonSession,
                              state: str) -> int:
        """`(1,15)`: the gate burst, or one of its two silent refusals.

        A run in progress wins over the gate lookup, and a gate-less area
        loses to it; both print their one line and send nothing, which is why
        neither has a DISPATCH line -- in the reference or here.
        """
        select = dungeon_select.Select.parse(tiles.decrypt_body(
            tiles.algo_id(dungeon_select.SELECT_OPCODE.sub), body))
        if session.in_progress:
            self.log.info("DUNGEON-SELECT-15",
                          f"conn={conn} {dungeon_select.IN_RUN_NOTE}")
            return 0
        row = dungeon_select.gate(session.town.town, session.town.area)
        if row is None:
            self.log.info("DUNGEON-SELECT-15",
                          f"conn={conn} {dungeon_select.miss_note(session.town.town, session.town.area)}")
            return 0
        session.selected = True
        self.log.info("DUNGEON-SELECT-15",
                      f"conn={conn} {dungeon_select.note(session, select, row)}")
        # The burst's own `(0,23)` carries the row's last persisted position,
        # the same frame the town pair builds -- read after the walk that put
        # it there, not cached at `(1,4)`.
        location = movement.Location.of(
            characters.by_id(self._db, session.character_id))
        sent, nbytes = await self._write_frames(
            writer, conn, dungeon_select.burst(session, row, location))
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_select.SELECT_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _dungeon_enter(self, writer: asyncio.StreamWriter, conn: int,
                             body: bytes, session: dungeon_run.DungeonSession,
                             character: int, state: str) -> int:
        """`(1,16)`: the shapes, in the reference's own guard order.

        The pending tutorial entry wins over everything; a run already in
        progress (or no selection drawn) is the one ignored line; the
        request's own quest names a maze when it can; otherwise the native
        retry remaps a bare gate click onto the maze of the gate's worldmap
        whose quest the character is already on; and when even that finds
        nothing -- a pick with no quest behind it -- the request's dungeon
        enters its own first maze, which is what the reference's level-110
        sessions do.  Only a dungeon table 045 does not hold still ends in
        the ignored line.
        """
        plain = tiles.decrypt_body(tiles.algo_id(dungeon_entry.ENTER_OPCODE.sub),
                                   body)
        request = dungeon_entry.Request.parse(plain)
        summary = characters.by_id(self._db, character)
        if (summary is not None and summary.pending_tutorial_dungeon_id
                and request.dungeon == summary.pending_tutorial_dungeon_id):
            return await self._tutorial_entry(writer, conn, session, character,
                                              request, state)
        if session.in_progress or not session.selected:
            self.log.info("DUNGEON-ENTER-16",
                          f"conn={conn} {dungeon_entry.ignored_line(request.dungeon)}")
            return 0
        index = dungeon_entry.maze_for(request.dungeon, request.quest)
        if index is None:
            retry = dungeon_entry.retry_quest(
                session, {q for q, _ in queststate.in_progress(
                    self._db, character)})
            if retry is not None:
                dungeon, index, quest = retry
                self.log.info("DUNGEON-ENTER-16",
                              f"conn={conn} {dungeon_entry.retry_line(request.dungeon, quest, dungeon)}")
                request = replace(request, dungeon=dungeon, quest=quest)
            else:
                index = dungeon_entry.default_maze(request.dungeon)
                if index is None:
                    self.log.info("DUNGEON-ENTER-16",
                                  f"conn={conn} {dungeon_entry.ignored_line(request.dungeon)}")
                    return 0
        self.log.info("DUNGEON-ENTER-16",
                      f"conn={conn} {dungeon_entry.request_line(session.key, summary.level, request)}")
        run = session.begin(request.dungeon, index, request.difficulty)
        return await self._entry_frames(writer, conn, session, run, request, state)

    async def _tutorial_entry(self, writer: asyncio.StreamWriter, conn: int,
                              session: dungeon_run.DungeonSession, character: int,
                              request: dungeon_entry.Request, state: str) -> int:
        """The pending tutorial dungeon's path: two pre-frames, then the pair.

        Five lines replace the usual two, the frames go out ahead of the pair,
        and the pending value is consumed in the same pass -- which is what
        the committed line reports by reading it back.
        """
        summary = characters.by_id(self._db, character)
        self.log.info("DUNGEON-ENTER-16",
                      f"conn={conn} {dungeon_entry.tutorial_line(session.key, request.dungeon)}")
        self.log.info("DUNGEON-ENTER-16",
                      f"conn={conn} {dungeon_entry.request_line(session.key, summary.level, request)}")
        self.log.info("DUNGEON-ENTER-16",
                      f"conn={conn} {dungeon_entry.pre_frames_line()}")
        # The tutorial dungeon is in no worldmap's node list, so its index is
        # not a lookup: the capture's one entry is maze 0 and nothing else is
        # reachable (`request.dungeon` is the character's own pending value).
        run = session.begin(request.dungeon, 0, request.difficulty)
        self.log.info("DUNGEON-ENTRY",
                      f"conn={conn} {dungeon_entry.entry_line(session.key, run, request, dungeon_entry.monster_count(run))}")
        characters.clear_pending_tutorial(self._db, character)
        pending = characters.by_id(self._db, character).pending_tutorial_dungeon_id
        self.log.info("DUNGEON-ENTER-16",
                      f"conn={conn} {dungeon_entry.committed_line(pending == 0)}")
        frames = [(dungeon_blocks.ACK_OPCODE,
                   dungeon_blocks.ack_body(session.key)),
                  (dungeon_blocks.HEAD_OPCODE, dungeon_blocks.ENTRY_HEAD_BODY)]
        sent, nbytes = await self._write_frames(
            writer, conn, frames + self._entry_pair(run))
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_entry.ENTER_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _entry_frames(self, writer: asyncio.StreamWriter, conn: int,
                            session: dungeon_run.DungeonSession,
                            run: dungeon_run.DungeonRun,
                            request: dungeon_entry.Request, state: str) -> int:
        """The entry pair and the two lines every non-tutorial entry prints."""
        self.log.info("DUNGEON-ENTRY",
                      f"conn={conn} {dungeon_entry.entry_line(session.key, run, request, dungeon_entry.monster_count(run))}")
        sent, nbytes = await self._write_frames(writer, conn, self._entry_pair(run))
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_entry.ENTER_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    @staticmethod
    def _entry_pair(run: dungeon_run.DungeonRun):
        """`(0,28)` + `(0,29)`, the two frames a run's room is drawn from."""
        return [(dungeon_entry.MAP_OPCODE, dungeon_entry.map_body(run)),
                (dungeon_entry.SPAWN_OPCODE,
                 dungeon_entry.room_body(run, revisit=False))]

    async def _dungeon_loaded(self, writer: asyncio.StreamWriter, conn: int,
                              session: dungeon_run.DungeonSession,
                              state: str) -> int:
        """`(1,37)`: the ack, and the two constant frames that follow it."""
        self.log.info("DUNGEON-LOADED-37",
                      f"conn={conn} {dungeon_loaded.note(session.run)}")
        sent, nbytes = await self._write_frames(writer, conn,
                                                dungeon_loaded.replies())
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_loaded.LOADED_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _dungeon_move(self, writer: asyncio.StreamWriter, conn: int,
                            body: bytes, session: dungeon_run.DungeonSession,
                            state: str) -> int:
        """`(1,45)`: the destination cell, answered with the room's `(0,29)`.

        One frame and one line, both read off the run the move just put the
        room in -- the room's records for the frame, its live count and the
        frame's content size for the line.  The two silent cases (no run, a
        cell with no map) are `loaded.move`'s None.
        """
        cell = dungeon_loaded.move_cell(tiles.decrypt_body(
            tiles.algo_id(dungeon_loaded.MOVE_OPCODE.sub), body))
        moved = dungeon_loaded.move(session, cell)
        if moved is None:
            return 0
        frames, text = moved
        self.log.info("DUNGEON-MOVE-45", f"conn={conn} {text}")
        sent, nbytes = await self._write_frames(writer, conn, frames)
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_loaded.MOVE_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    def _skill_rows(self, character_id: int) -> list[tuple[int, int]]:
        """The save's learned skills, `(skill_id, level)`, for the SP math."""
        return self._db.execute(
            "SELECT skill_id, level FROM character_skills "
            "WHERE character_id=? ORDER BY skill_id", (character_id,)).fetchall()

    async def _dungeon_die(self, writer: asyncio.StreamWriter, conn: int,
                           body: bytes, session: dungeon_run.DungeonSession,
                           character: int, state: str) -> int:
        """`(1,39)`: the drop frame, the exp frame, and the boss room's ack.

        A request that names no record this run has drawn is the reference's
        one refusal: no frames at all, its whole body in the line, and as
        `alive=` the lowest id still standing in the room the run is in --
        not the session's id counter, which stands 27 past it in the capture.
        """
        plain = tiles.decrypt_body(tiles.algo_id(dungeon_die.DIE_OPCODE.sub),
                                   body)
        killed = (None if session.run is None
                  else session.run.kill(dungeon_die.sequence(plain)))
        if killed is None:
            alive = session.next_id if session.run is None else session.run.live_id()
            self.log.info("COMBAT-DIE-39",
                          f"conn={conn} {dungeon_die.refusal_note(plain, alive)}")
            return 0
        map_id, spawn = killed
        summary = characters.by_id(self._db, character)
        spent = ((0, 0) if summary is None
                 else dungeon_die.spent_for(summary.class_id,
                                            self._skill_rows(character)))
        fed = self.oracle_kills.get(plain)
        if fed is None:
            fed = dungeon_die.Play(
                exp_before=summary.experience if summary is not None else 0,
                drops=dungeon_droppool.roll(session.run.dungeon, spawn))

        def boss(level: int) -> dungeon_die.Boss | None:
            """The kill's quest burst, at the level the kill lands on."""
            if summary is None:
                return None
            return dungeon_clear.boss_burst(
                self._db, character, map_id,
                replace(queststate.Seeker.of(summary), level=level),
                key=session.key, difficulty=session.run.difficulty)

        result = dungeon_die.resolution(session, session.run, map_id, spawn,
                                        dungeon_die.sequence(plain), fed, boss,
                                        spent=spent)
        if result.quest_note is not None:
            self.log.info("QUEST-COMBAT", f"conn={conn} {result.quest_note}")
        self.log.info("COMBAT-DIE-39", f"conn={conn} {result.note}")
        sent, nbytes = await self._write_frames(writer, conn, result.frames)
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_die.DIE_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        if result.experience_reply is not None:
            characters.grant_experience(self._db, character, result.level,
                                        result.experience)
        return nbytes

    async def _dungeon_pickup(self, writer: asyncio.StreamWriter, conn: int,
                              body: bytes, session: dungeon_run.DungeonSession,
                              character: int, state: str) -> int:
        """`(1,43)`: the ground row into the bag, and the frame that says where.

        The item form is one `(0,39)` and the gold form its own larger one plus
        the `(0,14)` refresh of slot 0; a refusal answers nothing and prints
        the whole request (`dungeon.pickup.Resolution`).
        """
        plain = tiles.decrypt_body(tiles.algo_id(dungeon_pickup.PICKUP_OPCODE.sub),
                                   body)
        result = dungeon_pickup.resolution(
            self._db, session, character, dungeon_pickup.slot_of(plain), plain,
            now=int(time.time()))
        self.log.info("DUNGEON-PICKUP", f"conn={conn} {result.note}")
        if not result.committed:
            return 0
        sent, nbytes = await self._write_frames(writer, conn, result.frames)
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_pickup.PICKUP_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _dungeon_clear(self, writer: asyncio.StreamWriter, conn: int,
                             body: bytes, session: dungeon_run.DungeonSession,
                             character: int, state: str) -> int:
        """`(1,46)`: the five frames a clear is answered with, and its flag.

        The clock and the card are the reference's own where a replay is fed
        both keyed by the request; a run with nothing fed rolls its card from
        the dungeon's own pools (`dungeon_cardpool`) and sends that, which is
        what lets the live client offer its flips at all.  `(0,37)` reports
        the character row as it stands: the clear itself grants no
        experience, which is what the capture's own 480/2296/7338 show.  The
        flag is what `(1,42)` reads back and what retires the run at the
        gates.
        """
        plain = tiles.decrypt_body(tiles.algo_id(dungeon_clear.CLEAR_OPCODE.sub),
                                   body)
        run = session.run
        if run is None:
            return 0
        fed = self.oracle_clears.get(plain)
        summary = characters.by_id(self._db, character)
        session.settled = True
        if fed is not None:
            card, items = fed.payload, ()
        else:
            reward = dungeon_cardpool.roll(run.dungeon)
            card, items = dungeon_cardpool.card_bytes(reward), reward.items
        # The card the five frames hand out is also the flips' context: what
        # the commits read their cost, free gold and grants from, and what
        # the settlement counts its attempts on (`dungeon_card.Result`).
        session.result = dungeon_card.Result.of(card, run.dungeon, items)
        result = dungeon_clear.resolution(
            run, summary.level, summary.experience,
            fed.clear_ms if fed is not None else run.elapsed_ms(),
            card,
            spent=dungeon_die.spent_for(summary.class_id,
                                        self._skill_rows(character)))
        self.log.info("DUNGEON-CLEAR-46", f"conn={conn} {result.note}")
        sent, nbytes = await self._write_frames(writer, conn, result.frames)
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_clear.CLEAR_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _dungeon_check(self, writer: asyncio.StreamWriter, conn: int,
                             body: bytes, session: dungeon_run.DungeonSession,
                             state: str) -> int:
        """`(1,117)`: the boss check, answered with the id's own `(0,115)`.

        One frame whatever the flags say -- the echo is the client's answer,
        and nothing in the capture shows the reference dropping it.  The two
        flags are read off the run the check names (`clear.check_flags`).
        """
        target = dungeon_clear.check_target(tiles.decrypt_body(
            tiles.algo_id(dungeon_clear.CHECK_OPCODE.sub), body))
        run = session.run
        valid, clear = ((False, False) if run is None
                        else dungeon_clear.check_flags(run, target))
        self.log.info("BOSS-CHECK-117",
                      f"conn={conn} {dungeon_clear.check_note(target, valid, clear)}")
        sent, nbytes = await self._write_frames(
            writer, conn, [(dungeon_blocks.BOSS_ACK_OPCODE,
                            dungeon_blocks.boss_ack_body(target))])
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_clear.CHECK_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _dungeon_leave(self, writer: asyncio.StreamWriter, conn: int,
                             session: dungeon_run.DungeonSession,
                             state: str) -> int:
        """`(1,42)`: the run ends and the town pair settles it.

        The note's `settled=` is read before `leave()` resets the flag -- it
        is a statement about the run being left, not about the next one.
        """
        settled = session.settled
        run = session.leave()
        location = movement.Location.of(
            characters.by_id(self._db, session.character_id))
        self.log.info("SETTLEMENT-42",
                      f"conn={conn} {dungeon_settle.note(run, settled, session.key, location)}")
        sent, nbytes = await self._write_frames(
            writer, conn, dungeon_settle.replies(session.key, location))
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_settle.LEAVE_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    def _quest_accept(self, body: bytes, character: int) -> None:
        """`(1,31)`: the two rows an accept writes (`queststate.accept`).

        Only the state is written: the retry scan reads it, and the request's
        own frames and reward line stay the replay's until the milestone that
        builds them.
        """
        quest = queststate.request_quest(tiles.decrypt_body(
            tiles.algo_id(queststate.ACCEPT_OPCODE.sub), body))
        queststate.accept(self._db, character, quest, now=int(time.time()))

    def _quest_finish(self, body: bytes, character: int) -> None:
        """`(1,34)`: the finished row, and the fed reward rows with it.

        The finish's own reward chain is a later milestone; what a capture's
        rows are handed in as is `dungeon.reward.Write`.
        """
        plain = tiles.decrypt_body(tiles.algo_id(queststate.FINISH_OPCODE.sub),
                                   body)
        now = int(time.time())
        queststate.finish(self._db, character,
                          queststate.request_quest(plain), now=now)
        self._fed_write(plain, character, now)

    async def _card_stage(self, writer: asyncio.StreamWriter, conn: int,
                          session: dungeon_run.DungeonSession,
                          opcode: frame.Opcode, state: str) -> int:
        """`(1,69)`/`(1,70)`: the flip's two stages, and one line for both.

        The first answers with the bare `01`, the second with the flag body
        and then the state frame the commit itself answers with -- the client
        draws the card from it either way.  Both lines print the two flags as
        the result stands at that moment, which is what tells the capture's
        pre-flip `False False` from its post-flip `True True`.
        """
        result = session.result
        self.log.info("DUNGEON-CARD-STAGE",
                      f"conn={conn} "
                      f"{dungeon_card.stage_note(session.key, opcode.sub, result)}")
        flags = opcode == dungeon_card.STAGE_FLAGS_OPCODE
        body = (dungeon_clear.STAGE_FLAGS_BODY if flags
                else dungeon_clear.STAGE_BODY)
        frames = [(opcode, dungeon_clear.padded(opcode, body))]
        if flags:
            frames.append((dungeon_card.COMMIT_OPCODE,
                           dungeon_clear.padded(dungeon_card.COMMIT_OPCODE,
                                                dungeon_card.state_body(
                                                    result.paid_item if result
                                                    is not None else None))))
        sent, nbytes = await self._write_frames(writer, conn, frames)
        self.log.debug("DISPATCH",
                       f"conn={conn} {opcode} -> {sent} frame(s) {nbytes}B "
                       f"state={state}->{state}")
        return nbytes

    async def _card_commit(self, writer: asyncio.StreamWriter, conn: int,
                           body: bytes, session: dungeon_run.DungeonSession,
                           character: int, state: str) -> int:
        """`(1,71)`: a flip's commit -- its two frames, its write, its line.

        The side is all the request carries; a fed commit writes exactly what
        the reference wrote and adopts its uuid, an unfed one moves the purse
        by its own card's delta and grants no item
        (`dungeon_card.resolution`).
        """
        plain = tiles.decrypt_body(tiles.algo_id(dungeon_card.COMMIT_OPCODE.sub),
                                   body)
        grants = self.oracle_commits.get(plain)
        grant = grants.pop(0) if grants else None
        result = dungeon_card.resolution(self._db, session, character,
                                         dungeon_card.side_of(plain), grant,
                                         int(time.time()))
        self.log.info("DUNGEON-CARD-71", f"conn={conn} {result.note}")
        sent, nbytes = await self._write_frames(writer, conn, result.frames)
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_card.COMMIT_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _dungeon_settle(self, writer: asyncio.StreamWriter, conn: int,
                              body: bytes, session: dungeon_run.DungeonSession,
                              character: int, state: str) -> int:
        """`(1,72)`: the card screen's close (`dungeon_settle.resolution`).

        Up to two lines go out before the frames: the story retry's, and the
        note -- which the reference leaves off the send that follows a story
        settle, the one `(1,72)` in the corpus with no line at all.
        """
        plain = tiles.decrypt_body(tiles.algo_id(dungeon_settle.SETTLE_OPCODE.sub),
                                   body)
        result = dungeon_settle.resolution(
            self._db, session, characters.by_id(self._db, character), plain)
        if result.story is not None:
            self.log.info("SETTLEMENT-72", f"conn={conn} {result.story}")
        if result.note is not None:
            self.log.info("SETTLEMENT-72", f"conn={conn} {result.note}")
        sent, nbytes = await self._write_frames(writer, conn, result.frames)
        self.log.debug("DISPATCH",
                       f"conn={conn} {dungeon_settle.SETTLE_OPCODE} -> {sent} "
                       f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    def _fed_write(self, plain: bytes, character: int, now: int) -> None:
        """Apply the row a fed `(1,34)` left, keyed by the request.

        A live server derives the reward rows; until that chain exists a
        replay is handed them from the reference's own log, so an unfed
        finish writes nothing.
        """
        writes = self.oracle_rewards.get(plain)
        if writes:
            dungeon_reward.apply(self._db, character, writes.pop(0), now)

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
        if cargo.is_cargo(request):
            return await self._cargo_move(writer, conn, request, character,
                                          state)
        outcome = inventory.execute(self._db, character, request)
        frames = [(inventory.OPCODE, request.ack(ok=outcome.ok, code=outcome.code))]
        note = outcome.note
        panel = False
        if outcome.ok and request.cross_container:
            # After the write, so the slot frames and the record stream both
            # read the state the move left behind.
            summary = characters.by_id(self._db, character)
            refreshed = refresh.build(self._db, character, request, summary)
            frames += refreshed.frames
            note = f"{note}; {refreshed.note}"
            panel = refreshed.panel
        self.log.info(outcome.tag, f"conn={conn} {note}")
        if panel:
            # The reference's own line right after an accepted cross move, on
            # exactly the characters whose panel went out (refresh.build).
            self.log.info("EQUIPMENT-SPECIFICITY",
                          f"conn={conn} character={character} converted=0 "
                          f"points={refresh.PANEL_POINTS} group=0 options=0")
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

    async def _cargo_move(self, writer: asyncio.StreamWriter, conn: int,
                          request: inventory.MoveRequest, character: int,
                          state: str) -> int:
        """`(1,19)` with a list 2 or 12 end: the CARGO-MOVE line, four frames.

        No EQUIPMENT-SPECIFICITY line and no USERINFO resend come with it; the
        first `(0,14)` is the emptied source, the second the moved row.  The
        refusals have no sample -- `game.item.cargo` says which and why they
        answer nothing.
        """
        outcome = cargo.execute(self._db, self._account, character, request)
        if not outcome.ok:
            self.log.warn(cargo.TAG, f"conn={conn} {request.describe()} "
                                     f"refused: {outcome.reason}; not stored")
            return 0
        self.log.info(cargo.TAG, cargo.note_line(conn, self._account, character,
                                                 request))
        sent = nbytes = 0
        for opcode, plain_body in cargo.frames(request, outcome):
            wire = self._encode_generated(opcode, plain_body)
            await sleep_gap(self.write_gap)
            writer.write(wire)
            await writer.drain()
            sent += 1
            nbytes += len(wire)
            self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {inventory.OPCODE} -> {sent} "
                                   f"frame(s) {nbytes}B state={state}->{state}")
        return nbytes

    async def _client_settings_save(self, writer: asyncio.StreamWriter, conn: int,
                                    body: bytes, character: int | None,
                                    state: str,
                                    session: dungeon_run.DungeonSession | None) -> int:
        """`(1,197)`: store the client's settings blob, then the CLASS-AVATAR ack.

        The store and its `saved C1/197` line always happen -- they precede
        the reference's gates.  The `(0,343)` ack and its `CLASS-AVATAR` line
        ride a live character with no dungeon run open: the reference's gates
        (`0x3d21f9`) go silent inside one, which is what its own silent sixth
        `(1,197)` (09-28 21:13:22.742) did.  Without a character the gates
        precede even the store.  `clientsettings.py` has the full reading.
        """
        if character is None:
            return 0
        plain = tiles.decrypt_body(tiles.algo_id(clientsettings.SAVE_OPCODE.sub),
                                   body)
        options = clientsettings.parse_save(plain)
        if options is None:
            self.log.warn("CLIENT-SETTINGS",
                          f"conn={conn} C1/197 body={len(plain)}B is not the "
                          f"{clientsettings.ROW_SIZE}B blob; not stored "
                          f"plain={_dump_plain(plain)}")
            return 0
        clientsettings.save(self._db, self._account, options)
        self.log.info("CLIENT-SETTINGS",
                      f"conn={conn} {clientsettings.save_line(options)}")
        if session is not None and session.run is not None:
            return 0
        key = self._character_key(character)
        preference = clientsettings.preference(options)
        flags = clientsettings.flags(preference)
        self.log.info(clientsettings.AVATAR_TAG,
                      f"conn={conn} "
                      f"{clientsettings.avatar_line(key, preference, flags)}")
        wire = self._encode_generated(
            clientsettings.SAVE_REPLY_OPCODE,
            clientsettings.avatar_reply_body(key, flags))
        await sleep_gap(self.write_gap)
        writer.write(wire)
        await writer.drain()
        self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {clientsettings.SAVE_OPCODE} -> "
                                   f"1 frame(s) {len(wire)}B state={state}->{state}")
        return len(wire)

    async def _item_use(self, writer: asyncio.StreamWriter, conn: int,
                        body: bytes, character: int, state: str) -> int:
        """`(1,44)`: one unit off the stack, three frames back.

        Both refusals -- an address that holds nothing (or another item), and
        the last unit -- write nothing and answer nothing; `game.item.use`
        says which is which and why the second one is not guessed.
        """
        plain = tiles.decrypt_body(tiles.algo_id(use.OPCODE.sub), body)
        request = use.UseRequest.parse(plain)
        self.log.info(use.TAG, request.request_line(conn, plain))
        outcome = use.execute(self._db, character, request)
        if not outcome.ok:
            self.log.warn(use.TAG, f"conn={conn} item {request.item_id} at "
                                   f"slot {request.slot_index} "
                                   f"(list={request.list_type}) refused: "
                                   f"{outcome.reason}; not stored "
                                   f"plain={_dump_plain(plain)}")
            return 0
        self.log.info(use.TAG, request.outcome_line(conn, outcome.before,
                                                    outcome.after.count))
        sent = nbytes = 0
        for opcode, plain_body in use.frames(request, plain, outcome.after):
            wire = self._encode_generated(opcode, plain_body)
            await sleep_gap(self.write_gap)
            writer.write(wire)
            await writer.drain()
            sent += 1
            nbytes += len(wire)
            self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {use.OPCODE} -> {sent} frame(s) "
                                   f"{nbytes}B state={state}->{state}")
        return nbytes

    async def _npc_buy(self, writer: asyncio.StreamWriter, conn: int,
                       body: bytes, character: int, state: str) -> int:
        """`(1,21)`: charge the gold/materials, land the item, answer.

        Two INFO lines under the tag, the request then the outcome, both the
        reference's own wording.  A refusal writes nothing and answers
        nothing; `game.shop.buy` says which and why.  So does a body of the
        wrong size: the reference's own line for one is `rejected=malformed
        request error=250`, with nothing built after it (09-25 19:39:31/42/49).
        """
        try:
            plain = tiles.decrypt_body(tiles.algo_id(buy.OPCODE.sub), body)
            request = buy.BuyRequest.parse(plain)
        except ValueError:
            self.log.info(buy.TAG,
                          f"conn={conn} rejected=malformed request error=250")
            return 0
        self.log.info(buy.TAG, request.request_line(conn))
        outcome = buy.execute(self._db, self._account, character, request)
        if not outcome.ok:
            self.log.warn(buy.TAG, f"conn={conn} shop={request.shop_id} "
                                   f"item={request.item_id} refused: "
                                   f"{outcome.reason}; not stored")
            return 0
        self.log.info(buy.TAG, buy.outcome_line(conn, request, outcome))
        sent = nbytes = 0
        for opcode, plain_body in buy.frames(outcome):
            wire = self._encode_generated(opcode, plain_body)
            await sleep_gap(self.write_gap)
            writer.write(wire)
            await writer.drain()
            sent += 1
            nbytes += len(wire)
            self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {buy.OPCODE} -> {sent} frame(s) "
                                   f"{nbytes}B state={state}->{state}")
        return nbytes

    async def _npc_sell(self, writer: asyncio.StreamWriter, conn: int,
                        body: bytes, character: int, state: str) -> int:
        """`(1,22)`: take the rows out of list 0, pay the gold, answer.

        Two INFO lines under the tag, the request then the sales, both the
        reference's own wording.  A refusal writes nothing and answers
        nothing; `game.shop.sell` says which.  A body of the wrong size gets
        the `rejected=malformed request error=250` line the other write
        paths use.
        """
        try:
            plain = tiles.decrypt_body(tiles.algo_id(sell.OPCODE.sub), body)
            request = sell.SellRequest.parse(plain)
        except ValueError:
            self.log.info(sell.TAG,
                          f"conn={conn} rejected=malformed request error=250")
            return 0
        self.log.info(sell.TAG, request.request_line(
            conn, sell.shop_type(request.shop), plain))
        outcome = sell.execute(self._db, self._account, character, request)
        if not outcome.ok:
            self.log.warn(sell.TAG, f"conn={conn} shop={request.shop} "
                                    f"refused: {outcome.reason}; not stored")
            return 0
        self.log.info(sell.TAG, sell.outcome_line(conn, outcome))
        sent = nbytes = 0
        for opcode, plain_body in sell.frames(outcome):
            wire = self._encode_generated(opcode, plain_body)
            await sleep_gap(self.write_gap)
            writer.write(wire)
            await writer.drain()
            sent += 1
            nbytes += len(wire)
            self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {sell.OPCODE} -> {sent} frame(s) "
                                   f"{nbytes}B state={state}->{state}")
        return nbytes

    async def _cera_buy(self, writer: asyncio.StreamWriter, conn: int,
                        body: bytes, character: int, state: str) -> int:
        """`(1,64)`: charge the cera, deliver the commodity, answer.

        Two INFO lines, the request then whichever family the delivered item
        is -- the item/ticket line, a warehouse kit's own `CARGO-BUY` tag, or
        the contract's activation line.  A refusal writes nothing and answers
        nothing; `game.shop.cera` says which.  A body of the wrong size gets
        the `rejected=malformed request error=250` line the other write paths
        use.
        """
        try:
            plain = tiles.decrypt_body(tiles.algo_id(cera.OPCODE.sub), body)
            request = cera.BuyRequest.parse(plain)
        except ValueError:
            self.log.info(cera.TAG,
                          f"conn={conn} rejected=malformed request error=250")
            return 0
        self.log.info(cera.TAG, request.request_line(conn, plain))
        outcome = cera.execute(self._db, self._account, character, request)
        if not outcome.ok:
            self.log.warn(cera.TAG, f"conn={conn} commodity={request.commodity} "
                                    f"refused: {outcome.reason}; not stored")
            return 0
        if outcome.family == cera.CARGO_FAMILY:
            self.log.info(cera.CARGO_TAG, cera.cargo_line(conn, outcome))
        elif outcome.family == cera.CONTRACT_FAMILY:
            self.log.info(cera.TAG, cera.contract_line(conn, outcome))
        else:
            self.log.info(cera.TAG, cera.item_line(conn, outcome))
        self.log.info(cera.TAG, cera.delivered_line(conn, outcome))
        sent = nbytes = 0
        for opcode, plain_body in cera.frames(outcome):
            wire = self._encode_generated(opcode, plain_body)
            await sleep_gap(self.write_gap)
            writer.write(wire)
            await writer.drain()
            sent += 1
            nbytes += len(wire)
            self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {cera.OPCODE} -> {sent} frame(s) "
                                   f"{nbytes}B state={state}->{state}")
        return nbytes

    async def _cera_poll(self, writer: asyncio.StreamWriter, conn: int,
                         state: str) -> int:
        """`(1,63)`: the balance poll an open shop sends once a minute.

        The body is empty and ignored; the answer is the same `(0,53)` the
        town entry's frame 14 carries, so both read the account row the same
        way.
        """
        balance = accounts.cera(self._db, self._account) or 0
        self.log.info(cera.POLL_TAG, cera.poll_line(conn, self._account, balance))
        wire = self._encode_generated(cera.BALANCE_OPCODE,
                                      cera.balance_body(balance))
        await sleep_gap(self.write_gap)
        writer.write(wire)
        await writer.drain()
        self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {cera.POLL_OPCODE} -> "
                                   f"1 frame(s) {len(wire)}B state={state}->{state}")
        return len(wire)

    async def _npc_redeem(self, writer: asyncio.StreamWriter, conn: int,
                          state: str,
                          session: dungeon_run.DungeonSession | None) -> int:
        """`(1,309)`: the buyback list, empty because the reference's is.

        Silent while a run is live: the handler at `0x2c89b0` answers only when
        its gates hold -- among them two pointers being NULL and the same pair
        guarding the town-move handler, whose own literal names the state
        "outside town movement state".  All four times the 09-28 session sent
        this with a dungeon run open it got nothing back and the reference
        logged nothing; every answered send (129 lines) is a town shopping
        round.  `session.run` is that same reading -- non-NULL for exactly as
        long as the character is inside the instance.
        """
        if session is not None and session.run is not None:
            return 0
        self.log.info(redeem.TAG, f"conn={conn} {redeem.NOTE}")
        wire = self._encode_generated(redeem.REPLY_OPCODE, redeem.REPLY_BODY)
        await sleep_gap(self.write_gap)
        writer.write(wire)
        await writer.drain()
        self.log.packet(conn, frame.Link.GAME_S2C, wire, from_client=False)
        self.log.debug("DISPATCH", f"conn={conn} {redeem.OPCODE} -> "
                                   f"1 frame(s) {len(wire)}B state={state}->{state}")
        return len(wire)

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
