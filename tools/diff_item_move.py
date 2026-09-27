#!/usr/bin/env python3
"""Diff the rewrite's `(1,19)` responses against the reference's, round by round.

The oracle log holds four driven sessions (`probe_m2_item_move.py` against the
real server, 2026-09-27): conn=1 the round-1 matrix, conn=2 the equipment
(cross-container) round, conn=3 the count round, conn=5 the edge matrix.  Each
session's `C->S game ... (1,19)` frames are complete, so this tool replays
*those exact bytes* -- not a reconstruction -- at a rewrite `GameServer` on a
fresh copy of the save, and lines the whole response up with the reference's in
order: the ack, then every refresh frame whose opcode belongs to the tail set,
which is how the oracle's own byte totals (`DISPATCH ... -> 8 frame(s) 6576B`)
account for them.

Every round starts from the restored baseline save (round 1's own last moves
restore it; the oracle run kept a backup for the others), so the tool copies
the save per round rather than mutating one.

Two deviations are expected and reported, not failed:

  * the version u16 -- `(0,2)[134:136]`, the giant's `(0,2)[24:26]` and
    `(0,2265)[4:6]` -- is a stand-in (`refresh.version`), so those bytes are
    masked before comparing.  The tool instead asserts each side's version is
    a pure function of the worn record stream (one state, one value) and that
    a response's three carriers agree;
  * the log truncates the giant at 4096B (`packetHexMaxBytes`) while its
    header still declares the true size, so the giant is compared up to the
    cut *plus* a declared-size equality.  Its last ~430 bytes -- the tail
    region -- are pinned by the 101 probe bins instead (`_m23/giant_model.py`).

    python tools/diff_item_move.py
    python tools/diff_item_move.py --oracle dfo-server/Logs-m2oracle/server-20260927.log
"""
from __future__ import annotations

import argparse
import asyncio
import binascii
import io
import shutil
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.game.item import giant, inventory, refresh  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402
from uslocalserver.server import game  # noqa: E402
from uslocalserver.server.logfile import Log  # noqa: E402

DEFAULT_ORACLE = paths.REPO_ROOT / "Logs-m2oracle" / "server-20260927.log"
PORT = 10013
ITEM_MOVE = (1, 19)
#: What may follow the ack on the same connection; anything else ends a group.
TAIL_OPCODES = frozenset({(0, 14), (0, 2), (0, 2265), (0, 2432), (0, 1361)})


@dataclass(frozen=True, slots=True)
class Frame:
    main: int
    sub: int
    plain: bytes
    wire: int               # bytes the log/socket carried
    true_size: int          # what the frame declares; > wire when truncated

    @property
    def opcode(self) -> tuple[int, int]:
        return (self.main, self.sub)


def _oracle_frame(f: frame.Frame, p: logs.PacketRecord) -> Frame:
    plain = tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)
    return Frame(f.opcode.main, f.opcode.sub, plain,
                 len(p.frame_bytes), p.hex.full_size)


def oracle_rounds(path: Path) -> dict[int, list[tuple[bytes, list[Frame]]]]:
    """{conn: [(request wire, [ack + tail frames]), ...]} in the log's order.

    Truncated dumps are kept -- the giant arrives cut at `packetHexMaxBytes` --
    but never filtered on: `frame_bytes` shorter than the declared size is a
    logging limit, not a wire fact.
    """
    rounds: dict[int, list[tuple[bytes, list[Frame]]]] = {}
    pending: dict[int, list[bytes]] = {}
    open_group: dict[int, list[Frame] | None] = {}
    for p in logs.iter_packets(path):
        if p.link != "game" or p.hex is None:
            continue
        if p.direction == "C->S":
            f = frame.parse(frame.Link.GAME_C2S, p.frame_bytes)
            if (f.opcode.main, f.opcode.sub) == ITEM_MOVE:
                pending.setdefault(p.conn, []).append(p.frame_bytes)
                open_group[p.conn] = None
        else:
            # `expect_size` + non-strict: the giant arrives cut at the log's
            # 4096B limit, and this parse is only needed for the opcode and the
            # first plaintext byte anyway.
            f = frame.parse(frame.Link.GAME_S2C, p.frame_bytes, strict=False,
                            expect_size=p.hex.full_size)
            key = (f.opcode.main, f.opcode.sub)
            if key == ITEM_MOVE:
                group = [_oracle_frame(f, p)]
                rounds.setdefault(p.conn, []).append((pending[p.conn].pop(0), group))
                open_group[p.conn] = group
            elif key in TAIL_OPCODES and open_group.get(p.conn):
                open_group[p.conn].append(_oracle_frame(f, p))
    left = {c: len(v) for c, v in pending.items() if v}
    if left:
        raise SystemExit(f"requests without an ack: {left}")
    return rounds


def save_copy(src: Path) -> Path:
    dst = Path(tempfile.mkdtemp(prefix="dfo-item-move-diff-")) / "uslocalserver.db"
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(src) + suffix)
        if p.exists():
            shutil.copy2(p, Path(str(dst) + suffix))
    return dst


def decrypt_request(wire: bytes) -> inventory.MoveRequest:
    f = frame.parse(frame.Link.GAME_C2S, wire)
    return inventory.MoveRequest.parse(
        tiles.decrypt_body(tiles.algo_id(ITEM_MOVE[1]), f.body))


async def replay(save: Path, requests: list[bytes]) -> list[list[Frame]]:
    """`(1,4)` to name the character, then the round's requests verbatim.

    The requests keep the oracle run's own seq numbers: neither server
    validates them (M2.0), and the point is to replay the bytes the reference
    answered, down to the frame.
    """
    log = Log(stream=io.StringIO())
    server = game.GameServer("127.0.0.1", {PORT: game.GAME_PORTS[PORT]},
                             game.GameScript.load(), log, save_db=save,
                             unix_seconds=1_789_824_022, write_gap=0.0)
    await server.start()
    try:
        port = server.ports_bound()[0]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        select = frame.build(frame.Link.GAME_C2S,
                             frame.Opcode(1, 4, frame.OpcodeEncoding.U8_U16LE, True),
                             tiles.encrypt_body(tiles.algo_id(4), bytes(16)), seq=0)
        writer.write(select)
        for raw in requests:
            writer.write(raw)
        await writer.drain()
        got = bytearray()
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(1 << 16), timeout=1.0)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            got += chunk
        writer.close()
    finally:
        server.close()
        log.close()
    stream = frame.FrameStream(frame.Link.GAME_S2C)
    stream.feed(bytes(got))
    groups: list[list[Frame]] = []
    open_group: list[Frame] | None = None
    while (f := stream.next_frame()) is not None:
        wire = f.rebuild()
        plain = tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)
        key = (f.opcode.main, f.opcode.sub)
        if key == ITEM_MOVE:
            open_group = [Frame(key[0], key[1], plain, len(wire), len(wire))]
            groups.append(open_group)
        elif key in TAIL_OPCODES and open_group is not None:
            open_group.append(Frame(key[0], key[1], plain, len(wire), len(wire)))
    return groups


def masked(f: Frame) -> bytes:
    """The frame's plaintext with the version stand-in's bytes zeroed."""
    body = bytearray(f.plain)
    if f.opcode == (0, 2) and body and body[0] == 0x00:
        body[refresh.VERSION_AT:refresh.VERSION_AT + 2] = bytes(2)
    elif f.opcode == (0, 2) and body and body[0] == 0x01:
        body[giant.VERSION_AT:giant.VERSION_AT + 2] = bytes(2)
    elif f.opcode == (0, 2265):
        body[4:6] = bytes(2)
    return bytes(body)


def version_of(f: Frame) -> int | None:
    if f.opcode == (0, 2) and f.plain and f.plain[0] == 0x00:
        return struct.unpack_from("<H", f.plain, refresh.VERSION_AT)[0]
    if f.opcode == (0, 2) and f.plain and f.plain[0] == 0x01:
        return struct.unpack_from("<H", f.plain, giant.VERSION_AT)[0]
    if f.opcode == (0, 2265):
        return struct.unpack_from("<H", f.plain, 4)[0]
    return None


class Versions:
    """Every version seen, keyed by the worn-record stream it went with.

    The whole point of the stand-in is that the *reference's* value is a pure
    function of the state (same records -> same u16, four sessions running);
    this records both sides' tables so an impurity on either one fails.
    """

    def __init__(self) -> None:
        self.by_state: dict[tuple[int, int], set[int]] = {}

    def add(self, userinfo: Frame) -> None:
        count = userinfo.plain[refresh.COUNT_AT]
        start = refresh.USERINFO_HEADER_SIZE
        records = userinfo.plain[start:start + refresh.RECORD_SIZE * count]
        key = (count, binascii.crc32(records) & 0xFFFF)
        self.by_state.setdefault(key, set()).add(version_of(userinfo))

    def impure(self) -> dict[tuple[int, int], set[int]]:
        return {k: v for k, v in self.by_state.items() if len(v) > 1}

    def describe(self) -> str:
        return ", ".join(f"{n}w/{c:#06x}->{[hex(v) for v in sorted(vs)]}"
                         for (n, c), vs in sorted(self.by_state.items()))


def first_diffs(a: bytes, b: bytes, limit: int = 4) -> str:
    out = []
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            out.append(f"[{i}] {x:#04x} vs {y:#04x}")
            if len(out) == limit:
                break
    if len(a) != len(b):
        out.append(f"len {len(a)} vs {len(b)}")
    return "; ".join(out) or "identical"


def compare_side(want: list[Frame], got: list[Frame],
                 ref_versions: Versions, our_versions: Versions,
                 problems: list[str]) -> None:
    """Pairwise compare one response.

    A frame the log truncated (the giant) is compared up to the bytes that
    survived the dump, on the strength of its header's declared size matching
    the rewrite's full one; the cut bytes themselves are the bins' job.
    """
    if len(want) != len(got):
        problems.append(f"frame count: reference {len(want)} vs rewrite {len(got)}")
        return
    for i, (a, b) in enumerate(zip(want, got)):
        if a.opcode != b.opcode:
            problems.append(f"frame {i}: opcode {a.opcode} vs {b.opcode}")
            continue
        if a.opcode == (0, 2) and a.plain and a.plain[0] == 0x00:
            ref_versions.add(a)
            our_versions.add(b)
        if a.true_size != b.true_size:
            problems.append(f"frame {i} {a.opcode}: declared {a.true_size}B vs "
                            f"rewrite {b.true_size}B")
        ref_bytes = masked(a)
        cut = masked(b)[:len(ref_bytes)]
        if ref_bytes != cut:
            problems.append(f"frame {i} {a.opcode}: {first_diffs(ref_bytes, cut)}")
    # the three version carriers of one response must agree, on each side
    for side, frames in (("reference", want), ("rewrite", got)):
        vs = [v for v in (version_of(f) for f in frames) if v is not None]
        if len(set(vs)) > 1:
            problems.append(f"{side} version mismatch within the response: "
                            f"{[hex(v) for v in vs]}")
    cut = sum(f.true_size - f.wire for f in want)
    label_cut = f" ({cut}B past the log's dump limit)" if cut else ""
    print(f"        {len(want)} frame(s) {sum(f.true_size for f in want)}B reference"
          f" vs {len(got)} frame(s) {sum(g.wire for g in got)}B rewrite{label_cut}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    ap.add_argument("--save", type=Path, default=paths.SAVE_DB,
                    help="baseline save; each round replays on a copy of it")
    args = ap.parse_args(argv)

    rounds = oracle_rounds(args.oracle)
    print(f"{args.oracle.name}: {sum(len(v) for v in rounds.values())} move(s) "
          f"over {len(rounds)} session(s)  {dict((c, len(v)) for c, v in rounds.items())}")
    ref_versions = Versions()
    our_versions = Versions()
    refused = 0
    for conn, pairs in rounds.items():
        save = save_copy(args.save)
        try:
            groups = asyncio.run(replay(save, [raw for raw, _ in pairs]))
        finally:
            shutil.rmtree(save.parent, ignore_errors=True)
        print(f"\nconn={conn}  {len(pairs)} request(s), {len(groups)} response(s)")
        if len(groups) != len(pairs):
            print(f"  !! response count differs")
            refused += abs(len(groups) - len(pairs))
        for i, (pair, got) in enumerate(zip(pairs, groups)):
            raw, want = pair
            request = decrypt_request(raw)
            problems: list[str] = []
            print(f"  [{i:>2}] {request.describe()}")
            compare_side(want, got, ref_versions, our_versions, problems)
            if problems:
                refused += 1
                for p in problems:
                    print(f"        MISMATCH {p}")
    print()
    bad = ref_versions.impure(), our_versions.impure()
    print(f"reference versions: {ref_versions.describe()}")
    print(f"rewrite   versions: {our_versions.describe()}")
    if bad[0] or bad[1]:
        print(f"!! version is not a pure function of the state: {bad}")
        refused += 1
    print(f"\n{refused} unexplained mismatch(es)")
    return 1 if refused else 0


if __name__ == "__main__":
    raise SystemExit(main())
