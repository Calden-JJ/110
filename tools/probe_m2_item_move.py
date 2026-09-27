#!/usr/bin/env python3
"""Drive the reference's (1,19) ITEM-MOVE with *constructed* C->S frames.

M2.0 (route A, answer: yes).  The rewrite has no client-side frame builder,
and the one field it cannot recompute is game-c2s `[7:11]` (four hash variants
all score 0/221 on the capture; see references/protocol.md).  This probe fills
it with zeros and replays the captured 09-26 session with constructed frames
spliced in right before its final `(1,3)`.  Measured 2026-09-27: the reference
took the frame, re-parsed the body field for field, and *executed* the move --
`[7:11]` is not validated, and neither is the spliced-in seq numbering.

M2.1 (oracle).  With the route open, send a whole *script* of moves in one
session and mine the reference's own record for the handler spec: its
`ITEM-MOVE-19 ... plain=` outcome lines and its `S->C game ... hex=` replies
both land in the reference log, and the cipher is known, so the hex decrypts.
The body layout is the one read off the 09-25 `plain=` oracle (576 samples,
all consistent, and the reference's re-parse of a constructed body matches)::

    u8 src.list | u16le src.slot | u32le src.iv
    u32le count
    u8 dst.list | u16le dst.slot | u32le dst.iv
    14B tail, constant across all samples: 00000000ffffffff000000000000

`DEFAULT_MOVES` is the round-1 matrix.  It is written against the current save
(character 1, XRenYing): list 0 has 101011203 at slot 9 (iv 668198703),
101011025 at slot 10, stackable 2660671 at slot 3, and empty slots 6/7/8.
Each move is reversible in principle, but the save *will* be mutated -- back
up the `uslocalserver.db*` set first and restore it after, and point the
reference's per-user `server.json` logDirectory outside the corpus `Logs/`.

    python tools/probe_m2_item_move.py --dry-run
    python tools/probe_m2_item_move.py --host 192.168.1.6 --port 10013
    python tools/probe_m2_item_move.py --moves moves.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
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
ITEM_MOVE_SUB = 19
FIRST_SEQ = 220
TAIL = bytes.fromhex("00000000ffffffff000000000000")

#: (src, dst, count, what the move asks).  Chosen so each answer names one
#: unknown: direction handling, swap-vs-move when both ends are occupied, the
#: both-empty error, whether `iv` is validated, and `count` on non-stackables.
DEFAULT_MOVES: tuple[tuple[tuple[int, int, int], tuple[int, int, int], int, str], ...] = (
    ((0, 6, 0), (0, 9, 668198703), 0, "move dst into empty src (M2.0 baseline)"),
    ((0, 6, 668198703), (0, 9, 0), 0, "reverse: move src into empty dst"),
    ((0, 9, 668198703), (0, 10, 704166429), 0, "both ends occupied"),
    ((0, 9, 704166429), (0, 10, 668198703), 0, "undo, if the previous was a swap"),
    ((0, 7, 0), (0, 8, 0), 0, "both ends empty"),
    ((0, 8, 0), (0, 9, 668198703), 0, "move dst into empty src, again"),
    ((0, 8, 668198703), (0, 9, 0), 0, "and back, to restore the baseline"),
    ((0, 9, 12345), (0, 6, 0), 0, "wrong src iv while both look occupied"),
    ((0, 6, 0), (0, 9, 0), 0, "dst iv 0 while the slot is occupied"),
    ((0, 9, 668198703), (0, 9, 668198703), 0, "src == dst"),
)


def item_move_body(src: tuple[int, int, int], dst: tuple[int, int, int],
                   count: int) -> bytes:
    s_list, s_slot, s_iv = src
    d_list, d_slot, d_iv = dst
    return (struct.pack("<BHI", s_list, s_slot, s_iv)
            + struct.pack("<I", count)
            + struct.pack("<BHI", d_list, d_slot, d_iv)
            + TAIL)


def parse_item_move(body: bytes) -> str:
    """Read the layout back, so the probe's own output can be checked."""
    if len(body) != 32:
        return f"<{len(body)}B, not 32>"
    s_list, s_slot, s_iv = body[0], struct.unpack_from("<H", body, 1)[0], \
        struct.unpack_from("<I", body, 3)[0]
    count = struct.unpack_from("<I", body, 7)[0]
    d_list, d_slot, d_iv = body[11], struct.unpack_from("<H", body, 12)[0], \
        struct.unpack_from("<I", body, 14)[0]
    tail_ok = body[18:] == TAIL
    return (f"src=(list={s_list},slot={s_slot},iv={s_iv}) "
            f"dst=(list={d_list},slot={d_slot},iv={d_iv}) count={count} "
            f"tail={'ok' if tail_ok else body[18:].hex()}")


def build_item_move(src, dst, count, seq: int, word: bytes = b"\x00\x00\x00\x00") -> bytes:
    body = item_move_body(src, dst, count)
    encrypted = tiles.encrypt_body(tiles.algo_id(ITEM_MOVE_SUB), body)
    opcode = frame.Opcode(1, ITEM_MOVE_SUB, frame.OpcodeEncoding.U8_U16LE, True)
    return frame.build(frame.Link.GAME_C2S, opcode, encrypted, seq=seq,
                       trailer=word + struct.pack("<H", seq))


def load_moves(path: Path) -> tuple[tuple[tuple[int, int, int], tuple[int, int, int], int, str], ...]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return tuple((tuple(m["src"]), tuple(m["dst"]), int(m.get("count", 0)),
                  m.get("note", "")) for m in doc)


def capture_frames(corpus: Path) -> list[bytes]:
    s = logs.corpus_session(corpus, "game")
    return [p.frame_bytes for p in logs.iter_packets(corpus)
            if p.hex is not None and p.link == "game" and p.direction == "C->S"
            and s.first <= p.line_no <= s.last]


def replace_seq(raw: bytes, seq: int) -> bytes:
    return raw[:11] + struct.pack("<H", seq) + raw[13:]


def splice(corpus: Path, injects: list[bytes]) -> list[bytes]:
    """The capture's frames with `injects` before the trailing (1,3).

    The injected frames take over seqs 220..220+N-1 and (1,3) is renumbered to
    220+N, so the counter stays gapless -- the reference may or may not care,
    and a contiguous counter is what a real client would have sent.
    """
    frames = capture_frames(corpus)
    last = frames[-1]
    if (last[0], struct.unpack_from("<H", last, 1)[0]) != (1, 3):
        raise SystemExit(f"capture no longer ends with (1,3): "
                         f"({last[0]},{struct.unpack_from('<H', last, 1)[0]})")
    return frames[:-1] + injects + [replace_seq(last, FIRST_SEQ + len(injects))]


async def exchange(host: str, port: int, payloads: list[bytes],
                   idle: float, send_gap: float) -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    got = bytearray()

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
            got += chunk
    finally:
        if not sender.done():
            sender.cancel()
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    return bytes(got)


def report_s2c(data: bytes) -> None:
    """Decrypt every S->C frame the exchange brought back and show it."""
    stream = frame.FrameStream(frame.Link.GAME_S2C)
    stream.feed(data)
    n = 0
    print(f"  {len(data)}B back, decoded:")
    while (f := stream.next_frame()) is not None:
        plain = tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)
        head = plain[:16].hex() if len(plain) > 16 else plain.hex()
        print(f"    [{n:>3}] {f.opcode} body={len(f.body)}B plain={len(plain)}B {head}"
              f"{'...' if len(plain) > 16 else ''}")
        n += 1


def build_moves(moves) -> list[bytes]:
    return [build_item_move(src, dst, count, FIRST_SEQ + i)
            for i, (src, dst, count, _) in enumerate(moves)]


async def main_async(args: argparse.Namespace) -> int:
    moves = load_moves(args.moves) if args.moves else DEFAULT_MOVES
    injects = build_moves(moves)
    print(f"{len(moves)} move(s), seqs {FIRST_SEQ}..{FIRST_SEQ + len(injects) - 1}")

    # Round-trip every frame through the framer before anything goes on the wire.
    for i, ((src, dst, count, note), raw) in enumerate(zip(moves, injects)):
        parsed = frame.parse(frame.Link.GAME_C2S, raw)
        back = parse_item_move(tiles.decrypt_body(tiles.algo_id(ITEM_MOVE_SUB), parsed.body))
        print(f"  [{i:>2}] seq={parsed.seq} {len(raw)}B src={tuple(src)} dst={tuple(dst)} "
              f"count={count}  {note}")
        print(f"       reparse -> {parsed.opcode} body={len(parsed.body)}B {back}")
    if args.dry_run:
        print("dry run: nothing sent")
        return 0

    payloads = splice(args.corpus, injects)
    print(f"\nreplaying {len(payloads)} frames to {args.host}:{args.port} "
          f"(injected at indexes {len(payloads) - 1 - len(injects)}..{len(payloads) - 2}) ...")
    got = await exchange(args.host, args.port, payloads, args.idle, args.send_gap)
    report_s2c(got)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="192.168.1.6")
    ap.add_argument("--port", type=int, default=10013)
    ap.add_argument("--corpus", type=Path, default=CORPUS)
    ap.add_argument("--moves", type=Path, help="JSON list of {src,dst,count,note}")
    ap.add_argument("--dry-run", action="store_true")
    # 1.0 was too short: the reference spends ~1s building the (1,143) town
    # burst and reads nothing meanwhile, so a 1s silence timeout closes the
    # connection before the spliced frames are ever reached (rx=8192B, 40/222
    # frames, `closed with 48B incomplete frame`).
    ap.add_argument("--idle", type=float, default=5.0)
    ap.add_argument("--send-gap", type=float, default=0.002)
    args = ap.parse_args(argv)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
