#!/usr/bin/env python3
"""Turn the 2026-09-28 dungeon session into the committed M3 fixture.

`Logs-dungeon/server-20260928.log` is the user's own play session against the
reference (`tools/diff_dungeon.py` explains it); logs are not in the repo, so
everything the M3 tests need has to be written down here the way
`extract_game_replies.py` writes down the M2 corpus.

The shape is the same one too -- one entry per C->S opcode, one *run* per
frame the client actually sent, each carrying the request, the frames it drew,
the reference's own prose and the state it left the session in -- with two
differences the dungeon forces:

* A played session is not a script.  The M2 corpus sends `(1,36)` five times
  with the reply chosen by *how many times it has been sent*; here the client
  sends `(1,39)` 79 times with 79 different monster sequences, and the n-th
  run is only meaningful as a test vector.  So every run stores its request
  wire as well, and the fixture is an oracle for tests rather than a script
  the server serves.
* Most runs draw nothing: **414 of the 612**.  `(1,2126)` 124 (no handler at
  all), `(1,585)` 110 (LEGACY-QUERY), `(1,283)` 59, `(1,35)` 36 (throttled),
  then a long tail that is silent on some sends and answers on others --
  `(1,15)` and `(1,191)`, for instance.  They are kept: silence is a claim
  about the reference, and a rewrite that answers where the reference did not
  is as wrong as one that stays quiet where it spoke.

A run's `request_wire_hex` is the **whole C->S frame**, header and ciphertext,
so a test decodes it the way the server does -- parse, then decrypt::

    f = frame.parse(frame.Link.GAME_C2S, bytes.fromhex(run["request_wire_hex"]))
    plain = tiles.decrypt_body(tiles.algo_id(run["request_sub"]), f.body)

S->C replies are the other way round: `plain_hex` is already decrypted and
`nonce` + `transform` rebuild the wire (`frame.build_s2c`).  Both directions
are re-derived by `check()` before anything is written.

    python tools/extract_dungeon_replies.py            # report + checks
    python tools/extract_dungeon_replies.py --json     # -> data/game/dungeon-20260928.json
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from uslocalserver import paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402
import diff_dungeon as D  # noqa: E402

OUT = paths.DATA_DIR / "game" / "dungeon-20260928.json"
CHANNELINFO = (0, 1)
HDR = frame.header_len(frame.Link.GAME_S2C)

#: The same three substitutions `extract_game_replies.py` makes: the fields a
#: note names that belong to the live session rather than to the capture.
NOTE_SUBS = (
    (re.compile(r"conn=\d+"), "conn={conn}"),
    (re.compile(r"plain=[0-9a-fA-F]*"), "plain={plain}"),
)


def transform_of(sub: int) -> str:
    return f"tile{tiles.algo_id(sub)}"


def note_doc(level: str, tag: str, msg: str) -> list[str]:
    for pat, rep in NOTE_SUBS:
        msg = pat.sub(rep, msg)
    return [level, tag, msg]


def frame_doc(f: D.Frame) -> dict:
    return {
        "main": f.opcode[0],
        "sub": f.opcode[1],
        "transform": transform_of(f.opcode[1]),
        "plain_hex": f.plain.hex(),
        "body_len": len(f.plain),
        "wire_len": f.wire,
        "nonce": f.nonce.hex(),
    }


def check(connect: list[D.Frame], runs: list[D.Run]) -> int:
    """Re-derive what the fixture assumes, and fail loudly on any of it.

    Three claims: the tile round-trips on every S->C frame (`decrypt` then
    `encrypt` is the identity, so a test may hold plaintext and rebuild the
    wire), the header's tag is the CRC of the ciphertext as `frame` says, and
    the frame rebuilds byte-identically from plaintext + stored nonce.  A
    capture that failed any of these would poison every test built on it.
    """
    frames = [f for r in runs for f in r.replies] + connect
    live = [f for f in frames if f.opcode != CHANNELINFO]
    print(f"-- checks over {len(frames)} S->C frame(s) "
          f"({len(runs)} C->S runs) --")
    bad = 0

    ok = 0
    for r in runs:
        f = frame.parse(frame.Link.GAME_C2S, r.body, strict=False,
                        expect_size=len(r.body))
        ok += ((f.opcode.main, f.opcode.sub) == r.opcode
               and len(r.body) == r.wire)
    print(f"  request wire parses to its own opcode and declared length: "
          f"{ok}/{len(runs)}")
    bad += ok != len(runs)

    ok = 0
    for r in runs:
        f = frame.parse(frame.Link.GAME_C2S, r.body, strict=False,
                        expect_size=len(r.body))
        algo = tiles.algo_id(r.opcode[1])
        ok += tiles.encrypt_body(algo, tiles.decrypt_body(algo, f.body)) == f.body
    print(f"  request body decrypt->encrypt is the identity: {ok}/{len(runs)}")
    bad += ok != len(runs)

    ok = 0
    for f in live:
        algo = tiles.algo_id(f.opcode[1])
        cipher = tiles.encrypt_body(algo, f.plain)
        ok += tiles.decrypt_body(algo, cipher) == f.plain
    print(f"  tile round-trip: {ok}/{len(live)}")
    bad += ok != len(live)

    ok = 0
    for f in live:
        body = tiles.encrypt_body(tiles.algo_id(f.opcode[1]), f.plain)
        v = frame.header_tag(frame.body_digest(body))
        ok += (f.header[7:11] == struct.pack("<I", v) and f.header[11] == v & 0xFF
               and f.header[15] == 0)
    print(f"  header [7:11]==LE32(tag(crc32(body))), [11]==its low byte, "
          f"[15]==0: {ok}/{len(live)}")
    bad += ok != len(live)

    ok = 0
    for f in live:
        op = frame.Opcode(f.opcode[0], f.opcode[1], frame.OpcodeEncoding.U8_U16LE,
                          True)
        wire = frame.build_s2c(op, tiles.encrypt_body(tiles.algo_id(f.opcode[1]),
                                                      f.plain), nonce=f.nonce)
        ok += wire == f.header + tiles.encrypt_body(tiles.algo_id(f.opcode[1]),
                                                    f.plain)
    print(f"  rebuild byte-identical: {ok}/{len(live)}")
    bad += ok != len(live)
    return bad


def report(connect: list[D.Frame], runs: list[D.Run]) -> None:
    print(f"\nconnect: {len(connect)} frame(s)")
    for f in connect:
        print(f"  ({f.opcode[0]},{f.opcode[1]}) wire={f.wire} "
              f"transform={transform_of(f.opcode[1])}")
    seen: dict[str, list[D.Run]] = {}
    for r in runs:
        seen.setdefault(r.key, []).append(r)
    print(f"\n{len(runs)} run(s) over {len(seen)} request opcode(s):")
    for key, rs in sorted(seen.items(), key=lambda kv: -len(kv[1])):
        shapes = sorted({len(r.replies) for r in rs})
        tags = sorted({t for r in rs for t in r.note_tags})
        print(f"  {key:>10} x{len(rs):<4} frames {shapes}"
              + (f"  notes {','.join(tags)}" if tags else ""))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--oracle", type=Path, default=D.DEFAULT_ORACLE)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    epoch, connect, runs = D.read_log(args.oracle, D.CONN)
    report(connect, runs)
    bad = check(connect, runs)

    if args.json:
        doc = {
            "generated_by": "tools/extract_dungeon_replies.py",
            "source": (f"{args.oracle.name}, the user's own dungeon session "
                       f"against the reference (conn={D.CONN}, game port "
                       f"{D.PORT}, one character from character-select to "
                       f"dungeon clear)"),
            "note": ("request_wire_hex is the whole C->S frame: parse it with "
                     "frame.parse(frame.Link.GAME_C2S, ...) and decrypt f.body "
                     "with tiles.decrypt_body(tiles.algo_id(request_sub), "
                     "f.body) before driving a handler.  S->C replies are the "
                     "reverse -- plain_hex is decrypted and transform + nonce "
                     "rebuild the wire.  Runs with no replies are evidence "
                     "too: 414 of the 612 draw nothing."),
            "session": {
                "conn": D.CONN,
                "port": D.PORT,
                "epoch": epoch,
                "character": D.CHARACTER,
                "span_seconds": round(runs[-1].offset, 3),
                "first_line": runs[0].line,
                "last_line": runs[-1].line,
            },
            "connect": [frame_doc(f) for f in connect],
            "scripts": [{
                "request_main": key[0],
                "request_sub": key[1],
                "runs": [{
                    "line": r.line,
                    "offset": round(r.offset, 3),
                    "request_wire_hex": r.body.hex(),
                    "wire_len": r.wire,
                    "state": list(r.dispatch[2:]) if r.dispatch else None,
                    "notes": [note_doc(*n) for n in r.notes],
                    "replies": [frame_doc(f) for f in r.replies],
                } for r in rs],
            } for key, rs in sorted(
                ((k, v) for k, v in _group(runs).items()),
                key=lambda kv: (kv[0][0], kv[0][1]))],
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(doc, indent=1), encoding="utf-8")
        print(f"\nwrote {OUT.relative_to(paths.REPO_ROOT)} "
              f"({OUT.stat().st_size}B)")

    print(f"\n{bad} failed check(s)")
    return 1 if bad else 0


def _group(runs: list[D.Run]) -> dict[tuple[int, int], list[D.Run]]:
    out: dict[tuple[int, int], list[D.Run]] = {}
    for r in runs:
        out.setdefault(r.opcode, []).append(r)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
