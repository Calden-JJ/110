#!/usr/bin/env python3
"""Decode every game-link frame in a log line range (ad-hoc recon helper).

    python tools/dump_frames.py <log> <first-line> <last-line> [--conn N]

Prints C->S frames as the decrypted request body and S->C frames as
`(main,sub) wire=N plain=M hex`, so a captured request/reply run can be read
byte by byte without opening the log in an editor.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", type=Path)
    ap.add_argument("first", type=int)
    ap.add_argument("last", type=int)
    ap.add_argument("--conn", type=int, default=None)
    args = ap.parse_args()

    c2s_hdr = frame.header_len(frame.Link.GAME_C2S)
    for p in logs.iter_packets(args.log):
        if p.link != "game" or not (args.first <= p.line_no <= args.last):
            continue
        if args.conn is not None and p.conn != args.conn:
            continue
        if p.hex is None or p.truncated:
            print(f"line {p.line_no} {p.ts} {p.direction} (no/truncated hex)")
            continue
        if p.direction == "C->S":
            body = tiles.decrypt_body(tiles.algo_id(p.opcode[1]),
                                      p.frame_bytes[c2s_hdr:])
            print(f"line {p.line_no} {p.ts} C->S {p.opcode} body={len(body)}B "
                  f"plain={body.hex()}")
        else:
            fr = frame.parse(frame.Link.GAME_S2C, p.frame_bytes, strict=False)
            plain = tiles.decrypt_body(tiles.algo_id(fr.opcode.sub), fr.body)
            print(f"line {p.line_no} {p.ts} S->C {fr.opcode} wire={p.wire}B "
                  f"plain={len(plain)}B {plain.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
