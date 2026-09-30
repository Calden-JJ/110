"""Block-level diff of two inflated ACK bodies (`_chan_exp/<label>/<name>.infl`).

    python tools/chan_diff.py base6 port84 --name CHANNEL_ACK

Prints the changed 16-byte block indices and, for a CHANNEL_ACK, the byte range
each changed block covers in the 4-byte-header / 24-byte-section / 48-byte-record
layout (record index and in-record offset), which is what turns a config edit
into a field offset.
"""
from __future__ import annotations

import argparse
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HEADER = 4
SECTION = 24
RECORD = 48


def load(label: str, name: str) -> bytes:
    return (REPO / "_chan_exp" / label / f"{name}.infl").read_bytes()


def layout(counts: list[int]) -> list[tuple[int, int, str]]:
    """(start, end, description) for every header and record."""
    out = [(0, HEADER, "global header")]
    pos = HEADER
    for sec, n in enumerate(counts):
        out.append((pos, pos + SECTION, f"section{sec} header"))
        pos += SECTION
        for rec in range(n):
            out.append((pos, pos + RECORD, f"section{sec} rec{rec}"))
            pos += RECORD
    return out


def describe(spans: list[tuple[int, int, str]], off: int) -> str:
    for start, end, name in spans:
        if start <= off < end:
            return f"{name}+{off - start}"
    return "?"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--name", default="CHANNEL_ACK")
    ap.add_argument("--cain", type=int, default=6)
    ap.add_argument("--siroco", type=int, default=3)
    args = ap.parse_args()

    a, b = load(args.left, args.name), load(args.right, args.name)
    print(f"{args.name}: {args.left} {len(a)}B -> {args.right} {len(b)}B")
    if len(a) != len(b):
        print("  (length changed)")
    spans = layout([n for n in (args.cain, args.siroco) if n])
    n = min(len(a), len(b))
    for i in range(0, n, 16):
        x, y = a[i:i + 16], b[i:i + 16]
        if x != y:
            where = f"{describe(spans, i)} .. {describe(spans, i + 15)}"
            print(f"  bytes {i:4d}..{i + 15:4d}  {where:34s} "
                  f"{x.hex()[:32]} -> {y.hex()[:32]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
