#!/usr/bin/env python3
"""Put the two halves of a live 0.4.4 session back together.

A relayed session leaves two independent records:

  * `Logs-capture/<stamp>/conn<N>.log` -- every frame with its opcode, sizes and
    (on game links) the decrypted body, written by `tools/capture_relay.py`;
  * `Server/Logs/server-<date>.log` -- the server's own events, hashed
    (`decode_events044.py` un-hashes them into `UNHANDLED`, `STUN`, ...).

Neither is enough alone: the relay sees *which bytes went by* but not what the
server made of them; the server log says *what it did* but not to which packet.
Both stamp local milliseconds, and the server emits its event while handling a
request -- so attribution is a join: an event belongs to the C2S frame that
arrived at or just before it.

    python tools/ref044/join_capture.py [CAPTURE ...] [--log LOG ...]
                                        [--window-ms 150] [--out PATH]

With no arguments the newest `Logs-capture/*` directory and the newest
reference `server-*.log` are used.  Writes `<capture>/joined.log` (each frame
with `  # LABEL` appended; `~` marks an inferred rather than direct match) and
prints the per-opcode census -- which is the 0.4.4 replacement for the 0.3.6
`UNHANDLED` progress counter.  If `mark.py` was used during the session, its
`marks.log` cuts the output into gameplay blocks; a slice is then "the frames
under one `--- MARK`", which is the unit the acceptance test is written in.

It assumes the relayed session is the only one the server is serving: restart
the reference server right before capturing (`capture_start.cmd` says so),
otherwise a second, direct session in the same log can drag its events onto
your frames.  The "events inside the capture window" line is the tell -- a
smoke test against a server that is also serving someone else shows a handful
of `~` matches instead of a clean join.
"""
from __future__ import annotations

import argparse
import collections
import re
import sys
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from ref044 import decode_events044 as D  # noqa: E402
from uslocalserver import paths  # noqa: E402

_FRAME = re.compile(
    r"^(?P<ts>\d\d:\d\d:\d\d\.\d{3}) (?P<dir>C2S|S2C) "
    r"\((?P<main>\d+),(?P<sub>\d+)\) (?P<rest>.*)$")
_STAMP_DIR = re.compile(r"(\d{8})-(\d{6})")


def seconds_of(ts: str) -> float:
    h, m, s = ts.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


@dataclass(frozen=True, slots=True)
class Frame:
    conn: int
    ts: str                 # "18:32:09.672"
    direction: str          # C2S | S2C
    opcode: tuple[int, int]
    line: str
    labels: tuple[str, ...] = ()

    @property
    def seconds(self) -> float:
        return seconds_of(self.ts)

    @property
    def key(self) -> str:
        return f"({self.opcode[0]},{self.opcode[1]})"

    def annotated(self) -> str:
        if not self.labels:
            return self.line
        return f"{self.line}  # {' '.join(self.labels)}"


def parse_frame_line(line: str, conn: int = 0) -> Frame | None:
    """One `conn<N>.log` line into a `Frame`; None for headers, gaps, notes."""
    m = _FRAME.match(line)
    if m is None:
        return None
    return Frame(conn, m.group("ts"), m.group("dir"),
                 (int(m.group("main")), int(m.group("sub"))), line)


def read_frames(path: Path) -> list[Frame]:
    match = re.search(r"conn(\d+)", path.name)
    conn = int(match.group(1)) if match else 0
    return [f for f in (parse_frame_line(line, conn)
                        for line in path.read_text(encoding="utf-8",
                                                   errors="replace").splitlines())
            if f is not None]


def capture_dir_date(capture: Path) -> str | None:
    """`20260930-183150` -> `2026-09-30`, for comparing against log dates."""
    m = _STAMP_DIR.search(capture.name)
    if m is None:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%d").strftime("%Y-%m-%d")
    except ValueError:
        return None


def newest_capture(out: Path) -> Path | None:
    """The newest capture directory that holds frames.

    A relay run that died on startup (ports taken) still leaves a stamped
    directory behind, and it is the *newest* one -- so pick by content, or the
    real capture is shadowed for the rest of the day.
    """
    dirs = sorted((p for p in out.glob("20*") if p.is_dir()),
                  key=lambda p: p.name)
    for directory in reversed(dirs):
        if any(directory.glob("conn*.log")):
            return directory
    return dirs[-1] if dirs else None


_MARK = re.compile(r"^(?P<ts>\d\d:\d\d:\d\d\.\d{3})\s*(?P<text>.*)$")


def read_marks(capture: Path) -> list[tuple[str, str]]:
    """The player's own `marks.log`, if `mark.py` was used during the run."""
    path = capture / "marks.log"
    if not path.exists():
        return []
    out: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _MARK.match(line.strip())
        if m:
            out.append((m.group("ts"), m.group("text").strip()))
    return sorted(out, key=lambda m: seconds_of(m[0]))


def split_blocks(frames: list[Frame], marks: list[tuple[str, str]]
                 ) -> list[tuple[str, list[Frame]]]:
    """Cut the frame stream at each mark -- the gameplay-block slices."""
    blocks: list[tuple[str, list[Frame]]] = []
    label, current = "(before the first mark)", []
    mi = 0
    for frame in frames:
        while mi < len(marks) and seconds_of(marks[mi][0]) <= frame.seconds:
            blocks.append((label, current))
            label, current = "  ".join(t for t in marks[mi] if t), []
            mi += 1
        current.append(frame)
    blocks.append((label, current))
    blocks.extend(("  ".join(t for t in mark if t), []) for mark in marks[mi:])
    if blocks and not blocks[0][1]:
        blocks.pop(0)          # the run opened with a mark -- no preamble
    return blocks


def attribute(frames: list[Frame], events: list[D.Event], window_s: float
              ) -> tuple[list[Frame], list[D.Event]]:
    """Stamp each event's label onto the frame it belongs to.

    Preference, in order: a C2S frame at or before the event (the server logs
    while handling a request), then the smallest time gap, then -- only when
    two frames sit at the same millisecond -- the connection number the server
    logged.  Order matters: the relay numbers connections from 1 per run while
    the server numbers them for its own lifetime, so the two agree only by
    luck; conn therefore breaks exact ties and never overrides the clock.
    Anything further than `window_s` from every frame stays unmatched instead
    of being forced onto a neighbour.
    """
    by_second: dict[int, list[int]] = collections.defaultdict(list)
    for i, f in enumerate(frames):
        by_second[int(f.seconds)].append(i)

    taken: dict[int, list[str]] = collections.defaultdict(list)
    unmatched: list[D.Event] = []
    for event in events:
        lo, hi = int(event.seconds - window_s), int(event.seconds + window_s)
        best: tuple[tuple[int, float, int], int] | None = None
        for sec in range(lo, hi + 1):
            for i in by_second.get(sec, ()):
                frame = frames[i]
                delta = event.seconds - frame.seconds
                if not -window_s <= delta <= window_s:
                    continue
                score = (0 if frame.direction == "C2S" and delta >= 0 else 1,
                         round(abs(delta), 3),
                         0 if event.conn is None or event.conn == frame.conn else 1)
                if best is None or score < best[0]:
                    best = (score, i)
        if best is None:
            unmatched.append(event)
            continue
        (direct, _, conn_ok), index = best
        name = event.label or f"?{event.digest}"
        taken[index].append(name if (conn_ok == 0 and direct == 0) else f"~{name}")

    return ([replace(f, labels=tuple(taken[i])) if i in taken else f
             for i, f in enumerate(frames)], unmatched)


def census(frames: list[Frame]) -> collections.Counter:
    """(opcode, direction) -> Counter of labels, over annotated frames."""
    out: collections.Counter = collections.Counter()
    for frame in frames:
        for label in frame.labels:
            out[(frame.direction, frame.key, label)] += 1
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("captures", nargs="*", type=Path,
                        help="capture directories (or conn*.log files)")
    parser.add_argument("--log", action="append", default=[], type=Path,
                        help="server log to join (default: newest reference log)")
    parser.add_argument("--out", type=Path, default=None,
                        help="where to write joined.log (default: in the capture dir)")
    parser.add_argument("--window-ms", type=float, default=150.0)
    parser.add_argument("--exe", default=str(paths.ACTIVE.exe))
    parser.add_argument("--quiet", action="store_true", help="only write the file")
    args = parser.parse_args(argv)

    captures = args.captures
    if not captures:
        newest = newest_capture(ROOT / "Logs-capture")
        if newest is None:
            print("no Logs-capture/<stamp> directory yet", file=sys.stderr)
            return 2
        captures = [newest]

    frame_paths: list[Path] = []
    for capture in captures:
        frame_paths.extend(sorted(capture.glob("conn*.log")) if capture.is_dir()
                           else [capture])
    if not frame_paths:
        print(f"no conn*.log under {captures}", file=sys.stderr)
        return 2
    frames = [f for p in frame_paths for f in read_frames(p)]

    logs = list(args.log)
    if not logs:
        newest = D.default_log()
        if newest is None:
            print(f"no server-*.log under {paths.ACTIVE.logs_dir}", file=sys.stderr)
            return 2
        logs = [newest]
    dictionary = D.build_dictionary(Path(args.exe)) if Path(args.exe).exists() else {}
    if not dictionary:
        print(f"warning: no exe at {args.exe}; digests will print raw", file=sys.stderr)
    events = [e.named(dictionary) for path in logs for e in D.read_events(path)]

    day = capture_dir_date(captures[0] if captures[0].is_dir() else captures[0].parent)
    for log in logs:
        days = {e.date for e in D.read_events(log)}
        if day and days and day not in days:
            print(f"warning: capture is {day}, {log.name} holds {sorted(days)} -- "
                  f"the join will be empty", file=sys.stderr)

    joined, unmatched = attribute(frames, events, args.window_ms / 1000.0)
    capture_dir = captures[0] if captures[0].is_dir() else captures[0].parent
    out = Path(args.out) if args.out else capture_dir / "joined.log"
    marks = read_marks(capture_dir)
    blocks = split_blocks(joined, marks)
    lines: list[str] = []
    for label, block in blocks:
        if marks:
            lines.append(f"--- MARK {label}   {len(block)} frame(s)")
        lines.extend(f.annotated() for f in block)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if args.quiet:
        return 0
    half = args.window_ms / 2000.0
    lo = min((f.seconds for f in joined), default=0.0) - half
    hi = max((f.seconds for f in joined), default=0.0) + half
    # Events outside the capture's clock window belong to some other session in
    # the same log file; only the ones *inside* it should have matched.
    inside = [e for e in events if lo <= e.seconds <= hi]
    missed = [e for e in unmatched if lo <= e.seconds <= hi]

    print(f"[out] {out}")
    if len(blocks) > 1:
        print(f"\nblocks ({len(blocks)}):")
        for label, block in blocks:
            labels = sum(len(f.labels) for f in block)
            print(f"  {len(block):6d} frames  {labels:5d} labels  {label}")
    print(f"\nframes: {len(joined)}   events in log: {len(events)}   "
          f"attributed: {sum(len(f.labels) for f in joined)}")
    print(f"events inside the capture window: {len(inside)}   "
          f"of those unattributed: {len(missed)}"
          f"{'   <-- expected 0; check the clock' if missed else ''}")
    counts = census(joined)
    if counts:
        print("\nper frame kind (top 25):")
        for (direction, key, label), n in counts.most_common(25):
            print(f"  {n:6d}  {direction} {key:10s} {label}")
    if missed:
        sample = collections.Counter(e.label or f"?{e.digest}" for e in missed)
        print("\nunattributed inside the window: "
              + ", ".join(f"{k}×{v}" for k, v in sample.most_common(8)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
