#!/usr/bin/env python3
"""Drop a timestamped breadcrumb into the running capture.

A capture is one flat stream of frames; this is how the player says "the next
frames are the shop".  `mark.py` appends to `Logs-capture/<stamp>/marks.log`
in the newest capture directory, and `join_capture.py` cuts `joined.log` at
those points -- so a debugging target becomes a *slice* ("the 40 frames of
`buy`") instead of the whole session.

    mark.cmd shop buy          one breadcrumb
    mark.cmd                   lists what has been marked so far

Run it from a second console while `capture_start.cmd` relays; the relay holds
no lock on the directory, so both can write at once.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from ref044.join_capture import newest_capture, read_marks  # noqa: E402


def main(argv: list[str]) -> int:
    capture = newest_capture(ROOT / "Logs-capture")
    if capture is None:
        print("no Logs-capture/<stamp> directory -- start capture_start.cmd first",
              file=sys.stderr)
        return 2
    text = " ".join(argv).strip()
    if not text:
        marks = read_marks(capture)
        print(f"{capture.name}: {len(marks)} mark(s)")
        for ts, note in marks:
            print(f"  {ts}  {note}")
        return 0
    stamp = f"{datetime.now():%H:%M:%S.%f}"[:-3]
    with (capture / "marks.log").open("a", encoding="utf-8") as fh:
        fh.write(f"{stamp}  {text}\n")
    print(f"[{stamp}] {text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
