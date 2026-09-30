#!/usr/bin/env python3
"""Extract the kill drop pools to data/game/kill_drops.json.

The live server has to answer `(1,39)` with the drops a kill left
(`droppool`), and no extracted table spells the selection out: table 050
holds the pools (`monsters`, `generic`, `gold`) but not the rate or the pick.
So the pools here are the corpus's own observed kills, one row per
`COMBAT-DIE-39` line over the reference logs and the repo's own dungeon runs:

    COMBAT-DIE-39 ... code=107000124 ... drops=[2:0x15/gold,3:400320513x1/monster] died; ...

An entry is `slot:0xNN/gold` -- the amount's *decimal* spelling behind the
marker -- or `slot:<id>x<count>/<pool>`, the pool word the note carries
(`monster`, `type2`, `world`, `dcod-local-policy/pvf-material`, ...).  The
slot is dropped: it is the session's running ground counter, not the roll.

Every kill is an observation, the empty `drops=[]` included -- a kill that
rolled nothing is exactly what the rate needs.  Two kinds of kill are
*excluded*, each for the same reason, that `droppool` answers them without
the pools: the cinematic outcomes (`story/friendly actor` and `cinematic map
objective confirmed`), which never drop, and the codes table 050 itself
gives a `monsters` pool (the room's boxes and pots), which drop on every
kill -- left in, the 100% objects would drag dungeon 3's layer from 16% to
45%.  The report prints both counts so the rules stay checkable.

The file stores every layer the live roll pools over -- the exact
`(dungeon, code)` pair, the code across dungeons, the dungeon across codes,
and the corpus-wide pool -- each as `[[entry, ...], times]` rows.  Which
layer a given kill reads is `droppool.MIN_N`'s call at roll time, not the
extractor's.

    python tools/extract_kill_drops.py                 # report
    python tools/extract_kill_drops.py --json          # write the file
    python tools/extract_kill_drops.py --logs-dir <d>  # other log directory
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import paths  # noqa: E402
from uslocalserver.game import data  # noqa: E402
from uslocalserver.game.dungeon import drops  # noqa: E402

OUT = paths.DATA_DIR / "game" / "kill_drops.json"
DEFAULT_LOGS = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\Logs")
EXTRA_LOGS = paths.REPO_ROOT / "Logs-dungeon"

DIE = re.compile(r"COMBAT-DIE-39 .*?dungeon=(\d+) .*?code=(\d+) .*?rank=(\w+) "
                 r".*?drops=\[([^\]]*)\] died; ([^;]*)")

#: The two outcomes `droppool` suppresses: a story actor, and the objective
#: branch of a hunt dummy.
CINEMATIC = ("story/friendly actor", "cinematic map objective confirmed")

#: The kills a layer needs before `droppool` trusts it (kept here so the
#: report can show what each threshold would keep).
MIN_N = 20


def object_codes() -> set[int]:
    """The codes with a non-empty table-050 `monsters` pool.

    These are the room's boxes and pots: every corpus kill of the 24 -- 155
    of 155 -- dropped, the one item weighted by the pool, so `droppool`
    rolls them straight from the table and their kills are *excluded* from
    the pools here -- left in, they would drag a dungeon layer's rate to
    their own 100% (dungeon 3's reads 45% with them, 16% without).
    """
    return {int(code) for code, entry in data.load("monster_drops")["monsters"].items()
            if entry.get("pool")}


def parse_entry(text: str) -> tuple | None:
    """One `drops=[...]` entry as `(kind, item, value)`, or None.

    Gold is `0x<decimal>/gold` and stored as `("gold", 0, amount)`; an item
    is `<id>x<count>/<pool>` and stored as `(pool, id, count)`.  The pool is
    everything past the *first* slash -- the corpus spells compound pools out
    (`dcod-local-policy/pvf-material`) -- and the count is what the note
    spells, so a stackable keeps it and an equipment's live instance uid is
    `droppool`'s to draw.
    """
    _, _, rest = text.partition(":")
    value, _, pool = rest.partition("/")
    if not pool:
        return None
    if value.startswith("0x"):
        if pool != drops.GOLD or not value[2:].isdigit():
            return None
        return (drops.GOLD, 0, int(value[2:], 10))
    item, _, count = value.partition("x")
    if not item.isdigit() or not count.isdigit():
        return None
    return (pool, int(item), int(count))


def parse_set(text: str) -> tuple | None:
    """The whole `[...]` group as a normalized set, None on any bad entry."""
    if not text:
        return ()
    entries = []
    for part in text.split(","):
        entry = parse_entry(part)
        if entry is None:
            return None
        entries.append(entry)
    return tuple(entries)


def scan(log_dir: Path) -> tuple[Counter, dict[str, Counter], list[str]]:
    """Per `(dungeon, code)` drop sets, the exclusion tallies, and any line
    that did not parse.

    The tallies count kills: `all` is every matched line, `cinematic` and
    `objects` the two exclusions, and `object_dropped` how many object kills
    carried a drop (the table-pool rule's own check).
    """
    sets: Counter = Counter()
    tally = {name: Counter() for name in
             ("all", "cinematic", "objects", "object_dropped")}
    bad: list[str] = []
    pools = object_codes()
    for path in sorted(log_dir.glob("server-*.log")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = DIE.search(line)
            if m is None:
                continue
            dungeon, code = int(m.group(1)), int(m.group(2))
            tally["all"][(dungeon, code)] += 1
            if any(mark in m.group(5) for mark in CINEMATIC):
                tally["cinematic"][(dungeon, code)] += 1
                continue
            if code in pools:
                tally["objects"][(dungeon, code)] += 1
                if m.group(4):
                    tally["object_dropped"][(dungeon, code)] += 1
                continue
            parsed = parse_set(m.group(4))
            if parsed is None:
                bad.append(line.strip())
                continue
            sets.setdefault((dungeon, code), Counter())[parsed] += 1
    return sets, tally, bad


def merge(dst: Counter, src: Counter) -> None:
    for key, counter in src.items():
        dst.setdefault(key, Counter()).update(counter)


def json_sets(counter: Counter) -> list:
    """A `Counter` of set tuples as `[[entry, ...], times]` rows, sorted."""
    return [[[entry for entry in entries], times]
            for entries, times in sorted(counter.items(),
                                         key=lambda kv: (-kv[1], kv[0]))]


def layers(sets: Counter) -> dict[str, list[tuple[str, Counter]]]:
    """The four pooling layers: key -> its own observation counter."""
    pairs = {f"{d}/{c}": counter for (d, c), counter in sets.items()}
    codes: dict[str, Counter] = {}
    dungeons: dict[str, Counter] = {}
    glob: Counter = Counter()
    for (d, c), counter in sets.items():
        codes.setdefault(str(c), Counter()).update(counter)
        dungeons.setdefault(str(d), Counter()).update(counter)
        glob.update(counter)
    return {"pairs": sorted(pairs.items()), "codes": sorted(codes.items()),
            "dungeons": sorted(dungeons.items()), "global": [("all", glob)]}


def kills(counter: Counter) -> int:
    return sum(counter.values())


def dropped(counter: Counter) -> int:
    return kills(counter) - counter.get((), 0)


def main(argv: list[str]) -> int:
    log_dir = DEFAULT_LOGS
    if "--logs-dir" in argv:
        log_dir = Path(argv[argv.index("--logs-dir") + 1])
    dirs = [log_dir] + ([EXTRA_LOGS] if EXTRA_LOGS.exists() else [])
    sets: Counter = Counter()
    tally = {name: Counter() for name in
             ("all", "cinematic", "objects", "object_dropped")}
    bad: list[str] = []
    for d in dirs:
        part, counts, lines = scan(d)
        merge(sets, part)
        for name, counter in counts.items():
            tally[name].update(counter)
        bad += lines
    n_sets = sum(kills(c) for c in sets.values())
    n_cine = kills(tally["cinematic"])
    n_obj = kills(tally["objects"])
    print(f"{kills(tally['all'])} kill line(s) in "
          f"{', '.join(str(d) for d in dirs)}: {n_sets} pooled, "
          f"{n_cine} cinematic (excluded), {n_obj} object "
          f"(table pool, excluded), {len(bad)} unparsed")
    for line in bad[:10]:
        print(f"  !! {line}")

    #: The 100% rule the object exclusion rests on, cheap to re-check: the
    #: corpus's objects dropped on every kill, so the table pool is enough.
    print(f"object kills dropped: {kills(tally['object_dropped'])}/{n_obj} "
          f"({kills(tally['object_dropped']) / max(1, n_obj):.0%})")

    lay = layers(sets)
    print(f"\n{'layer':>10} {'entries':>8} {'kills':>7} {'dropped':>8} "
          f"{'at >= MIN_N':>12} {'distinct sets':>14}")
    for name, group in lay.items():
        kept = sum(1 for _, c in group if kills(c) >= MIN_N)
        n = sum(kills(c) for _, c in group)
        dr = sum(dropped(c) for _, c in group)
        distinct = sum(len(c) for _, c in group)
        print(f"{name:>10} {len(group):>8} {n:>7} {dr:>8} {kept:>12} {distinct:>14}")

    print(f"\ntop (dungeon, code) pairs by kills:")
    for key, counter in sorted(lay["pairs"],
                               key=lambda kv: -kills(kv[1]))[:25]:
        rate = dropped(counter) / kills(counter)
        print(f"  {key:>16} {kills(counter):>4} kills, {dropped(counter):>3} "
              f"dropped ({rate:.0%}), {len(counter)} distinct set(s)")

    doc = {
        "generated_by": "tools/extract_kill_drops.py",
        "note": ("The kill drop pools, read off the COMBAT-DIE-39 lines: each "
                 "layer maps its key to `[[entry, ...], times]` rows, an entry "
                 "being `[\"gold\", 0, amount]` or `[pool, item, count]`.  The "
                 "empty set is the kill that rolled nothing.  Cinematic kills "
                 "are excluded -- they never drop.  `droppool` picks the layer "
                 "(pair, code, dungeon, global) at roll time by its MIN_N."),
        "pairs": {k: json_sets(c) for k, c in lay["pairs"]},
        "codes": {k: json_sets(c) for k, c in lay["codes"]},
        "dungeons": {k: json_sets(c) for k, c in lay["dungeons"]},
        "global": json_sets(lay["global"][0][1]),
    }
    if "--json" not in argv:
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"\nwrote {OUT.relative_to(paths.REPO_ROOT)} ({OUT.stat().st_size}B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
