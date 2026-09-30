#!/usr/bin/env python3
"""Extract the flip card's per-dungeon reward pools to data/game/card_pools.json.

The live server has to build the `(0,35)` card a clear drops (`cardpool`),
and the rule is only half-derivable: the *cost* is table 051's `paidCosts`
by the dungeon's `basisLevel` (d3 340, 8523 11380, 100000002 16180 -- all
the capture's own, and the two `disabled` specials read 0), but the *free
flip's* count, gold and items are rolled per run and no extracted table
holds the pools -- they live in the client's `itemdropinfo_clearreward.etc`,
which the 0.3.6 capture set does not carry.  So the pools here are the
corpus's own observed rolls, one row per `DUNGEON-CLEAR-46` and
`DUNGEON-CARD-71` line over the seven reference logs:

    DUNGEON-CLEAR-46 ... dungeon=3 ... (0,35) 315B free=2 paid=1 cost=340
    DUNGEON-CARD-71  ... dungeon=3 ... side=0 cost=0 goldDelta=34
                         balance=5066 rewards=0x34,406010081x1 committed

The clear lines give `free` and `cost`; the side-0 commit lines give the
run's own (gold, items) roll; the side-1 lines the paid item.  Everything
is stored with its observation count so a live roll samples the corpus's
own distribution -- see `game/dungeon/cardpool.py`, which also documents
what the fallback covers and why.

The `cost` is *checked* here, not stored: 051's `paidCosts[basisLevel]`
must equal every clear line's `cost=` (0 for `disabled` dungeons), and the
report fails loudly on a disagreement.

    python tools/extract_card_rewards.py                 # report
    python tools/extract_card_rewards.py --json          # write the file
    python tools/extract_card_rewards.py --logs-dir <d>  # other log directory
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
from uslocalserver.game.dungeon import maze  # noqa: E402

OUT = paths.DATA_DIR / "game" / "card_pools.json"
DEFAULT_LOGS = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\Logs")
EXTRA_LOGS = paths.REPO_ROOT / "Logs-dungeon"

CLEAR = re.compile(r"DUNGEON-CLEAR-46 .*?dungeon=(\d+).*?free=(\d+) paid=(\d+) cost=(\d+)")
COMMIT = re.compile(r"DUNGEON-CARD-71 .*?dungeon=(\d+) .*?side=(\d+) cost=(\d+) "
                    r"goldDelta=(-?\d+) .*?rewards=(.*?) committed")

#: The basis bands the free-count fallback is derived over, as
#: `(limit, ...)`: a dungeon falls in the first band whose limit it is under.
FREE_BANDS = (90, 130, 201)


def parse_rewards(text: str) -> tuple[tuple[int, int], ...]:
    """The `rewards=` list as granted `(item, count)` pairs.

    `0xNNN` is the gold marker (the delta's *decimal* spelling), not an item.
    """
    out = []
    for part in text.split(","):
        if not part or part.startswith("0x"):
            continue
        item, _, count = part.partition("x")
        out.append((int(item), int(count or 1)))
    return tuple(out)


def scan(log_dir: Path) -> tuple[dict, int, int]:
    """The corpus's clears and commits, and the line count of each."""
    clears: dict[int, Counter] = {}
    commits: dict[int, list[tuple[int, int, tuple]]] = {}
    n_clear = n_commit = 0
    for path in sorted(log_dir.glob("server-*.log")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = CLEAR.search(line)
            if m:
                dungeon, free, cost = int(m.group(1)), int(m.group(2)), int(m.group(4))
                clears.setdefault(dungeon, Counter())[(free, cost)] += 1
                n_clear += 1
                continue
            m = COMMIT.search(line)
            if m:
                dungeon, side = int(m.group(1)), int(m.group(2))
                commits.setdefault(dungeon, []).append(
                    (side, int(m.group(4)), parse_rewards(m.group(5))))
                n_commit += 1
    return {"clears": clears, "commits": commits}, n_clear, n_commit


def card_051() -> dict:
    return data.load("card_rewards")


def cost_of(dungeon: int) -> int:
    """The clear line's `cost=` as table 051 spells it."""
    cfg = card_051()["dungeons"].get(str(dungeon))
    if cfg is None or cfg.get("disabled"):
        return 0
    return dict(card_051()["paidCosts"]).get(maze.basis_level(dungeon), 0)


def pools(corpus: dict) -> tuple[dict, list[str]]:
    """Per-dungeon pools, and any cost a clear line disagrees with 051 over."""
    bad: list[str] = []
    out: dict[str, dict] = {}
    dungeons = set(corpus["clears"]) | set(corpus["commits"])
    for dungeon in sorted(dungeons):
        free = Counter()
        for (count, cost), times in corpus["clears"].get(dungeon, {}).items():
            free[count] += times
            if cost != cost_of(dungeon):
                bad.append(f"d{dungeon}: clear cost={cost} but 051 says "
                           f"{cost_of(dungeon)}")
        runs = Counter()
        paid = Counter()
        for side, gold, items in corpus["commits"].get(dungeon, []):
            if side == 0:
                runs[(gold, items)] += 1
            else:
                paid[items[0][0]] += 1 if items else 0
        entry: dict = {}
        if free:
            entry["free"] = sorted([c, n] for c, n in free.items())
        if runs:
            entry["runs"] = [[gold, [list(i) for i in items], n]
                             for (gold, items), n in sorted(runs.items())]
        if paid:
            entry["paid_items"] = sorted([i, n] for i, n in paid.items())
        out[str(dungeon)] = entry
    return out, bad


def fallback(corpus: dict) -> dict:
    """What a dungeon the corpus never rolled falls back to.

    Each field keeps the corpus's own observations so a live roll samples
    them rather than a fitted band: the free counts of every basis band with
    the `disabled` specials left out -- their 0 is the special's, not the
    band's -- the `gold / gold[basisLevel]` ratios of every side-0 commit
    (table 050's per-level gold), and every free-side grant as
    `(item, count, times)`.  A fallback item's count is the one it was rolled
    with, so the pair travels together.  `paid_items` is the corpus-wide
    paid pool, what a dungeon with no side-1 observation draws from.
    """
    gold_table = {lv: gold for lv, gold, _ in data.load("monster_drops")["gold"]}
    ratios = []
    grants: Counter = Counter()
    paid: Counter = Counter()
    per_band: dict[int, Counter] = {limit: Counter() for limit in FREE_BANDS}
    for dungeon in sorted(set(corpus["clears"]) | set(corpus["commits"])):
        basis = maze.basis_level(dungeon)
        disabled = card_051()["dungeons"].get(str(dungeon), {}).get("disabled")
        limit = next((b for b in FREE_BANDS if basis < b), FREE_BANDS[-1])
        if not disabled:
            for (count, _cost), times in corpus["clears"].get(dungeon, {}).items():
                per_band[limit][count] += times
        for side, gold, items in corpus["commits"].get(dungeon, []):
            if side:
                if items:
                    paid[items[0][0]] += 1
                continue
            if not gold:
                continue
            base = gold_table.get(basis)
            if base:
                ratios.append(gold / base)
            for item, count in items:
                grants[(item, count)] += 1
    return {
        "free_bands": [[limit, sorted([c, n] for c, n in per_band[limit].items())]
                       for limit in FREE_BANDS if per_band[limit]],
        "gold_ratios": sorted(round(r, 4) for r in ratios),
        "items": sorted([item, count, times]
                        for (item, count), times in grants.items()),
        "paid_items": sorted([item, times] for item, times in paid.items()),
    }


def main(argv: list[str]) -> int:
    log_dir = DEFAULT_LOGS
    if "--logs-dir" in argv:
        log_dir = Path(argv[argv.index("--logs-dir") + 1])
    dirs = [log_dir] + ([EXTRA_LOGS] if EXTRA_LOGS.exists() else [])
    corpus: dict = {"clears": {}, "commits": {}}
    n_clear = n_commit = 0
    for d in dirs:
        part, c, k = scan(d)
        for dungeon, counter in part["clears"].items():
            corpus["clears"].setdefault(dungeon, Counter()).update(counter)
        for dungeon, runs in part["commits"].items():
            corpus["commits"].setdefault(dungeon, []).extend(runs)
        n_clear += c
        n_commit += k
    print(f"{n_clear} clear line(s), {n_commit} commit line(s) "
          f"in {', '.join(str(d) for d in dirs)}")
    dungeons, bad = pools(corpus)
    for line in bad:
        print(f"  !! {line}")
    print(f"\n{'dungeon':>10} {'basis':>5} {'cost':>6} {'free (x times)':<22} "
          f"{'side-0 runs':<34} paid")
    for key, entry in sorted(dungeons.items(), key=lambda kv: int(kv[0])):
        d = int(key)
        free = ",".join(f"{c}x{n}" for c, n in entry.get("free", []))
        runs = " | ".join(
            f"{gold}:{'+'.join(f'{i}x{c}' for i, c in items)}x{n}"
            for gold, items, n in entry.get("runs", []))
        paid = ",".join(str(i) for i, _ in entry.get("paid_items", []))
        print(f"{d:>10} {maze.basis_level(d):>5} {cost_of(d):>6} {free:<22} "
              f"{runs:<34} {paid}")
    fb = fallback(corpus)
    print(f"\nfallback free bands (basis<limit -> count x times): {fb['free_bands']}")
    print(f"fallback gold ratios: {len(fb['gold_ratios'])} observed, "
          f"{fb['gold_ratios'][0]}..{fb['gold_ratios'][-1]}")
    print(f"fallback item pool: {len(fb['items'])} grant kind(s), "
          f"{sum(n for _, _, n in fb['items'])} grant(s)")
    print(f"fallback paid pool: {len(fb['paid_items'])} item(s), "
          f"{sum(n for _, n in fb['paid_items'])} grant(s)")

    if bad:
        print("\nrefusing to write: cost disagreements above")
        return 1
    if "--json" not in argv:
        return 0
    doc = {
        "generated_by": "tools/extract_card_rewards.py",
        "note": ("The flip card's per-dungeon pools, read off the reference "
                 "logs: `free` are the DUNGEON-CLEAR-46 free counts, `runs` "
                 "the DUNGEON-CARD-71 side-0 (gold, items) rolls, `paid_items` "
                 "the side-1 grants -- each with its observation count.  The "
                 "cost is not stored: table 051's paidCosts[basisLevel] is it "
                 "(0 for disabled dungeons).  `fallback` is what a dungeon the "
                 "corpus never rolled draws from; see game/dungeon/cardpool.py "
                 "for how each field is read."),
        "dungeons": dungeons,
        "fallback": fb,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"\nwrote {OUT.relative_to(paths.REPO_ROOT)} ({OUT.stat().st_size}B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
