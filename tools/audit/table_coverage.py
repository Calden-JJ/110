"""Which of the 69 game-data tables does the rewrite actually read?

0.4.4 no longer embeds those tables, so re-sourcing them is real work and the
size of the job is the number of tables that matter -- not 69.  This runs the
whole test suite with `game.data.load` instrumented and reports the split.

    python tools/table_coverage.py            # run the suite, summarise
    python tools/table_coverage.py --verbose  # and name the touched tables
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from uslocalserver.game import data as data_mod                     # noqa: E402

TOUCHED: dict[str, int] = {}
FAILED_REASONS: list[str] = []

_real_load = data_mod.load


def traced_load(name: str):
    TOUCHED[name] = TOUCHED.get(name, 0) + 1
    return _real_load(name)


data_mod.load.cache_clear()
data_mod.load = traced_load

# `rows()` and `flat()` call `load`, but they were generated as module-level
# functions that captured the original name, so patch through them too.
_real_rows = data_mod.rows
_real_flat = data_mod.flat


def traced_rows(name: str, key=None):
    TOUCHED[name] = TOUCHED.get(name, 0) + 1
    return _real_rows(name, key)


def traced_flat(name: str):
    TOUCHED[name] = TOUCHED.get(name, 0) + 1
    return _real_flat(name)


data_mod.rows = traced_rows
data_mod.flat = traced_flat


class Collector(unittest.TestResult):
    def addError(self, test, err):                     # noqa: N802
        super().addError(test, err)
        FAILED_REASONS.append(f"{test}: {err[1]}")

    def addFailure(self, test, err):                   # noqa: N802
        super().addFailure(test, err)
        FAILED_REASONS.append(f"{test}: {err[1]}")


def main() -> int:
    verbose = "--verbose" in sys.argv
    suite = unittest.TestLoader().discover(str(REPO / "tests"))
    result = Collector()
    suite.run(result)

    print(f"\ntests: {result.testsRun} run, "
          f"{len(result.errors)} errors, {len(result.failures)} failures")
    print(f"tables read: {len(TOUCHED)} of {len(data_mod.FILES)}")

    print("\n--- READ, by call count ---")
    for name, n in sorted(TOUCHED.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>6}  {name}")

    untouched = sorted(set(data_mod.FILES) - set(TOUCHED))
    print(f"\n--- NEVER READ ({len(untouched)}) ---")
    for name in untouched:
        print(f"    {name}")

    if verbose:
        print("\n--- failure reasons, first 25 ---")
        for line in FAILED_REASONS[:25]:
            print(f"  {line[:190]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
