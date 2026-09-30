"""Classify every test module by what reference material it needs.

Going 0.4.4-only means the 0.3.6 oracle tree is gone: no `uslocalserver.db` with
XRenYing, no `server-202609{19,25,26}.log` corpus.  Before re-pinning anything it
helps to know which modules are blocked on which resource, and how big each
block is.

    python tools/classify_tests.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TESTS = REPO / "tests"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# resource -> regex that detects a module's dependency on it
RESOURCES = {
    "save-db": r"paths\.SAVE_DB|_save_copy|schema\.connect\(",
    "corpus": r"_corpus|CORPUS|paths\.LOGS_DIR",
    "replies": r"replies\.json|game\.replies|channel\.replies",
    "tables": r"game\.data|from \.\.data|from \.data|dungeon\.data|\bcontent\b",
    "client": r"launcher",
    "frames": r"protocol\.frame|_bootstrap",
}


def main() -> int:
    rows = []
    for path in sorted(TESTS.glob("test_*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        cases = len(re.findall(r"def test_", text))
        needed = [name for name, rx in RESOURCES.items() if re.search(rx, text)]
        rows.append((path.name, cases, needed))

    width = max(len(r[0]) for r in rows)
    print(f"{'module'.ljust(width)}  cases  needs")
    print("-" * (width + 40))
    for name, cases, needed in rows:
        print(f"{name.ljust(width)}  {cases:>5}  {', '.join(needed)}")

    print()
    print(f"{len(rows)} modules, {sum(r[1] for r in rows)} test cases")
    for resource in RESOURCES:
        mods = [r for r in rows if resource in r[2]]
        print(f"  {resource:>9}: {len(mods):>2} modules, "
              f"{sum(m[1] for m in mods):>4} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
