"""Put src/ and tools/ on sys.path.  Import this first in every test module.

pytest is not installed here and the network is unreachable, so the suite is
stdlib-only and runs with:

    python -m unittest discover -s tests

`-t .` must *not* be added: it makes the start directory `tests/` itself
non-importable (no `__init__.py`, and adding one would break the plain
`import _bootstrap` every test module starts with).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

for _p in (REPO / "src", REPO / "tools", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
