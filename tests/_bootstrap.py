"""Put src/ and tools/ on sys.path.  Import this first in every test module.

pytest is not installed here and the network is unreachable, so the suite is
stdlib-only and runs with:

    python -m unittest discover -s tests

`-t .` must *not* be added: it makes the start directory `tests/` itself
non-importable (no `__init__.py`, and adding one would break the plain
`import _bootstrap` every test module starts with).

It also carries the two shared skip helpers.  Both exist for the same reason:
`DFO110-0.3.6` -- the tree every packet-level fixture was measured against --
was deleted, so the captured `server-202609*.log` corpus is not on disk.  A
module that cannot run without it should say so once, loudly, instead of
reporting a fixture gap as a code defect.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

for _p in (REPO / "src", REPO / "tools", REPO):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

#: Names the 0.3.6 capture set.  Every frame count in the suite is pinned to
#: `server-20260926.log` (288 records, 4 truncated), so that file -- not the
#: newest log on disk -- is what "the corpus" means.  `DFO_CORPUS_LOG` overrides.
CORPUS_CANDIDATES = (
    "server-20260926.log",
    "server-20260927.log",
    "server-20260928.log",
    "server-20260929.log",
)


def corpus_log():
    """The pinned 0.3.6 capture log, or None when that tree is gone.

    Deliberately does *not* fall back to whatever `server-*.log` happens to
    exist.  A 0.4.4 capture is a different build with different frame counts, so
    substituting it would silently turn "the fixture is missing" into 40
    assertion failures about bytes nobody measured.
    """
    from uslocalserver import paths                       # noqa: PLC0415
    override = os.environ.get("DFO_CORPUS_LOG")
    if override:
        path = Path(override)
        return path if path.exists() else None
    for name in CORPUS_CANDIDATES:
        candidate = paths.LOGS_DIR / name
        if candidate.exists():
            return candidate
    return None


def any_server_log():
    """The newest `server-*.log` on disk, whatever release wrote it."""
    from uslocalserver import paths                       # noqa: PLC0415
    logs = sorted(paths.LOGS_DIR.glob("server-*.log"))
    return logs[-1] if logs else None


def require_corpus():
    """The corpus log, or `SkipTest` naming the tree that has to be restored."""
    path = corpus_log()
    if path is None:
        from uslocalserver import paths                       # noqa: PLC0415
        newest = any_server_log()
        hint = (f"; newest log present is {newest.name}, which is a different "
                f"capture and not a substitute" if newest else "")
        raise unittest.SkipTest(
            f"no 0.3.6 capture corpus under {paths.LOGS_DIR} (wanted "
            f"{CORPUS_CANDIDATES[0]}); the DFO110-0.3.6 reference tree that "
            f"held it is not on disk{hint}. Set DFO_CORPUS_LOG to override.")
    return path


def skip_without_corpus(func):
    """Decorator for a module or a single test that needs the capture corpus."""
    def wrapper(*args, **kwargs):
        require_corpus()
        return func(*args, **kwargs)
    wrapper.__name__ = getattr(func, "__name__", "wrapper")
    wrapper.__doc__ = getattr(func, "__doc__", None)
    return wrapper


def skip_module_without_corpus() -> None:
    """Call at import time in a module whose every test needs the corpus."""
    require_corpus()

