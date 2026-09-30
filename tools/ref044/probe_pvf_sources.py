"""Can the 0.4.4 pvf-cache replace the 69 tables 0.3.6 embedded?

0.3.6's 69 JSON tables each carried a top-level `source` naming the client file
they were derived from (`list/map.lst`, `etc/disjoint.etc`, `monster/monsterexp.tbl`,
`stackable/cash/inven_upgradekit1.stk`, ...).  The 0.4.4 exe no longer carries
those tables at all, but the release ships a 926 MB SQLite mirror of the whole
`Script.pvf` (`Server\\Data\\pvf-cache\\<sha>.db`) with 493,781 rows in
`scripts(path, payload, sha256)`.

This asks the only question that matters for re-pointing the data layer: are
those source files there, and is the payload something we can parse?

Usage:
    python tools/probe_pvf_sources.py            # the 69 derived sources
    python tools/probe_pvf_sources.py list/map.lst
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from uslocalserver import paths                                     # noqa: E402

CACHE = paths.for_version("0.4.4").pvf_cache_db()
TABLES_DIR = REPO / "data" / "tables"


def derived_sources() -> list[str]:
    """Every `source` string the 0.3.6 tables name, deduplicated and ordered."""
    seen: list[str] = []
    for path in sorted(TABLES_DIR.glob("[0-9][0-9][0-9]_*.json")):
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        src = obj.get("source") if isinstance(obj, dict) else None
        if isinstance(src, str) and src.strip():
            name = src.split("\n")[0].split(";")[0].strip()
            if name not in seen:
                seen.append(name)
    return seen


def main() -> int:
    if CACHE is None or not Path(CACHE).exists():
        raise SystemExit("no pvf-cache on this release")
    print(f"cache {CACHE}  {Path(CACHE).stat().st_size / 1e6:.1f} MB")
    conn = sqlite3.connect(f"file:{Path(CACHE).as_posix()}?mode=ro", uri=True)

    if len(sys.argv) > 1:
        for want in sys.argv[1:]:
            row = conn.execute("select payload, sha256 from scripts where path=?",
                               (want,)).fetchone()
            if row is None:
                print(f"MISS {want}")
                continue
            payload = row[0]
            print(f"HIT  {want}  {len(payload)}B")
            print(f"     first 160 bytes: {payload[:160]!r}")
        return 0

    sources = derived_sources()
    print(f"distinct sources named by the 69 tables: {len(sources)}\n")

    hit = miss = 0
    for name in sources:
        row = conn.execute("select length(payload) from scripts where path=?",
                           (name,)).fetchone()
        if row is None:
            miss += 1
            print(f"  MISS  {name}")
        else:
            hit += 1
            print(f"  hit   {name:<52} {row[0]:>10,} B")
    print(f"\n{hit} hit / {miss} miss of {len(sources)}")

    # A few obvious neighbours, in case the paths drifted (case, extension).
    print("\n--- does the cache hold anything like 'list/map.lst'? ---")
    for pattern in ("list/%", "etc/%", "monster/%", "stackable/%"):
        n = conn.execute("select count(*) from scripts where path like ?",
                         (pattern,)).fetchone()[0]
        print(f"  {pattern:<14} {n:>7,} rows")
    print("\n--- neighbour sample around list/ ---")
    for path, n in conn.execute(
            "select path, length(payload) from scripts where path like 'list/%' "
            "order by path limit 25"):
        print(f"  {path:<50} {n:>10,} B")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
