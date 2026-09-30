"""Survey the 0.4.4 pvf-cache: is it where the 69 embedded JSON tables went?

0.4.4's exe no longer carries the 81 MB plaintext JSON region that 0.3.6 had --
the 69 resource names survive in the manifest but the bodies do not, and the
whole image is 41.7 MB.  Meanwhile 0.4.4 ships
`Server\\Data\\pvf-cache\\<sha256>.db`, 883 MB.  This prints that database's
shape so the rewrite's data layer can be re-pointed instead of guessing.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DB = Path(r"E:\DFO_2.31.1.117\DFO110-0.4.4\Server\Data\pvf-cache"
          r"\4c4d9d6ee19f2d8a5243a5a457e35d51b88019b63ae3756ca19f2f457f85a9a9.db")


def main() -> int:
    print(f"db {DB}  {DB.stat().st_size / 1e6:.1f} MB")
    conn = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    print("\n--- sqlite_master ---")
    for row in conn.execute(
            "select type, name, tbl_name, length(sql) as n from sqlite_master "
            "order by type, name"):
        print(f"  {row['type']:8} {row['name']:<34} {row['tbl_name']:<22} sql={row['n']}")

    tables = [r[0] for r in conn.execute(
        "select name from sqlite_master where type='table' order by name")]
    print(f"\n--- tables: {len(tables)} ---")
    for t in tables:
        cols = [(r[1], r[2]) for r in conn.execute(f'pragma table_info("{t}")')]
        try:
            n = conn.execute(f'select count(*) from "{t}"').fetchone()[0]
        except sqlite3.Error as exc:                       # pragma: no cover
            n = f"ERR {exc}"
        print(f"  {t:<30} rows={n!s:<12} cols={[c for c, _ in cols]}")
        for row in conn.execute(f'select * from "{t}" limit 2'):
            d = dict(row)
            shown = {k: (f"<{len(v)}B>" if isinstance(v, (bytes, bytearray)) else
                         (v[:120] if isinstance(v, str) else v))
                     for k, v in d.items()}
            print(f"      {shown}")

    print("\n--- indexes ---")
    for row in conn.execute(
            "select name, tbl_name from sqlite_master where type='index'"):
        print(f"  {row[0]} on {row[1]}")

    # The 0.3.6 tables carried a top-level "source" naming the client file they
    # came from (list/map.lst, etc/disjoint.etc, ...).  If the cache stores PVF
    # paths, those strings are the join key between old and new.
    for t in tables:
        cols = [r[1] for r in conn.execute(f'pragma table_info("{t}")')]
        for probe in ("path", "source", "name", "key", "file"):
            if probe in cols:
                print(f"\n--- {t}.{probe} samples ---")
                for row in conn.execute(
                        f'select distinct "{probe}" from "{t}" limit 12'):
                    print(f"   {row[0]!r}")
                break

    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
