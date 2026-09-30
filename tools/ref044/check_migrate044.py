"""Can `migrations.py` reconstruct a 0.4.4 save from 0.4.4's own bootstrap script?

This is the migration's acceptance test, run before changing anything: apply
the *current* upgrade layer (which was derived from the 0.3.6 save) to the 0.4.4
script and diff the result against the live 0.4.4 save.  Whatever the report
still names is precisely what has to be added for 0.4.4 support.
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from uslocalserver import paths                            # noqa: E402
from uslocalserver.persistence import migrations, schema   # noqa: E402

REF = "0.4.4"
layout = paths.for_version(REF)
real = schema.Schema.from_connection(schema.connect(layout.save_db, readonly=True))
print(f"live {REF}: {len(real.tables)} tables, {len(real.indexes)} indexes, "
      f"{len(real.triggers)} triggers")

conn = sqlite3.connect(":memory:", isolation_level=None)
script = layout.bootstrap_sql.read_text(encoding="utf-8")
conn.executescript(script)
boot = schema.Schema.from_connection(conn)
print(f"bootstrap  : {len(boot.tables)} tables, {len(boot.indexes)} indexes, "
      f"{len(boot.triggers)} triggers")

applied = migrations.for_script(script)
print(f"upgrade set: {'CURRENT' if applied is migrations.CURRENT else 'LEGACY'} "
      f"({len(applied)} migrations, "
      f"{sum(len(m.definitions) for m in applied)} columns, "
      f"{sum(len(m.ddl) for m in applied)} ddl)")
migrations.apply(conn, script=script)
built = schema.Schema.from_connection(conn)
report = schema.diff(expected=real, actual=built)
print(f"after migrations: {len(built.tables)} tables, {len(built.indexes)} indexes, "
      f"{len(built.triggers)} triggers")
print()
print("REPORT (what 0.4.4 needs beyond the current upgrade layer):")
print(report)
print()

if report.missing_columns:
    print("=== exact definitions for the missing columns, from the live save ===")
    for table, column in report.missing_columns:
        sql = real.table(table).sql
        start = sql.lower().index(column.lower())
        # print the clause around the column
        depth = 0
        for i in range(start, len(sql)):
            if sql[i] == "(":
                depth += 1
            elif sql[i] == ")":
                if depth == 0:
                    print(f'    "{sql[start:i].strip()}"')
                    break
                depth -= 1
            elif sql[i] == "," and depth == 0:
                print(f'    "{sql[start:i].strip()}"')
                break
if report.missing_indexes:
    print("=== missing index DDL ===")
    for name in report.missing_indexes:
        print(f"    {real.indexes[name].sql}")
if report.changed_triggers:
    print("=== changed triggers ===")
    for name, detail in report.changed_triggers:
        print(f"    {name}: {detail[:200]}")

sys.exit(0 if report.clean else 1)
