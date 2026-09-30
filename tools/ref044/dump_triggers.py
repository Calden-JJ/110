"""Print the trigger DDL of the active reference save, verbatim.

`migrations.py` rebuilds a save from the bootstrap script plus an upgrade layer;
the script carries most triggers but the server adds the rest at runtime, so
each release's added triggers have to be read back off the live save.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from uslocalserver import paths                            # noqa: E402
from uslocalserver.persistence import schema               # noqa: E402

REF = sys.argv[1] if len(sys.argv) > 1 else "0.4.4"
layout = paths.for_version(REF)
conn = schema.connect(layout.save_db, readonly=True)

boot = layout.bootstrap_sql.read_text(encoding="utf-8", errors="replace")
for name, sql in conn.execute(
        "select name, sql from sqlite_master where type='trigger' order by name"):
    in_script = f"trigger {name}" in boot or f'"{name}"' in boot
    print(f"--- {name}   {'(in bootstrap script)' if in_script else '(ADDED AT RUNTIME)'}")
    print(sql)
    print()
