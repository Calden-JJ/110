"""Live schema introspection, row access, and drift detection.

Never derive a table's shape from `BootstrapSchema.sql`.  The server creates
the tables and *then* runs a migration layer, so the file describes a database
that never exists -- 17 columns and one index short of the real save (see
`migrations.py`).  Because `CREATE TABLE IF NOT EXISTS` is idempotent the
shortfall is silent: it shows up much later as fields that are always NULL.

Everything here therefore reads the live connection.  That is correct for the
real save and for one we built ourselves, and it makes the two comparable:
`diff(expected=..., actual=...)` is what proves a rebuilt database is faithful.

Columns come from `pragma_table_info`; the index `WHERE` clause, the table's
CHECK/FOREIGN/UNIQUE clauses and `AUTOINCREMENT` come from the `CREATE TABLE`
text in `sqlite_master` (parsed with a paren-aware splitter, not a regex that
would trip over `CHECK(count >= 0)`).
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

CONSTRAINT_KEYWORDS = frozenset({"constraint", "primary", "unique", "check", "foreign"})
_CHECK = re.compile(r"\bcheck\s*\(", re.I)
_WHERE = re.compile(r"\bwhere\b", re.I)
_QUOTES = "\"'`[]"


def _norm(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip().rstrip(",").strip().lower()


def _balanced(sql: str, start: int) -> str:
    """The parenthesised group beginning at `start`, brackets included."""
    depth = 0
    for i in range(start, len(sql)):
        if sql[i] == "(":
            depth += 1
        elif sql[i] == ")":
            depth -= 1
            if depth == 0:
                return sql[start:i + 1]
    raise ValueError(f"unbalanced parentheses at {start}: {sql[start:start + 40]!r}")


def _split_top_level(body: str) -> list[str]:
    parts, depth, start = [], 0, 0
    for i, c in enumerate(body):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(body[start:i])
            start = i + 1
    parts.append(body[start:])
    return [p.strip() for p in parts if p.strip()]


def _checks_in(clause: str) -> tuple[str, ...]:
    return tuple(_norm(_balanced(clause, m.end() - 1)) for m in _CHECK.finditer(clause))


def _head_token(clause: str) -> str:
    token = clause.strip().split(None, 1)[0] if clause.strip() else ""
    if token[:1] in _QUOTES:
        return token.strip(_QUOTES)
    return token


@dataclass(frozen=True, slots=True)
class Column:
    name: str
    type: str
    notnull: bool
    default: str | None
    pk: int
    checks: tuple[str, ...] = ()

    def shape(self) -> tuple:
        return (self.type, self.notnull, self.default, self.pk, self.checks)


@dataclass(frozen=True, slots=True)
class ForeignKey:
    table: str
    columns: tuple[str, ...]
    ref_table: str
    ref_columns: tuple[str, ...]
    on_update: str
    on_delete: str


@dataclass(frozen=True, slots=True)
class Index:
    name: str
    table: str
    unique: bool
    partial: bool
    where: str | None
    columns: tuple[str, ...]
    sql: str | None = None

    def shape(self) -> tuple:
        return (self.table, self.unique, self.partial,
                _norm(self.where or ""), self.columns)


@dataclass(frozen=True, slots=True)
class Table:
    name: str
    columns: tuple[Column, ...]
    constraints: tuple[str, ...]      # normalized table-level PRIMARY/UNIQUE/CHECK/FOREIGN
    autoincrement: bool
    foreign_keys: tuple[ForeignKey, ...]
    sql: str

    @property
    def column_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns)

    @property
    def pk_columns(self) -> tuple[str, ...]:
        return tuple(c.name for c in sorted(
            (c for c in self.columns if c.pk), key=lambda c: c.pk))

    @property
    def checks(self) -> tuple[str, ...]:
        return tuple(c for c in self.constraints if c.startswith("check"))

    def column(self, name: str) -> Column:
        for c in self.columns:
            if c.name == name:
                return c
        raise KeyError(f"{self.name} has no column {name!r}")


@dataclass(frozen=True, slots=True)
class Schema:
    tables: Mapping[str, Table]
    indexes: Mapping[str, Index]
    triggers: Mapping[str, str]

    @property
    def table_names(self) -> tuple[str, ...]:
        return tuple(sorted(self.tables))

    def table(self, name: str) -> Table:
        try:
            return self.tables[name]
        except KeyError:
            raise KeyError(f"no table {name!r}; have {len(self.tables)}") from None

    @classmethod
    def from_connection(cls, conn: sqlite3.Connection) -> "Schema":
        tables: dict[str, Table] = {}
        rows = conn.execute(
            "select name, sql from sqlite_master where type='table' "
            "and name not like 'sqlite_%' order by name").fetchall()
        for name, sql in rows:
            info = conn.execute(f'pragma table_info("{name}")').fetchall()
            clauses, constraints = _split_definition(sql)
            columns = tuple(
                Column(name=cname, type=ctype, notnull=bool(notnull), default=dflt,
                       pk=pk, checks=_checks_in(clauses.get(cname.lower(), "")))
                for _, cname, ctype, notnull, dflt, pk in info)
            tables[name] = Table(
                name=name,
                columns=columns,
                constraints=tuple(constraints),
                autoincrement=bool(re.search(r"\bautoincrement\b", sql, re.I)),
                foreign_keys=_foreign_keys(conn, name),
                sql=sql,
            )
        return cls(tables=tables, indexes=_indexes(conn), triggers=_triggers(conn))


def _split_definition(sql: str) -> tuple[dict[str, str], list[str]]:
    """Split a CREATE TABLE body into per-column clauses and table constraints."""
    body = _balanced(sql, sql.index("("))[1:-1]
    clauses: dict[str, str] = {}
    constraints: list[str] = []
    for part in _split_top_level(body):
        head = _head_token(part)
        if head.lower() in CONSTRAINT_KEYWORDS:
            constraints.append(_norm(part))
        else:
            clauses[head.lower()] = part
    return clauses, constraints


def _foreign_keys(conn: sqlite3.Connection, table: str) -> tuple[ForeignKey, ...]:
    # pragma foreign_key_list returns one row per column; composite keys share an id.
    grouped: dict[int, list[tuple]] = {}
    for row in conn.execute(f'pragma foreign_key_list("{table}")'):
        grouped.setdefault(row[0], []).append(row)
    out = []
    for key_id in sorted(grouped):
        rows = sorted(grouped[key_id], key=lambda r: r[1])
        out.append(ForeignKey(
            table=table,
            columns=tuple(r[3] for r in rows),
            ref_table=rows[0][2],
            ref_columns=tuple(r[4] for r in rows),
            on_update=rows[0][5],
            on_delete=rows[0][6],
        ))
    return tuple(out)


def _indexes(conn: sqlite3.Connection) -> dict[str, Index]:
    out: dict[str, Index] = {}
    rows = conn.execute(
        "select name, tbl_name, sql from sqlite_master where type='index' "
        "and name not like 'sqlite_%' order by name").fetchall()
    for name, table, sql in rows:
        detail = conn.execute(f'pragma index_list("{table}")').fetchall()
        meta = next((d for d in detail if d[1] == name), None)
        unique = bool(meta[2]) if meta else False
        partial = bool(meta[4]) if meta else False
        where = None
        if sql:
            m = _WHERE.search(sql)
            if m:
                where = sql[m.end():].strip()
        out[name] = Index(
            name=name, table=table, unique=unique, partial=partial, where=where,
            columns=tuple(r[2] for r in conn.execute(f'pragma index_info("{name}")')),
            sql=sql,
        )
    return out


def _triggers(conn: sqlite3.Connection) -> dict[str, str]:
    return {name: _norm(sql or "") for name, sql in conn.execute(
        "select name, sql from sqlite_master where type='trigger' order by name")}


#: The fields that carry a difference.  `index_tables` is context, not a
#: difference, so `clean` cannot just walk every field.
_DIFF_FIELDS = (
    "missing_tables", "extra_tables", "missing_columns", "extra_columns",
    "changed_columns", "changed_tables", "missing_indexes", "extra_indexes",
    "changed_indexes", "changed_triggers", "changed_foreign_keys",
)


@dataclass(frozen=True, slots=True)
class DriftReport:
    """What an `actual` schema is missing or has changed relative to `expected`."""
    missing_tables: tuple[str, ...] = ()
    extra_tables: tuple[str, ...] = ()
    missing_columns: tuple[tuple[str, str], ...] = ()
    extra_columns: tuple[tuple[str, str], ...] = ()
    changed_columns: tuple[tuple[str, str, str], ...] = ()
    changed_tables: tuple[tuple[str, str], ...] = ()
    missing_indexes: tuple[str, ...] = ()
    extra_indexes: tuple[str, ...] = ()
    changed_indexes: tuple[tuple[str, str], ...] = ()
    changed_triggers: tuple[tuple[str, str], ...] = ()
    changed_foreign_keys: tuple[tuple[str, str], ...] = ()
    #: index name -> table, so an index-only difference still names its table.
    index_tables: Mapping[str, str] = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not any(self._differences())

    def _differences(self) -> list:
        return [v for name in _DIFF_FIELDS for v in (getattr(self, name),) if v]

    @property
    def affected_tables(self) -> tuple[str, ...]:
        names = set(self.missing_tables) | set(self.extra_tables)
        names |= {t for t, _ in self.missing_columns + self.extra_columns + self.changed_tables}
        names |= {t for t, _, _ in self.changed_columns}
        names |= {t for t, _ in self.changed_foreign_keys}
        names |= {self.index_tables[n] for n in
                  self.missing_indexes + self.extra_indexes
                  if n in self.index_tables}
        names |= {self.index_tables[n] for n, _ in self.changed_indexes
                  if n in self.index_tables}
        return tuple(sorted(names))

    def summary(self) -> str:
        if self.clean:
            return "schemas match"
        bits = [
            f"{len(self.missing_columns)} missing column(s)",
            f"{len(self.extra_columns)} extra column(s)",
            f"{len(self.changed_columns)} changed column(s)",
            f"{len(self.missing_indexes)} missing index(es)",
            f"{len(self.extra_indexes)} extra index(es)",
            f"{len(self.changed_indexes)} changed index(es)",
            f"{len(self.changed_triggers)} changed trigger(s)",
            f"{len(self.changed_tables)} other table difference(s)",
            f"{len(self.changed_foreign_keys)} changed foreign key(s)",
        ]
        return ", ".join(b for b in bits if not b.startswith("0 "))

    def __str__(self) -> str:
        if self.clean:
            return "schemas match"
        lines = [self.summary()]
        for table in self.missing_tables:
            lines.append(f"  - missing table {table}")
        for table in self.extra_tables:
            lines.append(f"  + extra table {table}")
        for table, column in self.missing_columns:
            lines.append(f"  - {table}.{column}")
        for table, column in self.extra_columns:
            lines.append(f"  + {table}.{column}")
        for table, column, detail in self.changed_columns:
            lines.append(f"  ~ {table}.{column}: {detail}")
        for table, detail in self.changed_tables:
            lines.append(f"  ~ {table}: {detail}")
        for name in self.missing_indexes:
            lines.append(f"  - index {name}")
        for name in self.extra_indexes:
            lines.append(f"  + index {name}")
        for name, detail in self.changed_indexes:
            lines.append(f"  ~ index {name}: {detail}")
        for name, detail in self.changed_triggers:
            lines.append(f"  ~ trigger {name}: {detail}")
        for table, detail in self.changed_foreign_keys:
            lines.append(f"  ~ {table} foreign key: {detail}")
        return "\n".join(lines)


def diff(*, expected: Schema, actual: Schema) -> DriftReport:
    """Everything in `expected` that `actual` does not reproduce."""
    missing_tables, extra_tables = [], []
    missing_columns, extra_columns, changed_columns = [], [], []
    changed_tables, changed_fks = [], []

    for name in sorted(set(expected.tables) - set(actual.tables)):
        missing_tables.append(name)
    for name in sorted(set(actual.tables) - set(expected.tables)):
        extra_tables.append(name)

    for name in sorted(set(expected.tables) & set(actual.tables)):
        exp, act = expected.tables[name], actual.tables[name]
        exp_names, act_names = exp.column_names, act.column_names
        for column in exp_names:
            if column not in act_names:
                missing_columns.append((name, column))
        for column in act_names:
            if column not in exp_names:
                extra_columns.append((name, column))
        for column in exp_names:
            if column not in act_names:
                continue
            e, a = exp.column(column), act.column(column)
            if e.shape() != a.shape():
                changed_columns.append((name, column, _column_detail(e, a)))
        if set(exp_names) == set(act_names) and exp_names != act_names:
            changed_tables.append((name, f"column order {act_names} != {exp_names}"))
        if exp.constraints != act.constraints:
            changed_tables.append((name, "table constraints differ: "
                                   f"{act.constraints} != {exp.constraints}"))
        if exp.autoincrement != act.autoincrement:
            changed_tables.append((name, f"autoincrement {act.autoincrement} != {exp.autoincrement}"))
        if exp.foreign_keys != act.foreign_keys:
            changed_fks.append((name, f"{act.foreign_keys} != {exp.foreign_keys}"))

    missing_indexes, extra_indexes, changed_indexes = [], [], []
    for name in sorted(set(expected.indexes) - set(actual.indexes)):
        missing_indexes.append(name)
    for name in sorted(set(actual.indexes) - set(expected.indexes)):
        extra_indexes.append(name)
    for name in sorted(set(expected.indexes) & set(actual.indexes)):
        e, a = expected.indexes[name], actual.indexes[name]
        if e.shape() != a.shape():
            changed_indexes.append((name, f"{a.shape()} != {e.shape()}"))

    changed_triggers = [
        (name, f"{actual.triggers[name]!r} != {expected.triggers[name]!r}")
        for name in sorted(set(expected.triggers) & set(actual.triggers))
        if expected.triggers[name] != actual.triggers[name]
    ]
    for name in sorted(set(expected.triggers) - set(actual.triggers)):
        changed_triggers.append((name, "missing"))
    for name in sorted(set(actual.triggers) - set(expected.triggers)):
        changed_triggers.append((name, "unexpected"))

    return DriftReport(
        index_tables={**{n: i.table for n, i in expected.indexes.items()},
                      **{n: i.table for n, i in actual.indexes.items()}},
        missing_tables=tuple(missing_tables),
        extra_tables=tuple(extra_tables),
        missing_columns=tuple(missing_columns),
        extra_columns=tuple(extra_columns),
        changed_columns=tuple(changed_columns),
        changed_tables=tuple(changed_tables),
        missing_indexes=tuple(missing_indexes),
        extra_indexes=tuple(extra_indexes),
        changed_indexes=tuple(changed_indexes),
        changed_triggers=tuple(changed_triggers),
        changed_foreign_keys=tuple(changed_fks),
    )


def _column_detail(e: Column, a: Column) -> str:
    bits = []
    for field in ("type", "notnull", "default", "pk", "checks"):
        ev, av = getattr(e, field), getattr(a, field)
        if ev != av:
            bits.append(f"{field} {av!r} != {ev!r}")
    return "; ".join(bits)


def apply_ddl(conn: sqlite3.Connection, statements: Iterable[str]) -> None:
    """Run DDL statements in order.  Callers that need atomicity wrap this."""
    for statement in statements:
        conn.execute(statement)


def connect(path: str | Path, *, readonly: bool = False) -> sqlite3.Connection:
    """Open a save.

    `isolation_level=None` keeps the connection out of an implicit transaction,
    without which `PRAGMA foreign_keys=ON` is accepted and then silently does
    nothing.  A read-only connection must not be switched to WAL: SQLite
    answers that with "attempt to write a readonly database".
    """
    if readonly:
        conn = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True,
                               isolation_level=None)
    else:
        conn = sqlite3.connect(str(path), isolation_level=None)
        conn.execute("pragma journal_mode=wal")
    conn.row_factory = sqlite3.Row
    conn.execute("pragma foreign_keys=on")
    return conn


class Repository:
    """Column-checked row access for one table.

    Identifiers are validated against the `Table` descriptor first, so a typo
    is a KeyError naming the bad column rather than a half-built SQL string.
    """

    def __init__(self, conn: sqlite3.Connection, table: Table) -> None:
        self.conn = conn
        self.table = table

    @classmethod
    def of(cls, conn: sqlite3.Connection, table: str) -> "Repository":
        return cls(conn, Schema.from_connection(conn).table(table))

    def _checked(self, names: Iterable[str]) -> tuple[str, ...]:
        names = tuple(names)
        for name in names:
            if name not in self.table.column_names:
                raise KeyError(f"{self.table.name} has no column {name!r}")
        return names

    def get(self, *pk: Any) -> sqlite3.Row | None:
        keys = self.table.pk_columns
        if len(pk) != len(keys):
            raise ValueError(f"{self.table.name} primary key is {keys}, got {len(pk)} value(s)")
        where = " and ".join(f'"{k}" = ?' for k in keys)
        return self.conn.execute(
            f'select * from "{self.table.name}" where {where}', pk).fetchone()

    def select(self, **where: Any) -> list[sqlite3.Row]:
        names = self._checked(where)
        clause = (" where " + " and ".join(f'"{n}" = ?' for n in names)) if names else ""
        return self.conn.execute(
            f'select * from "{self.table.name}"{clause}', tuple(where[n] for n in names)).fetchall()

    def count(self, **where: Any) -> int:
        names = self._checked(where)
        clause = (" where " + " and ".join(f'"{n}" = ?' for n in names)) if names else ""
        return self.conn.execute(
            f'select count(*) from "{self.table.name}"{clause}',
            tuple(where[n] for n in names)).fetchone()[0]

    def insert(self, row: Mapping[str, Any]) -> None:
        names = self._checked(row)
        marks = ", ".join("?" * len(names))
        self.conn.execute(
            f'insert into "{self.table.name}" ({_columns(names)}) values ({marks})',
            tuple(row[n] for n in names))

    def upsert(self, row: Mapping[str, Any], *, conflict: Sequence[str] | None = None) -> None:
        names = self._checked(row)
        keys = tuple(conflict) if conflict is not None else self.table.pk_columns
        self._checked(keys)
        updates = [n for n in names if n not in keys]
        action = (", ".join(f'"{n}" = excluded."{n}"' for n in updates)
                  if updates else "nothing")
        self.conn.execute(
            f'insert into "{self.table.name}" ({_columns(names)}) '
            f'values ({", ".join("?" * len(names))}) '
            f'on conflict ({_columns(keys)}) do update set {action}',
            tuple(row[n] for n in names))

    def update(self, pk: Any, **values: Any) -> int:
        names = self._checked(values)
        keys = self.table.pk_columns
        if len(keys) != 1:
            raise ValueError(f"{self.table.name} has a composite key {keys}; use upsert")
        assignments = ", ".join(f'"{n}" = ?' for n in names)
        cur = self.conn.execute(
            f'update "{self.table.name}" set {assignments} where "{keys[0]}" = ?',
            tuple(values[n] for n in names) + (pk,))
        return cur.rowcount

    def delete(self, *pk: Any) -> int:
        keys = self.table.pk_columns
        if len(pk) != len(keys):
            raise ValueError(f"{self.table.name} primary key is {keys}, got {len(pk)} value(s)")
        where = " and ".join(f'"{k}" = ?' for k in keys)
        return self.conn.execute(
            f'delete from "{self.table.name}" where {where}', pk).rowcount

    def __iter__(self) -> Iterator[sqlite3.Row]:
        return iter(self.conn.execute(f'select * from "{self.table.name}"').fetchall())


def _columns(names: Iterable[str]) -> str:
    return ", ".join(f'"{n}"' for n in names)
