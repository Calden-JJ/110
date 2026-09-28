"""The account row behind a game session.

`(1,4)`'s request body names a character-selection *slot*, not a character id,
so resolving it needs the account as well.  The reference reads that off the
`(1,1)` login request -- it logs `conn=2 client account_id=0` -- but the rewrite
does not decode the login body yet, so it takes the save's only account and
refuses to guess when there is more than one.  A two-account save needs the
login field pinned down, not a default.

`cera` and `premium_contracts` are what the `(1,4)` role-selection body and
its line read -- the cera the line prints, and the countdown pair
`game.character.roleselection` writes at `[5:8]`/`[37:40]`.
"""
from __future__ import annotations

import sqlite3

TABLE = "accounts"
CONTRACTS_TABLE = "account_premium_contracts"


def sole_account(conn: sqlite3.Connection) -> int:
    rows = conn.execute(f'select account_id from "{TABLE}" order by account_id').fetchall()
    if len(rows) != 1:
        raise LookupError(f'save has {len(rows)} "{TABLE}" rows; the (1,1) login body has '
                          "to be decoded before this server can pick one")
    return rows[0][0]


def cera(conn: sqlite3.Connection, account_id: int) -> int | None:
    """The account's cash balance, or None when the save has no such row.

    The reference's `SELECTION-4` line prints it (`cera=96500`); the body
    itself does not carry it -- see `roleselection`'s docstring.
    """
    row = conn.execute(f'select cera from "{TABLE}" where account_id = ?',
                       (account_id,)).fetchone()
    return None if row is None else row[0]


def premium_contracts(conn: sqlite3.Connection, account_id: int
                      ) -> tuple[tuple[int, int], ...]:
    """The account's contracts as `(premium_type, expires_at)`, `premium_type`
    ascending -- both fields of the countdown pair `(1,4)` writes, and the
    first row is the `{type}:{remaining}` the line prints.

    Only the primary key orders these; an account with several types is
    inferred to put the lowest first (no capture has one).
    """
    rows = conn.execute(
        f'select premium_type, expires_at from "{CONTRACTS_TABLE}" '
        f'where account_id = ? order by premium_type', (account_id,)).fetchall()
    return tuple((row[0], row[1]) for row in rows)
