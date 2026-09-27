"""The account row behind a game session.

`(1,4)`'s request body names a character-selection *slot*, not a character id,
so resolving it needs the account as well.  The reference reads that off the
`(1,1)` login request -- it logs `conn=2 client account_id=0` -- but the rewrite
does not decode the login body yet, so it takes the save's only account and
refuses to guess when there is more than one.  A two-account save needs the
login field pinned down, not a default.
"""
from __future__ import annotations

import sqlite3

TABLE = "accounts"


def sole_account(conn: sqlite3.Connection) -> int:
    rows = conn.execute(f'select account_id from "{TABLE}" order by account_id').fetchall()
    if len(rows) != 1:
        raise LookupError(f'save has {len(rows)} "{TABLE}" rows; the (1,1) login body has '
                          "to be decoded before this server can pick one")
    return rows[0][0]
