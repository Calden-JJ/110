"""`(1,4)`'s 1296B role-selection body: a captured blob and its live regions.

The body answers a character pick -- it is the second of the run's four frames,
between the `(0,173)` settings push (`account.clientsettings`) and `(0,1370)` +
`(0,2082)`.  Eleven sends exist across seven sessions, all on the wire at
`raw=1312` (16B header + 1296B body), and the six dumped whole pin six regions::

    [5:9]    u32le   now, the build timestamp in unix seconds
    [9]      u8      the session key, slot_index + 1
    [36]     u8      the contract's premium_type
    [37:41]  u32le   expires_at - now
    [45:49]  u32le   the account's cera
    [249]    u8      the character's town_id

Everything else -- 1286 of the bytes minus those six regions -- is
byte-identical across two characters, five levels, two towns and two cera
balances, so it ships as a constant, `data/game/selection4.bin` (the
`packetHexLog` corpus session's own body, 09-26 22:16:34;
`tools/extract_game_replies.py` writes it).

**The logged size.**  The line reports 1286B, ten less than the 1296 it sends,
and across its 39 lines the number takes three values that decompose exactly::

    1188  the first login (09-25 08:57:20, level 1) -- no tutorial flags sent
    1277  + 89, the flag block at [254:344): a count byte 0x59 = 89 and the
          ids 0..88, matching the `TUTORIAL-FLAGS` note beside each line
          (`sent 89 seen flag(s) max=88`)
    1286  + 9, the contract record at [36:45): premium_type, the countdown,
          and four bytes that never differ in any dump

and each is padded up to the next 16-byte multiple: 1188 -> 1200, 1277 ->
1280, 1286 -> **1296**, the size that goes on the wire.

**The countdown pair.**  `[36]`/`[37:41]` are the account's
`account_premium_contracts` row: the 33 post-contract lines all print
`contracts=92:{N}` with N = `expires_at - now` to the second, 0 residual, and
the body writes the same number.  The six pre-contract lines print no
`contracts=` tail at all.

**now, and the epoch that was not.**  `[5:9]` reads 1790432194 exactly at the
corpus timestamp -- a plain unix time.  It used to be written here as a 3-byte
value counted from a constant "epoch" 1778384896 = 0x6A000000; that is an
artifact: 0x6a is merely the top byte of `now`, so the constant holds only
until 2026-11-20 20:08 +08, when the high byte rolls to 0x6b.  The body's own
convention is little-endian u32 -- the rows after `[49]` are a 6-byte-period
table of `ffff0000` sentinels -- so the field is written as one.

**The cera.**  `[45:49]` is the account's cash balance, the same number the
line prints, and the same 4 bytes, in the same position, that the `(0,53)`
frame carries (`01` + u32le(cera) + 11 zero bytes; `tools/solve_s2c_algo.py`).
Its value never moved during the dump window -- all six dumps read 96500, and
so do the seven `(0,53)` frames from 09-26 22:16 to 09-27 23:16:24 -- so the
dumps alone cannot tell a live field from a constant.  What settles it is the
two 09-27 23:16 purchases: `(0,53)` then reads 96475 (96500 - 25) and 95575
(96500 - 925), which is the save's cera today, while the line's `cera=` takes
four values across the logs (100000, 99870, 99005, 96500).

**The line.**  `privileges=5/12` never varies in the 82 lines that print it
and is in no table -- `PRIVILEGES` is a stand-in.  Name, job and level are in
the line only; the body does not carry them.

**Inferred, no capture**: an account with no contract row.  The 1277/1188
bodies were never dumped, so neither the record's absence nor the resulting
size (the padding rule says 1280, not 1296) is observed; `NO_EXPIRY` writes a
zero countdown into the full 1296B blob as a stand-in.  Likewise an account
with more than one contract row -- the first in `premium_type` order is what
the pair and the line use, and the line prints only that one.  Neither shape
exists in the save, which has had exactly one type-92 row since 09-25 13:55.
"""
from __future__ import annotations

import sqlite3
import struct
from dataclasses import dataclass
from functools import lru_cache

from ... import paths
from ...persistence import accounts, characters
from ...protocol import frame

OPCODE = frame.Opcode(1, 4, frame.OpcodeEncoding.U8_U16LE, True)

#: The frame's size, and the content size the reference's line reports for it.
BODY_SIZE = 1296
LOGGED_SIZE = 1286

#: Where the run's four frames sit, 0-based: the `(0,173)` push is 0
#: (`account.clientsettings.SELECTION_AT`), this body is 1.
RUN_AT = 1

#: The six live regions.
NOW_AT = 5
KEY_AT = 9
CONTRACT_TYPE_AT = 36
CONTRACT_END_AT = 37
CERA_AT = 45
TOWN_AT = 249

#: What `[37:41]` counts down to when the account has no contract row.
NO_EXPIRY = 0

#: The reference's line prints this for every account it has been seen for.
PRIVILEGES = "5/12"

TEMPLATE_PATH = paths.DATA_DIR / "game" / "selection4.bin"


@lru_cache(maxsize=1)
def template() -> bytes:
    """The captured blob, `BODY_SIZE` bytes of it."""
    blob = TEMPLATE_PATH.read_bytes()
    if len(blob) != BODY_SIZE:
        raise ValueError(f"{TEMPLATE_PATH} is {len(blob)}B, expected {BODY_SIZE}")
    return blob


@dataclass(frozen=True, slots=True)
class Pick:
    """What the `(1,4)` run answers with, and what its line reports."""

    account: int
    slot: int
    name: str
    job: int
    level: int
    cera: int
    town: int
    contracts: tuple[tuple[int, int], ...]     # (premium_type, expires_at)
    now: int

    @classmethod
    def of(cls, conn: sqlite3.Connection, account: int, summary: "characters.CharacterSummary",
           now: int) -> "Pick":
        row = accounts.cera(conn, account)
        return cls(account=account, slot=summary.slot_index, name=summary.name,
                   job=summary.class_id, level=summary.level,
                   cera=0 if row is None else row, town=summary.town_id,
                   contracts=accounts.premium_contracts(conn, account), now=now)

    @property
    def key(self) -> int:
        """`[9]`: the session key the reference's own lines print as `key=`."""
        return self.slot + 1

    @property
    def premium_type(self) -> int:
        return self.contracts[0][0] if self.contracts else 0

    @property
    def remaining(self) -> int:
        """`[37:41]` before masking: what the reference prints after the colon.

        Floored at zero -- the field is unsigned, and an expired row is at
        worst a zero-second contract.
        """
        expiry = self.contracts[0][1] if self.contracts else NO_EXPIRY
        return max(0, expiry - self.now)

    def body(self) -> bytes:
        """The 1296B body: the captured blob with the six regions written."""
        out = bytearray(template())
        out[NOW_AT:NOW_AT + 4] = struct.pack("<I", self.now)
        out[KEY_AT] = self.key & 0xFF
        out[CONTRACT_TYPE_AT] = self.premium_type & 0xFF
        out[CONTRACT_END_AT:CONTRACT_END_AT + 4] = struct.pack("<I", self.remaining)
        out[CERA_AT:CERA_AT + 4] = struct.pack("<I", self.cera)
        out[TOWN_AT] = self.town & 0xFF
        return bytes(out)

    def note(self) -> str:
        """The `SELECTION-4` prose after the bare `conn=N `."""
        text = (f"built {LOGGED_SIZE}B role-selection response for account "
                f"{self.account}: slot={self.slot} key={self.key} "
                f"name='{self.name}' job={self.job} level={self.level} "
                f"cera={self.cera} privileges={PRIVILEGES}")
        if self.contracts:
            text += f" contracts={self.premium_type}:{self.remaining}"
        return text
