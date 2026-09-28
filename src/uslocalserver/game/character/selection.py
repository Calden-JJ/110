"""The six roster/town acks: `(1,140)`, `(1,433)`, `(1,637)`, `(1,666)`,
`(1,707)`, `(1,848)`.

Each is answered with a constant frame.  Six `packetHexLog` logins (09-26
22:16 through 09-27 13:23) hold the whole family on both sides, and every
opcode's S->C body decrypts to exactly one distinct plaintext in all of them:
24B `01` + zeros for `(1,848)`, 8B `01` + zeros for `(1,433)` and `(1,637)`,
8B zeros for the other three.  Nothing in a reply reads the save, so these are
generated rather than replayed -- the capture holds one run per opcode, and a
client that sends one a second time would draw the replay script's last run
rather than its own answer again.

Per login the client sends `(1,848)`, `(1,433)`, `(1,637)` while the roster is
ready, then the town-entry burst, then a second `(1,433)`, `(1,140)`,
`(1,707)` and `(1,666)`.  None of the six moves the session's state: the
DISPATCH lines read `RosterReady->RosterReady` for `(1,848)`, `(1,637)` and
the roster `(1,433)`, `InTown->InTown` for the rest.

The notes are the reference's own wording, `1B reply` included -- it prints
that for the three replies whose bodies are 8B.  The requests behind them are
0B (`(1,848)`, `(1,637)`, `(1,666)`), 8B (`(1,433)`'s `0601020304050600`,
six one-byte entries behind their count byte and a trailing zero; `(1,707)`'s
`f188d71700000000`) and 16 zero bytes (`(1,140)`).  `(1,433)`'s note prints
the count it read, so it is the one note built from the request rather than
from the table.
"""
from __future__ import annotations

from dataclasses import dataclass

from ...protocol import frame

#: The three bodies the six replies share.
ZERO_8 = bytes(8)
ONE_8 = b"\x01" + bytes(7)
ONE_24 = b"\x01" + bytes(23)


@dataclass(frozen=True, slots=True)
class Ack:
    opcode: frame.Opcode
    body: bytes
    tag: str
    note: str                      # `{conn}` and `{n}` left for the logger


#: sub -> (reply body, the note after the bare `conn=N `).  `{n}` is the
#: request body's length and is filled by the server's note logger; the tag is
#: `SELECTION-{sub}`.
_TABLE = {
    140: (ZERO_8, "built S2C (1,140) 1B reply (request body {n}B)"),
    433: (ONE_8, "accepted {entries} request entries -> built S2C success "
                 "with zero entries"),
    637: (ONE_8, "built S2C (1,637) success"),
    666: (ZERO_8, "built S2C (1,666) 1B reply (request body {n}B)"),
    707: (ZERO_8, "built S2C (1,707) 1B reply (request body {n}B)"),
    848: (ONE_24, "built S2C (1,848) success"),
}


def handles(key: tuple[int, int]) -> bool:
    """Whether `key` is one of the six -- cheap enough for the frame loop."""
    return key[0] == 1 and key[1] in _TABLE


def entry_count(plain: bytes) -> int:
    """`(1,433)`'s `accepted N`: the request body's leading count byte.

    The only body ever captured is `0601020304050600`, so both readings of the
    shape -- a leading count, or the body's length less the two framing bytes
    -- say 6 for it.  A body that tells them apart has not been seen.
    """
    return plain[0] if plain else 0


def ack(key: tuple[int, int], plain: bytes) -> Ack | None:
    """The ack `key` draws, or None when `key` is not in the family.

    `plain` is the decrypted request body; only `(1,433)` reads it.
    """
    if not handles(key):
        return None
    body, note = _TABLE[key[1]]
    entries = str(entry_count(plain))
    return Ack(opcode=frame.Opcode(1, key[1], frame.OpcodeEncoding.U8_U16LE, True),
               body=body,
               tag=f"SELECTION-{key[1]}",
               note=f"conn={{conn}} {note.replace('{entries}', entries)}")
