"""`(1,309)` NPC-REDEEM -- the buyback list, and it is always empty.

When it answers at all.  The reference never implemented the storage behind
it, so the request body is never read: the answer is the constant `(0,292)`
16 zero bytes with the note `answered with empty S292 list (buyback storage
not implemented)`.  129 lines across the corpus (09-19 21:22:58 through
09-27 23:15:27, six connections) and every one of them says exactly that --
there is no non-empty form to generate.  The six dumped `(1,309)` requests
(09-27, `_csprobe/c2s-1-309.hex`) are 13B of wire each, empty bodies, each
answered `-> 1 frame(s) 32B`.

The handler at `0x2c89b0` has a silent branch: six gates must hold for the
log line and the reply, and when one fails a cached default object is
returned with no log and no frame.  Two of the gates -- `[M+0x50]` and
`[M+0x58]` both NULL -- are shared with the sibling handler at `0x2cdda0`,
whose literal calls the passing state "outside town movement state"; the
09-28 session sent this four times from inside a live DUNGEON-CARD run
(21:11:42, 21:11:51, 21:12:55, 21:13:19, runs `b67cba62` and `ec0fe4f9`) and
got silence, while every answered send above is a town shopping round.  The
gate is therefore "no dungeon run open", which the server applies in
`_npc_redeem` as `session.run is not None`.
"""
from __future__ import annotations

from ...protocol import frame

OPCODE = frame.Opcode(1, 309, frame.OpcodeEncoding.U8_U16LE, True)
#: The empty list -- `(0,292)` 16 zero bytes, 32B of wire.
REPLY_OPCODE = frame.Opcode(0, 292, frame.OpcodeEncoding.U8_U16LE, True)
REPLY_BODY = bytes(16)

TAG = "NPC-REDEEM-309"
NOTE = "answered with empty S292 list (buyback storage not implemented)"
