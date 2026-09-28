"""`(1,309)` NPC-REDEEM -- the buyback list, and it is always empty.

The reference never implemented the storage behind it, so the request body is
never read: the answer is the constant `(0,292)` 16 zero bytes with the note
`answered with empty S292 list (buyback storage not implemented)`.  129 lines
across the corpus (09-19 21:22:58 through 09-27 23:15:27, six connections)
and every one of them says exactly that -- there is no non-empty form to
generate.  The six dumped `(1,309)` requests (09-27, `_csprobe/c2s-1-309.hex`)
are 13B of wire each, empty bodies, each answered `-> 1 frame(s) 32B`.
"""
from __future__ import annotations

from ...protocol import frame

OPCODE = frame.Opcode(1, 309, frame.OpcodeEncoding.U8_U16LE, True)
#: The empty list -- `(0,292)` 16 zero bytes, 32B of wire.
REPLY_OPCODE = frame.Opcode(0, 292, frame.OpcodeEncoding.U8_U16LE, True)
REPLY_BODY = bytes(16)

TAG = "NPC-REDEEM-309"
NOTE = "answered with empty S292 list (buyback storage not implemented)"
