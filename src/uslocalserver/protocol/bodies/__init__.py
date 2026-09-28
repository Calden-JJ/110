"""Client request bodies, and how much of each one is actually known.

The reference server prints the parsed request in its own log lines
(`request=SelectDungeonRequest { DungeonId = 7114, ... }`), which gives the
field *names* and their *order* for free -- but not the bytes.  So every entry
here records which of the two it has:

    verified    the layout was read off a real body.  `(1,1592)` is the only
                one: 23 `plain=` dumps across the three server logs, all 32
                bytes and byte-identical.  (46 if the launcher logs count --
                they repeat every server line, so it is 23 events either way.)
    declared    the field names and order come from the reference server's own
                `ToString()`; the wire bytes have never been seen for that
                opcode, so the widths below are a reading of the field types
                and nothing more.

`parse_body` refuses a `declared` entry unless the caller asks for it by name.
A five-field struct assumed to be five `u32`s does not fail loudly when the
assumption is wrong -- it returns plausible numbers from the wrong offsets --
and M0 has no captured body to check either against.  So the two declared
parsers are here to be *tested* the moment a capture exists, not to be used.

A third case, `TownPlacement`, is here as `declared` for a sharper reason: it
is not established that it is a body at all.  Its five fields are exactly the
`characters` location columns (`town_id, area_id, position_x, position_y,
town_state`), and 46 of 98 logged placements equal the position from the
preceding `TOWN-MOVE-35` -- yet 36 of 123 carry coordinates that appear
nowhere else in the logs.  It is either the (1,33) body or a value object the
server builds from its own state, and the logs do not say which.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..reader import BodyReader, TruncatedBody


class LayoutUnverified(LookupError):
    """A declared body was asked for without `allow_declared=True`."""


@dataclass(frozen=True, slots=True)
class SelectDungeonRequest:
    """The `(1,16)` request body.  Field order is the reference server's.

    `DungeonId` reaches 291100268 in one day's logs, so it is wider than
    `u16`; `Difficulty` runs 0-2, `EntryOption` is 0 in every sample, `Mode`
    and `HellDifficulty` are 0-1.  Five `u32le` is 20 bytes, and no logged
    C->S body is 20 bytes.  The one `(1,16)` dump that does exist
    (`server-20260927.log:2553`, 32 bytes, logged beside `DungeonId = 81,
    Difficulty = 2`) starts `51 00 00 00 02 00 00 00 00 ff ff 00 ...`, so the
    first two fields read as declared and the third does not -- the layout is
    wrong somewhere past `Difficulty`, and nothing is generated from it yet.
    """
    dungeon_id: int
    difficulty: int
    entry_option: int
    mode: int
    hell_difficulty: int


@dataclass(frozen=True, slots=True)
class TownPlacement:
    """`TownId, AreaId, X, Y, State` -- a character's position, not a body.

    See the module docstring: whether this arrives in the `(1,33)` packet is
    unresolved, and the column names are the ones it shares with `characters`.
    """
    town_id: int
    area_id: int
    x: int
    y: int
    state: int


@dataclass(frozen=True, slots=True)
class ClientEnvironment:
    """The `(1,1592)` body, sent by the client right after `LOGIN`.

    The name is ours -- the reference server never names this one, because
    nothing handles it.  `timezone` is so named because the value is
    `"China Standard Time"`; what the second string or the trailing byte mean
    is unknown, and all 46 samples agree byte for byte, so nothing here can be
    told apart by contrast.
    """
    timezone: str
    list: str
    trailing: int


def _parse_client_environment(r: BodyReader) -> ClientEnvironment:
    out = ClientEnvironment(
        timezone=r.len_prefixed_str(),
        list=r.len_prefixed_str(),
        trailing=r.u8(),
    )
    r.expect_eof()
    return out


def _parse_select_dungeon(r: BodyReader) -> SelectDungeonRequest:
    out = SelectDungeonRequest(
        dungeon_id=r.u32le(),
        difficulty=r.u32le(),
        entry_option=r.u32le(),
        mode=r.u32le(),
        hell_difficulty=r.u32le(),
    )
    r.expect_eof()
    return out


def _parse_town_placement(r: BodyReader) -> TownPlacement:
    out = TownPlacement(r.u32le(), r.u32le(), r.u32le(), r.u32le(), r.u32le())
    r.expect_eof()
    return out


@dataclass(frozen=True, slots=True)
class BodySpec:
    opcode: tuple[int, int]
    body: type
    parse: Callable[[BodyReader], object]
    layout: str
    verified: bool
    doc: str = ""


REGISTRY: dict[tuple[int, int], BodySpec] = {
    spec.opcode: spec for spec in (
        BodySpec((1, 1592), ClientEnvironment, _parse_client_environment,
                 "u32le len + utf-8 + u32le len + utf-8 + u8", True,
                 "all 23 logged bodies are byte-identical"),
        BodySpec((1, 16), SelectDungeonRequest, _parse_select_dungeon,
                 "assumed 5 x u32le", False,
                 "the one 32B dump agrees up to Difficulty and then diverges"),
        BodySpec((1, 33), TownPlacement, _parse_town_placement,
                 "assumed 5 x u32le", False,
                 "may not be a packet body at all"),
    )
}


def parse_body(opcode: tuple[int, int], body: bytes, *,
               allow_declared: bool = False, label: str = "") -> object:
    """Decode `body` for `opcode`.

    `allow_declared` guards the entries whose layout has never been seen: the
    caller has to know that and say so.  `TruncatedBody` comes out of the
    reader, `LayoutUnverified` and `KeyError` out of here.
    """
    spec = REGISTRY[opcode]
    if not spec.verified and not allow_declared:
        raise LayoutUnverified(
            f"{opcode} {spec.body.__name__}: layout is declared, not verified "
            f"({spec.doc}); pass allow_declared=True to read it anyway")
    return spec.parse(BodyReader(body, label=label or f"{opcode}"))


__all__ = ["ClientEnvironment", "LayoutUnverified", "REGISTRY", "SelectDungeonRequest",
           "TownPlacement", "parse_body", "TruncatedBody"]
