"""`(1,63)`/`(1,64)`: the cera (cash) shop -- balance poll, purchase, four families.

Measured 2026-09-27 23:16 and 09-25/09-26, from the live reference's own runs
(`DFO110-0.3.6/Server/Logs/server-*.log`); the two 09-27 runs have wire bytes,
the older ones only prose::

    09-27 23:16:30  conn=2 commodity 3400255  item 590713930 x1   slot 66  25 cera
    09-27 23:16:37  conn=2 commodity 3000112  item 1      x100   slot 1   900 cera
    09-26 10:29:44  conn=9 commodity 3000109  item 1      x1     slot 1   15 cera
    09-26 10:31:05  conn=9 commodity 3000112  item 1      x100   slot 1   900 cera
    09-26 10:31:12  conn=9 commodity 3000668  item 2660671 x500   slot 68  1190 cera
    09-25 12:55:00  conn=12 commodity 3001002 item 50006401 x1    slot 66  0 cera
    09-25 13:13:16  conn=12 commodity 3000147 ticket 2660296       []       40 cera
    09-25 13:14:18  conn=12 commodity 3000109 item 1      x1     slot 1   15 cera
    09-25 13:55:04  conn=12 commodity 3000678 contract 92         none     0 cera
    09-25 15:14:34  conn=17 commodity 3000129 kit item 50         none     30 cera
    09-26 10:46:08  conn=9  commodity 3000134 kit item 61         none     400 cera
    (and four more cargo kits 3000130..3000133, and 22 more contract buys)

The request is 16B::

    u16le prefix | u8 cart | u8 sel_row | u8 sel_col | u32le commodity |
    u16le quantity | 5 zero bytes

-- `prefix=(0,0) cart=1 sel=(0,0) quantity=1` on every one of the 40-odd
captured bodies, and the commodity is what the catalogue keys on: the
`shop_content` `products` row `[item, count, price, bag, stack, section]`.

The ack is one 56B block per cart line::

    01 00 | FF FF FF FF | u32le commodity | 14 zero bytes | FF FF FF FF |
    16 zero bytes | 01 | 11 zero bytes

The two 09-27 acks differ in the `[6:10]` word alone and it is the request's
commodity; what the four `FF` fields mean is not read -- one cart line is all
any capture has, so a multi-line cart's block repeat is inferred.

Four families, dispatched on the *delivered* item id:

* a **ticket** (`inventory_tickets.tickets`, 2660296 -> 8 and 2660297 -> 16)
  sets `character_inventory_expansion.expansion` to the ticket's target and
  lands nothing -- the log's slot list is `[]` and its line reads
  `expansion=0->8` then `8->16`.  The other 90 tickets carry target 0, which
  no capture buys and would *lower* an upgraded bag, so those are refused --
  see `execute`.
* a **warehouse kit** (`cargo.personalTools` 50->24, 57->40, ... 61->104;
  `secondTools` for the account warehouse) sets `character_cargo_state`'s
  capacity to the kit's row and lands nothing.  Kit 61's 104 is in the save;
  the reference's own `TOWN-CARGO` line read 88 (kit 60) in the sessions
  after it, which is a lag in that line's source, not in the write.
* a **contract** (`shop_content.premiumContracts`, keyed by item id:
  10000389 -> type 92, 604800s) moves `account_premium_contracts.expires_at`
  and lands nothing.  The rule is exact over 18 consecutive buys: `new =
  max(existing, now) + durationSeconds` -- the first buy from a standing
  `1790315704` gave `1790920504` = buy-second + 604800, and every later one
  moved up by exactly 604800.
* anything else is a plain **item**: it lands in `character_items` list 0,
  merging into a row of the same item when the character has one, else in the
  first free cell at or past its band's base (`buy.free_slot`, which also
  carries the item-1 override), with `product.count * quantity` units.

Every buy spends `price * quantity` cera and answers with the ack, then the
account's new balance as `(0,53)`, then one `(0,14)` slot frame when something
landed, then the 16B board -- 320B over four frames on both 09-27 runs.  The
`(1,63)` poll takes an empty body and answers the `(0,53)` alone, once a
minute while the shop is open.

Every refusal -- an unknown commodity, a cart that is not 1, a
non-positive quantity, an empty or too small balance, a target-0 ticket, a
full bag -- writes nothing and answers nothing, like the other write paths'.
No capture shows one, so which of them the reference rejects silently is
inferred from the plain text of the rules.

What is *not* inferred: the two 09-27 runs byte for byte against a copy of the
save, and the older runs' purchase effects -- `tests/test_cera_shop.py`.
"""
from __future__ import annotations

import sqlite3
import struct
import time
from dataclasses import dataclass, replace

from ...persistence import accounts, capacity, items
from ...protocol import frame
from ..data import load
from ..item import refresh
from . import buy

OPCODE = frame.Opcode(1, 64, frame.OpcodeEncoding.U8_U16LE, True)
POLL_OPCODE = frame.Opcode(1, 63, frame.OpcodeEncoding.U8_U16LE, True)
BALANCE_OPCODE = frame.Opcode(0, 53, frame.OpcodeEncoding.U8_U16LE, True)

BODY_SIZE = 16
BALANCE_SIZE = 16
ACK_BLOCK_SIZE = 56

TAG = "SHOP-BUY-64"
POLL_TAG = "CERA-REQUEST-63"
#: The warehouse upgrade's own tag; `Log.line` pads it to ten columns, which
#: is where the reference's two spaces after it come from.
CARGO_TAG = "CARGO-BUY"
#: Where the `(1,143)` burst carries its `(0,53)`, and the tag of its note.
TOWN_AT = 14
TOWN_TAG = "TOWN-CERA"

#: The expansion values the ticket rule may write; the table's CHECK holds the
#: same three, and the two measured targets are 8 and 16.
EXPANSION_TARGETS = frozenset({8, 16})

ITEM_FAMILY = "item"
EXPANSION_FAMILY = "expansion"
CARGO_FAMILY = "cargo"
CONTRACT_FAMILY = "contract"


@dataclass(frozen=True, slots=True)
class Product:
    """One `shop_content` `products` row, its section number resolved."""

    commodity: int
    item_id: int
    count: int
    price: int
    bag: int
    stack: int
    section: str


@dataclass(frozen=True, slots=True)
class Kit:
    """One `cargo` warehouse-upgrade kit."""

    item_id: int
    capacity: int
    second: bool               # the account/second warehouse's table


@dataclass(frozen=True, slots=True)
class BuyRequest:
    """One `(1,64)` body: the cart line that was clicked."""

    prefix: tuple[int, int]
    cart: int
    row: int
    col: int
    commodity: int
    quantity: int

    @classmethod
    def parse(cls, plain: bytes) -> "BuyRequest":
        if len(plain) != BODY_SIZE:
            raise ValueError(f"(1,64) body is {len(plain)}B, expected {BODY_SIZE}")
        prefix, cart, row, col, commodity, quantity = struct.unpack_from(
            "<HBBBIH", plain, 0)
        return cls(prefix=(prefix & 0xFF, prefix >> 8), cart=cart, row=row,
                   col=col, commodity=commodity, quantity=quantity)

    def request_line(self, conn: int, plain: bytes) -> str:
        """The reference's own line -- `plain=` in *upper* case here, the
        opposite of the `UNHANDLED` dump's."""
        return (f"conn={conn} prefix=({self.prefix[0]},{self.prefix[1]}) "
                f"cart={self.cart}: commodity={self.commodity} "
                f"sel=({self.row},{self.col}) quantity={self.quantity} "
                f"plain={plain.hex().upper()}")


@dataclass(frozen=True, slots=True)
class Outcome:
    ok: bool
    family: str = ""
    product: Product | None = None
    item_id: int = 0
    units: int = 0
    price: int = 0
    cera_after: int = 0
    #: The list-0 cells the buy landed in, in the order the line prints them.
    slots: tuple[int, ...] = ()
    #: `(1,4)`'s own two fields; a plain or ticket buy moves them only when
    #: the ticket says so.
    expansion_before: int = 0
    expansion_after: int = 0
    #: The contract's terms, for the line and the row.
    premium_type: int = 0
    expires_at: int = 0
    records: tuple[refresh.SlotRecord, ...] = ()
    #: Why nothing was written, for the caller's WARN.
    reason: str = ""


def product(commodity: int) -> Product | None:
    """The catalogue row for a commodity, or None when it has none."""
    content = load("shop_content")
    row = content["products"].get(str(commodity))
    if row is None:
        return None
    item_id, count, price, bag, stack, section = row
    return Product(commodity=commodity, item_id=item_id, count=count,
                   price=price, bag=bag, stack=stack,
                   section=content["sections"][section])


def purchase_limit(commodity: int) -> int | None:
    """The catalogue's purchase cap for a commodity, when it has one.

    The reference reads it and does not enforce it -- its own line says so
    (`the catalogue caps this one at 0 (not enforced)`).
    """
    return load("shop_content")["purchaseLimits"].get(str(commodity))


def ticket_target(item_id: int) -> int | None:
    """The expansion target of an inventory ticket, or None when the item is
    not a ticket at all."""
    row = load("inventory_tickets")["tickets"].get(str(item_id))
    return None if row is None else row["target"]


def cargo_kit(item_id: int) -> Kit | None:
    """The warehouse kit an item id is, or None when it is not one."""
    content = load("cargo")
    for key, second in (("personalTools", False), ("secondTools", True)):
        for entry in content[key]:
            if entry["itemId"] == item_id:
                return Kit(item_id=item_id, capacity=entry["capacity"],
                           second=second)
    return None


def contract_rule(item_id: int) -> tuple[int, int] | None:
    """`(premium_type, durationSeconds)` for a contract commodity's item."""
    row = load("shop_content")["premiumContracts"].get(str(item_id))
    return None if row is None else (row[0], row[1])


def balance_body(cera: int) -> bytes:
    """The 16B `(0,53)`: `01`, the balance, `01`, ten zero bytes.

    Both the poll's reply and the town entry's frame 14 use it -- and the
    two `01`s are the reason the old note `01 + u32 + 11 zeros` is wrong.
    """
    return b"\x01" + struct.pack("<I", cera) + b"\x01" + bytes(10)


def execute(conn: sqlite3.Connection, account_id: int, character_id: int,
            request: BuyRequest, *, now: int | None = None) -> Outcome:
    """Charge the cera, deliver whatever the commodity is, commit.

    Every check runs before the first write, so a refusal leaves the save as
    it was.  A target-0 ticket is refused rather than written: 90 of the 92
    tickets carry 0, no capture buys one, and the write would take an
    upgraded bag *down*, which the two measured tickets (`8`, then `16` on a
    character that had 8) never do.
    """
    now = int(time.time()) if now is None else now
    with conn:
        entry = product(request.commodity)
        if entry is None:
            return Outcome(False, reason="commodity is not in the catalogue")
        if request.cart != 1:
            return Outcome(False, reason="cart is not 1")
        if request.quantity < 1:
            return Outcome(False, reason="quantity is not positive")
        balance = accounts.cera(conn, account_id)
        if balance is None:
            return Outcome(False, reason="no accounts row")
        price = entry.price * request.quantity
        if balance < price:
            return Outcome(False, reason="not enough cera")
        units = entry.count * request.quantity

        contract = contract_rule(entry.item_id)
        target = ticket_target(entry.item_id)
        kit = cargo_kit(entry.item_id)
        if contract is not None:
            premium_type, duration = contract
        elif target is not None:
            if target not in EXPANSION_TARGETS:
                return Outcome(False, reason=f"ticket target {target} is not "
                                             f"an expansion")
        elif kit is None:
            slot = buy.free_slot(conn, character_id, entry.item_id)
            if slot is None:
                return Outcome(False, reason="no free slot")

        accounts.set_cera(conn, account_id, balance - price, now)
        before = capacity.expansion(conn, character_id) or 0

        if contract is not None:
            standing = dict(accounts.premium_contracts(conn, account_id))
            expires = max(standing.get(premium_type, 0), now) + duration
            accounts.set_contract(conn, account_id, premium_type, expires, now)
            return Outcome(True, family=CONTRACT_FAMILY, product=entry,
                           item_id=entry.item_id, units=units, price=price,
                           cera_after=balance - price,
                           premium_type=premium_type, expires_at=expires)

        if target is not None:
            capacity.set_expansion(conn, character_id, target)
            return Outcome(True, family=EXPANSION_FAMILY, product=entry,
                           item_id=entry.item_id, units=units, price=price,
                           cera_after=balance - price,
                           expansion_before=before, expansion_after=target)

        if kit is not None:
            capacity.set_cargo_capacity(conn, character_id, kit.capacity,
                                        second=kit.second)
            return Outcome(True, family=CARGO_FAMILY, product=entry,
                           item_id=entry.item_id, units=units, price=price,
                           cera_after=balance - price)

        record = _land(conn, character_id, entry, slot, units, now)
        return Outcome(True, family=ITEM_FAMILY, product=entry,
                       item_id=entry.item_id, units=units, price=price,
                       cera_after=balance - price, slots=(slot,),
                       expansion_before=before, expansion_after=before,
                       records=(record,))


def _land(conn: sqlite3.Connection, character_id: int, entry: Product,
          slot: int, units: int, now: int) -> refresh.SlotRecord:
    """Write the bought row and return the record the frames carry.

    `free_slot` chose the cell: one holding the same item merges (the row's
    count moves up by the units bought), anything else is a fresh row.
    """
    existing = items.load(conn, character_id, buy.GOLD_LIST, slot)
    if existing is not None:
        held = existing.count + units
        items.set_count(conn, existing, held, now)
        row = replace(existing, count=held, updated_at=now)
    else:
        row = buy.fresh_row(character_id, slot, entry.item_id, units, now)
        items.insert(conn, row)
    return refresh.SlotRecord.of_stack(row)


def ack(outcome: Outcome) -> bytes:
    """The per-cart-line block -- 56B, once, for the single-line carts the
    captures are."""
    out = bytearray(b"\x01\x00")
    out += b"\xff\xff\xff\xff"
    out += struct.pack("<I", outcome.product.commodity)
    out += bytes(14)
    out += b"\xff\xff\xff\xff"
    out += bytes(16)
    out += b"\x01"
    out += bytes(11)
    return bytes(out)


def frames(outcome: Outcome) -> list[tuple[frame.Opcode, bytes]]:
    """The ack, the balance, the landed row when there is one, the board --
    four frames, 320B, on both measured item runs."""
    out = [(OPCODE, ack(outcome)),
           (BALANCE_OPCODE, balance_body(outcome.cera_after))]
    if outcome.records:
        out.append((refresh.OPCODE_SLOT,
                    refresh.slot_frame(buy.GOLD_LIST, outcome.records)))
    out.append((refresh.OPCODE_BOARD, refresh.BOARD_AFTER_WRITE_BODY))
    return out


def item_line(conn: int, outcome: Outcome) -> str:
    """The delivered-item line -- the plain and the ticket families share it,
    the ticket's slot list being `[]`."""
    slots = "[" + ", ".join(str(slot) for slot in outcome.slots) + "]"
    line = (f"conn={conn} commodity {outcome.product.commodity} "
            f"({outcome.product.section}) -> item {outcome.item_id} "
            f"×{outcome.units} into Consumable slot(s) {slots} for "
            f"{outcome.price} cera; expansion={outcome.expansion_before}->"
            f"{outcome.expansion_after}")
    limit = purchase_limit(outcome.product.commodity)
    if limit is not None:
        line += f"; the catalogue caps this one at {limit} (not enforced)"
    return line


def cargo_line(conn: int, outcome: Outcome) -> str:
    """The warehouse upgrade's line, under its own tag."""
    return (f"conn={conn} item={outcome.item_id} price={outcome.price}; "
            f"upgraded and persisted")


def contract_line(conn: int, outcome: Outcome) -> str:
    return (f"conn={conn} commodity {outcome.product.commodity} activated "
            f"account contract type={outcome.premium_type} "
            f"expiresAt={outcome.expires_at} for {outcome.price} cera; "
            f"no inventory item")


def delivered_line(conn: int, outcome: Outcome) -> str:
    return (f"conn={conn} delivered 1 of 1 item(s); spent {outcome.price} "
            f"cera, {outcome.cera_after} left; answered with the per-item "
            f"acks + (0,53) + (0,14)×{len(outcome.records)}")


def poll_line(conn: int, account_id: int, cera: int) -> str:
    return (f"conn={conn} account {account_id} cera={cera}; "
            f"answered with (0,53)")


def town_line(account_id: int, cera: int) -> str:
    """The `TOWN-CERA` note's tail; the note is a `{conn}` template, so
    `_town_entry` writes the prefix (`roleselection.Pick.note`'s shape)."""
    return f"account {account_id} cera={cera}; sent as (0,53)"
