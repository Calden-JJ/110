"""The live `(0,35)` card: the flip chain's own pools, rolled per clear.

A card is `139B prefix | free x 29B records | 118B suffix`, so `257 + 29 *
free` bytes, and the three cards the 09-28 capture holds pin every field a
live one fills::

    [131]         u8     the free flip count -- also the record count, and
                        the card's own size (315B is free=2, 344B free=3)
    [136:140]     u32le  the free side's gold, the delta its commit moves
                        (34 on the card whose commit reads `goldDelta=34`)
    [161+29i]     u32le  record i's item id
    [165+29i]     u8     and its count
    [-118:-116]   u16le  the paid side's cost, 051's `paidCosts` by the
                        dungeon's `basisLevel` (340 for d3, 580 for d5)
    [-90]         u8     1 iff the paid side is for sale (cost > 0)

Record 0 holds the run's one item on both free=2 cards, and the free=1
gold-only card (18 gold, no item) leaves its single record zero -- so the
records are written in grant order and a gold-only flip simply has none.
The rest of each record is zero in every capture, and the card carries no
paid item: the client learns what it bought from the commit's own answer.

**The pools.**  Nothing extracted holds them -- the free count, gold and
items live in the client's `itemdropinfo_clearreward.etc`, which the 0.3.6
set does not carry -- so `tools/extract_card_rewards.py` reads them off the
corpus's own `DUNGEON-CLEAR-46` and `DUNGEON-CARD-71` lines into
`data/game/card_pools.json`: per dungeon the free counts, the joint
(gold, items) rows of its side-0 commits, and its side-1 items, each with
its observation count, plus a `fallback` section for dungeons the corpus
never rolled (its basis band's free counts, a `gold / gold[050][basis]`
ratio, the corpus-wide grant and paid pools).

**Whose roll it is.**  The commit request is eight bytes of side index and
carries no reward of its own, so the card *is* the grant: `card.resolution`
writes what this module rolled, and a client that decodes the card for
display is the reference's own design, not trust.

**The two floors.**  The reference's own rolls could come up empty, and the
user's flips kept doing exactly that, so a live roll guarantees both sides
pay: a free card that rolled no gold falls back to `gold[050][basis]`'s own
`randint(min, max)` and one that rolled no item draws one
`FREE_ITEM_CHANCE` of the time; a paid flip pays back `paid_gold()` -- the
cost to half again the cost, so it is never a net loss -- and lands its
`paid_items` draw `PAID_ITEM_CHANCE` of the time instead of always.
"""
from __future__ import annotations

import json
import random
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ... import paths
from .. import data
from . import maze

CARD_PATH = paths.DATA_DIR / "game" / "card_pools.json"

#: The card's fields.  `clear.FREE_AT` and `card.GOLD_AT` are the same two
#: numbers, named where the clear chain reads them.
FREE_AT = 131
GOLD_AT = 136
ITEM_AT = 161
COUNT_AT = 165
RECORD_SIZE = 29
FIXED_SIZE = 257
COST_FROM_END = 118
PAID_FROM_END = 90

#: A record's count is one byte; the corpus's largest is 250.
COUNT_LIMIT = 255

#: The floors the live roll adds to the reference's own shape: a free flip
#: that rolled no item lands one this often, and a paid flip pays back up to
#: half again its cost before the item's own chance.
FREE_ITEM_CHANCE = 0.4
PAID_GOLD_HI = 1.5
PAID_ITEM_CHANCE = 0.6


@dataclass(frozen=True, slots=True)
class Reward:
    """One clear's live roll: what its card shows and its commit grants."""

    free: int
    gold: int
    items: tuple[tuple[int, int], ...] = ()
    cost: int = 0

    @property
    def paid(self) -> bool:
        return self.cost > 0


@lru_cache(maxsize=1)
def _pools() -> dict:
    return json.loads(CARD_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _gold_table() -> dict[int, tuple[int, int]]:
    """`gold[basisLevel]` as `(max, min)` -- the row is `[level, max, min]`."""
    return {lv: (hi, lo) for lv, hi, lo in data.load("monster_drops")["gold"]}


def cost(dungeon: int) -> int:
    """The paid flip's cost: 051's `paidCosts[basisLevel]`, 0 for a `disabled`
    dungeon and for one the table does not hold."""
    table = data.load("card_rewards")
    cfg = table["dungeons"].get(str(dungeon))
    if cfg is None or cfg.get("disabled"):
        return 0
    return dict(table["paidCosts"]).get(maze.basis_level(dungeon), 0)


def roll(dungeon: int, *, rng: random.Random | None = None) -> Reward:
    """One clear's whole free side, sampled from its dungeon's own pool.

    A dungeon the corpus rolled gives its own free count and its own joint
    (gold, items) rows; one with clears but no commits (many of the corpus's
    dungeons were never flipped) keeps its free count and takes the fallback
    gold and items; a dungeon the corpus never saw takes all three.  The
    items are cut to the free count, the records' own room.

    A free count of 0 carries nothing: the corpus's only free=0 dungeon is
    the `disabled` special whose 257B card has no record to hold anything.

    The two guarantees sit on top of the sample: a free flip whose gold came
    out 0 takes `_floor_gold`, and one whose items came out empty draws one
    `FREE_ITEM_CHANCE` of the time -- so a card that never rolls an item of
    its own still shows one now and then.
    """
    rng = random if rng is None else rng
    pools = _pools()
    entry = pools["dungeons"].get(str(dungeon)) or {}
    fb = pools["fallback"]
    if entry.get("free"):
        free = _pick(rng, entry["free"])
    else:
        free = _band_free(rng, fb["free_bands"], maze.basis_level(dungeon))
    if entry.get("runs"):
        gold, items = _pick_run(rng, entry["runs"])
    elif free:
        gold = _ratio_gold(rng, fb, dungeon)
        items = _fallback_items(rng, fb, free)
    else:
        gold, items = 0, ()
    if free and not gold:
        gold = _floor_gold(rng, dungeon)
    if free and not items and rng.random() < FREE_ITEM_CHANCE:
        items = _one_item(rng, fb)
    return Reward(free=free, gold=gold, items=tuple(items[:free]),
                  cost=cost(dungeon))


def paid_gold(cost: int, *, rng: random.Random | None = None) -> int:
    """The gold a side-1 commit pays back before its item: `cost` to half
    again the cost, so the flip never loses.  0 when nothing is for sale."""
    rng = random if rng is None else rng
    if cost <= 0:
        return 0
    return rng.randint(cost, round(cost * PAID_GOLD_HI))


def paid_item(dungeon: int, *, rng: random.Random | None = None) -> int | None:
    """The item a side-1 commit grants: the dungeon's own observed pool, else
    the corpus-wide one -- and only `PAID_ITEM_CHANCE` of the time, None
    otherwise (also None when the file carries no pool at all).

    Every observed paid item is equipment (kind 0) and granted as one.
    """
    rng = random if rng is None else rng
    if rng.random() >= PAID_ITEM_CHANCE:
        return None
    pools = _pools()
    entry = pools["dungeons"].get(str(dungeon)) or {}
    pool = entry.get("paid_items") or pools["fallback"]["paid_items"]
    return _pick(rng, pool) if pool else None


def card_bytes(reward: Reward) -> bytes:
    """The `(0,35)` body a clear sends -- `257 + 29 * free` bytes.

    The item records go in grant order, one per flip, which is what the two
    captured free=2 cards show (their one item in record 0).  Gold is written
    only when it is nonzero and *before* the cost, so that the one card shape
    with no room for both -- free=0, whose 118B suffix starts at 139 and
    overlaps the gold u32 at [136:140] -- keeps its cost readable.
    """
    body = bytearray(FIXED_SIZE + RECORD_SIZE * reward.free)
    body[FREE_AT] = reward.free
    size = len(body)
    struct.pack_into("<H", body, size - COST_FROM_END, reward.cost)
    body[size - PAID_FROM_END] = 1 if reward.paid else 0
    if reward.gold:
        struct.pack_into("<I", body, GOLD_AT, reward.gold)
    for i, (item, count) in enumerate(reward.items):
        struct.pack_into("<I", body, ITEM_AT + RECORD_SIZE * i, item)
        body[COUNT_AT + RECORD_SIZE * i] = min(count, COUNT_LIMIT)
    return bytes(body)


# ------------------------------------------------------------- the fallback

def _band_free(rng: random.Random, bands: list, basis: int) -> int:
    """The free count of the first band whose limit the basis is under."""
    band = next((b for b in bands if basis < b[0]), bands[-1] if bands else None)
    if band is None:
        return 0
    return _pick(rng, band[1])


def _ratio_gold(rng: random.Random, fb: dict, dungeon: int) -> int:
    """`gold / gold[050][basis]` sampled from the corpus, times the basis's
    table 050 gold -- the corpus's per-kill gold, scaled to this level."""
    base = _gold_table().get(maze.basis_level(dungeon), (0, 0))[0]
    if not base or not fb["gold_ratios"]:
        return 0
    return round(rng.choice(fb["gold_ratios"]) * base)


def _floor_gold(rng: random.Random, dungeon: int) -> int:
    """`gold[050][basis]`'s own `randint(min, max)`: the free flip's gold
    when the sampled rows held none."""
    bounds = _gold_table().get(maze.basis_level(dungeon))
    return rng.randint(bounds[1], bounds[0]) if bounds else 0


def _one_item(rng: random.Random, fb: dict) -> list:
    """One grant off the corpus-wide pool -- the fill-in for a flip whose
    own rows held no item."""
    if not fb["items"]:
        return []
    pool = [(item, count) for item, count, _ in fb["items"]]
    weights = [times for _, _, times in fb["items"]]
    return [rng.choices(pool, weights=weights)[0]]


def _fallback_items(rng: random.Random, fb: dict, free: int) -> list:
    """Up to `free` grants sampled from the corpus-wide pool.

    The count of them is uniform over `0..free`; the corpus's own runs grant
    between zero (a gold-only free=1 flip) and about one per flip, and no
    observation pairs the two -- the clear and commit lines are separate.
    """
    if not fb["items"]:
        return []
    pool = [(item, count) for item, count, _ in fb["items"]]
    weights = [times for _, _, times in fb["items"]]
    return [rng.choices(pool, weights=weights)[0]
            for _ in range(rng.randint(0, free))]


def _pick(rng: random.Random, pairs: list):
    """`[[value, times], ...]` sampled by its counts."""
    return rng.choices([value for value, _ in pairs],
                       weights=[times for _, times in pairs])[0]


def _pick_run(rng: random.Random, runs: list) -> tuple[int, tuple]:
    """One observed side-0 row: its gold and its items as a unit.

    The rows are joint on purpose -- a run's gold and its items were rolled
    together, and sampling them apart would invent combinations the corpus
    never produced.
    """
    row = _pick(rng, [[run[:2], run[2]] for run in runs])
    return row[0], tuple((item, count) for item, count in row[1])
