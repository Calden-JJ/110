"""The live `(0,38)` roll: what a kill leaves on the ground.

`drops.py` is the frame; this is the roll behind it, sampled from the
corpus's own kills (`data/game/kill_drops.json`, `extract_kill_drops.py`).
Four rules write the whole roll::

    cinematic spawn                     -> nothing
    code with a table-050 monsters pool -> one item, the pool's own weights
    Boss rank                           -> gold + one equipment, always
    anything else                       -> 8% gold, 12% material

**Cinematic.**  Every story actor and hunt dummy killed across the corpus --
150 of them -- left nothing; `die.resolution`'s own two branches already say
so (`story/friendly actor`, `cinematic map objective confirmed`), and the
roll simply agrees.

**The room's boxes.**  Table 050's `monsters` section holds a weighted pool
for 24 of the corpus's codes -- the pots and boxes -- and all 99 corpus kills
of them dropped, the item exactly from the pool (dungeon 3's code 1 draws
1047 twice as often as 1004 and four times 1000, which is its pool's own
50/100/200 weights).  So an object kill drops one item of the pool and never
consults the corpus at all.

**Bosses** drop gold and one piece of equipment every kill.  The reference's
own bosses did that only about half the time -- of its 129 logged Boss kills
68 (52.7%) left gold and 80 (62.0%) an item -- so this is a deliberate
richness, not a fit.  The gold band is `BOSS_GOLD_LO`..`BOSS_GOLD_HI` of
`gold[050][basisLevel]`'s own max, d3's measured 35..52 over its 34; the
equipment is one catalogue-kind-0 entry the corpus's kills of that code
left, deepest layer first like the materials.

**Everything else** -- the ordinary monsters -- rolls two independent
chances: `NORMAL_GOLD_CHANCE` for gold and `NORMAL_MATERIAL_CHANCE` for one
material (catalogue kind 1).  The reference's own rates over its 6,717
Normal kills were 5.3% gold and 10.7% items; 8/12 is the user's own call --
slightly richer without being a piñata.  The material is drawn from the
corpus's own item pools, deepest layer first::

    (dungeon, code), 6677 kills over 484 pairs
    code,            the same kills over 367 codes
    dungeon,         over 64 dungeons
    global,          6677 kills

the first layer holding a kind-1 entry answers -- a well-played dungeon
drops its own materials, a first visit pools the code across dungeons, and a
dungeon the corpus never killed in falls to the global mix.

**Gold amounts re-roll.**  The corpus's own amounts are samples of table
050's `gold[basisLevel]` -- `[level, max, min]`, and all 436 corpus gold
drops land in that range, uniform across it -- so a live gold entry draws
`randint(min, max)` rather than repeating one observed number.  Every other
field (which items, their counts) travels as observed; an equipment's record
value is a live instance uid, drawn the way `buy.fresh_row` draws one.
"""
from __future__ import annotations

import json
import random
from functools import lru_cache

from ... import paths
from .. import data
from ..data import content
from ..shop import buy
from . import drops, maze as maze_data
from .maze import Spawn

POOL_PATH = paths.DATA_DIR / "game" / "kill_drops.json"

#: The one pool word this module invents no corpus set for: 050's own
#: `monsters` section, which the note spells `monster`.
MONSTER_POOL = "monster"

#: The ordinary monster's two chances, rolled independently.  The corpus's
#: own rates over 6,717 Normal kills: 5.3% gold, 10.7% items.
NORMAL_GOLD_CHANCE = 0.08
NORMAL_MATERIAL_CHANCE = 0.12

#: The boss gold band as multiples of `gold[050][basisLevel]`'s own max:
#: dungeon 3's 35..52 over its 34 is the reference-measured payout, and every
#: other dungeon scales with the same ratio (basis 5's 48 reads 49..73).
BOSS_GOLD_LO = 35 / 34
BOSS_GOLD_HI = 52 / 34


@lru_cache(maxsize=1)
def _pools() -> dict:
    return json.loads(POOL_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _gold_table() -> dict[int, tuple[int, int]]:
    """`gold[basisLevel]` as `(max, min)` -- the row is `[level, max, min]`."""
    return {lv: (hi, lo) for lv, hi, lo in data.load("monster_drops")["gold"]}


@lru_cache(maxsize=1)
def _object_pools() -> dict[int, tuple[tuple[int, int], ...]]:
    """The codes with a non-empty table-050 pool, as `(item, weight)` rows."""
    return {int(code): tuple((item, weight) for item, weight in entry["pool"])
            for code, entry in data.load("monster_drops")["monsters"].items()
            if entry.get("pool")}


def roll(dungeon: int, spawn: Spawn,
         *, rng: random.Random | None = None) -> tuple[drops.Fact, ...]:
    """One kill's drops, in slot order.

    `spawn` is the record that died -- `monster` picks the pools and the
    words decide the cinematic rule -- and `dungeon` the run's own id, whose
    basis level scales the gold.
    """
    if maze_data.cinematic(spawn):
        return ()
    rng = random if rng is None else rng
    pool = _object_pools().get(spawn.monster)
    if pool is not None:
        return (_fact([MONSTER_POOL, _pick(rng, pool), 1], dungeon, rng),)
    if maze_data.rank(spawn) == "Boss":
        return _boss(dungeon, spawn.monster, rng)
    return _normal(dungeon, spawn.monster, rng)


def _boss(dungeon: int, code: int, rng: random.Random) -> tuple[drops.Fact, ...]:
    """The boss's guaranteed pair: its gold, then one equipment."""
    facts = [drops.Fact(item=0, value=_boss_gold(dungeon, rng), kind=drops.GOLD)]
    entry = _observed(dungeon, code, rng, _is_equipment)
    if entry is not None:
        facts.append(_fact(entry, dungeon, rng))
    return tuple(facts)


def _normal(dungeon: int, code: int, rng: random.Random) -> tuple[drops.Fact, ...]:
    """An ordinary monster's two independent chances."""
    facts = []
    if rng.random() < NORMAL_GOLD_CHANCE:
        amount = _gold(dungeon, None, rng)
        if amount:
            facts.append(drops.Fact(item=0, value=amount, kind=drops.GOLD))
    if rng.random() < NORMAL_MATERIAL_CHANCE:
        entry = _observed(dungeon, code, rng, _is_material)
        if entry is not None:
            facts.append(_fact(entry, dungeon, rng))
    return tuple(facts)


def _observed(dungeon: int, code: int, rng: random.Random,
              wanted) -> list | None:
    """One entry the corpus left, off the first layer that holds one of the
    kind `wanted` asks for, weighted by its own set's kill count."""
    pools = _pools()
    for sets in (pools["pairs"].get(f"{dungeon}/{code}"),
                 pools["codes"].get(str(code)),
                 pools["dungeons"].get(str(dungeon)),
                 pools["global"]):
        pool = [(entry, times) for entries, times in sets or ()
                for entry in entries if wanted(entry[1])]
        if pool:
            return _pick(rng, pool)
    return None


def _is_material(item: int) -> bool:
    """Catalogue kind 1, gold's own zero excluded -- item 0 has a row too."""
    definition = content.definition(item) if item else None
    return definition is not None and definition.kind == drops.STACKABLE_KIND


def _is_equipment(item: int) -> bool:
    definition = content.definition(item) if item else None
    return definition is not None and definition.kind == 0


def _fact(entry: list, dungeon: int, rng: random.Random) -> drops.Fact:
    """One observed entry as a live `Fact`.

    Gold keeps the row but re-rolls its amount inside table 050's range --
    the observed number is one sample of it.  An item keeps the observed
    count when the catalogue calls it stackable, and otherwise takes a live
    instance uid, which is what the record's value has to be.
    """
    kind, item, value = entry
    if kind == drops.GOLD:
        return drops.Fact(item=0, value=_gold(dungeon, value, rng), kind=kind)
    definition = content.definition(item)
    if definition is None or definition.kind != drops.STACKABLE_KIND:
        value = rng.randrange(1, buy.INSTANCE_LIMIT)
    return drops.Fact(item=item, value=value, kind=kind)


def _gold(dungeon: int, observed: int | None, rng: random.Random) -> int:
    """`randint(min, max)` of `gold[basisLevel]`, the observed amount (or
    nothing) where the table has no row -- a dungeon past level 200."""
    bounds = _gold_table().get(maze_data.basis_level(dungeon))
    return rng.randint(bounds[1], bounds[0]) if bounds else observed or 0


def _boss_gold(dungeon: int, rng: random.Random) -> int:
    """The boss band: `BOSS_GOLD_LO`..`BOSS_GOLD_HI` of the basis's own max."""
    table = _gold_table()
    bounds = table.get(maze_data.basis_level(dungeon)) or table[max(table)]
    return rng.randint(round(bounds[0] * BOSS_GOLD_LO),
                       round(bounds[0] * BOSS_GOLD_HI))


def _pick(rng: random.Random, rows):
    """`[[value, weight], ...]`, or the sets' `[[entry, ...], times]` -- one
    row sampled by its own weight, whatever the row holds."""
    return rng.choices([row[0] for row in rows],
                       weights=[row[1] for row in rows])[0]
