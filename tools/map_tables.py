#!/usr/bin/env python3
"""Recover the canonical table name behind each `data/tables/NNN_<slug>.json`.

`extract_tables.py` carves 69 JSON documents out of the exe and gives them
numbers, because nothing in the data says what they are called.  The names
live in the exe's resource manifest, and there are **two** lists of them that
must not be confused:

    0x58f1050  ASCII, `[u8 2*len][name]` records, build order   <- this one
    ~0x63a41e6 UTF-16LE, the same 69 names alphabetised         <- _names.json

Zipping `_names.json` against `_index.json` would permute every entry. The
ASCII listing is in the same order as `_index.json`'s `i`, and that is the
only reason the pairing below is possible at all: the order is *not* derivable
from the names. crc32 / fnv1a32 / fnv1a64 / djb2 were all tried against 13
known pairs and scored 0/13, so it comes from the build pipeline, not a hash
of the name.

Position alone is therefore not evidence, and the pairing is checked against
independent content: 15 anchors, each of which must show a fingerprint in the
table body -- a `source` field naming the PVF file the table was built from
(`list/quest.lst`, `etc/disjoint.etc`), or a distinctive top-level key
(`cubeConstants`, `roots`+`packages`) that no other table has.

Two of those anchors correct guesses made before the manifest was readable:

    20 equipment_specificity   source: Etc/EquipmentSpecificity/... (was 37)
    30 npc_shop_content        source: list/itemshop.lst           (was 18)

The manifest keeps going past the game tables into
`USLocalServer.Protocol.Crypto.Tables.<algo>.bin`, so the walk stops at the
first non-`Game` resource name rather than at a hand-tuned end offset. That
boundary is also what lets `paths.MANIFEST_REGION` be a loose window.

Usage:
    python tools/map_tables.py [--exe F] [--out F] [--check]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import paths                                 # noqa: E402

#: `[u8 2*len][ASCII name]` -- the length byte counts UTF-16 code units, so it
#: is twice the ASCII character count.  An earlier read of this region took
#: the manifest for a `[len][name]` byte-length format and missed the last
#: record, which sits one byte past the window end.
RESOURCE = re.compile(
    rb"USLocalServer\.Game\.(?P<domain>[A-Za-z]+)\.Data\.(?P<name>[a-z0-9_]+)_110us\.json")
#: First thing after the game tables; the end of the listing we want.
STOP = re.compile(rb"USLocalServer\.Protocol\.")
#: Records are ~140 bytes; 32 KiB is generous and still cheap to scan.
WINDOW = 0x8000

FRAMING = "USLocalServer.Game.<domain>.Data.<name>_110us.json"

#: (i, name, kind, token).  `source` matches a substring of the body's
#: `source` field, case-insensitively; `key` must be a top-level key.
ANCHORS: tuple[tuple[int, str, str, str], ...] = (
    (4, "dye_content", "key", "avatarTypes"),
    (15, "monster_experience", "source", "monster/monsterexp.tbl"),
    (20, "equipment_specificity", "source", "equipmentspecificity"),
    (23, "quest_content", "source", "list/quest.lst"),
    (24, "image_communication", "source", "imagecommunication.etc"),
    (30, "npc_shop_content", "source", "list/itemshop.lst"),
    (31, "creature_content", "source", "list/equipment.lst"),
    (34, "disjoint_content", "source", "etc/disjoint.etc"),
    (35, "package_content", "key", "packages"),
    (42, "buff_swap", "source", "switchingsupportskill.etc"),
    (44, "dungeon_worldmap", "source", "list/worldmap.lst"),
    (46, "map_content", "source", "list/map.lst"),
    (52, "tournaments", "key", "tournaments"),
    (60, "dusky_island_operations", "source", "duskyisland.etc"),
    (62, "hell_party", "source", "hell party"),
)

EXPECTED_TABLES = 69
EXPECTED_DOMAINS = {"characters": 5, "dungeons": 26, "items": 31, "quests": 7}


class ManifestError(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__(f"{len(problems)} problem(s): " + "; ".join(problems[:3]))
        self.problems = problems


def read_manifest(exe: Path | None = None, start: int | None = None,
                  window: int = WINDOW) -> list[dict]:
    """The 69 game-table resources, in build order, with their domains.

    Only the window is read; the exe is 107 MB and nothing outside these
    ~10 KB is relevant.
    """
    exe = paths.EXE if exe is None else exe
    start = paths.MANIFEST_REGION[0] if start is None else start
    with exe.open("rb") as fh:
        fh.seek(start)
        data = fh.read(window)
    stop = STOP.search(data)
    end = stop.start() if stop else len(data)
    out = []
    for m in RESOURCE.finditer(data, 0, end):
        out.append({
            "i": len(out),
            "offset": f"0x{start + m.start():08x}",
            "domain": m.group("domain").decode().lower(),
            "name": m.group("name").decode(),
        })
    if not out:
        raise ManifestError([f"no resource names in 0x{start:x}..0x{start + end:x}"])
    return out


def load_index() -> list[dict]:
    entries = json.loads(paths.TABLES_INDEX.read_text(encoding="utf-8"))
    return sorted(entries, key=lambda e: e["i"])


def load_names() -> list[str]:
    """The UTF-16LE listing, alphabetised -- a set, never an ordering."""
    return json.loads(paths.TABLES_NAMES.read_text(encoding="utf-8"))


def fingerprints(entry: dict) -> dict[str, str]:
    """What the body is known to contain, as `_index.json` recorded it."""
    out = {}
    if entry.get("source"):
        out["source"] = str(entry["source"]).lower()
    for key in entry.get("top_keys", ()):
        out[key] = "key"
    return out


def check_anchor(entry: dict, name: str, kind: str, token: str) -> str | None:
    """Return the evidence string, or None when the fingerprint is absent."""
    if entry.get("slug") is None:
        return None
    if kind == "source":
        source = str(entry.get("source") or "").lower()
        return f"source:{token}" if token in source else None
    return f"key:{token}" if token in entry.get("top_keys", ()) else None


def build_payload(manifest: list[dict], index: list[dict],
                  names: list[str] | None = None) -> dict:
    problems: list[str] = []

    if len(manifest) != EXPECTED_TABLES:
        problems.append(f"manifest holds {len(manifest)} names, expected {EXPECTED_TABLES}")
    if len(index) != EXPECTED_TABLES:
        problems.append(f"index holds {len(index)} documents, expected {EXPECTED_TABLES}")
    problems += _check_names(manifest, names)

    anchors: list[dict] = []
    evidence: dict[int, list[str]] = {}
    for i, name, kind, token in ANCHORS:
        if i >= len(manifest) or i >= len(index):
            problems.append(f"anchor i={i} is out of range")
            continue
        got_name = manifest[i]["name"]
        if got_name != name:
            problems.append(f"i={i}: manifest says {got_name!r}, anchor says {name!r}")
            continue
        match = check_anchor(index[i], name, kind, token)
        if match is None:
            problems.append(f"i={i}: {name} has no {kind} fingerprint {token!r}; "
                            f"index has {fingerprints(index[i])}")
            continue
        evidence.setdefault(i, []).append(match)
        anchors.append({"i": i, "name": name, "fingerprint": match})

    names = [t["name"] for t in manifest]
    if len(set(names)) != len(names):
        dupes = sorted(n for n, c in Counter(names).items() if c > 1)
        problems.append(f"manifest repeats {dupes}")
    # `file` is the identity (`NNN_` prefix included); `slug` is not -- several
    # tables share one, which is why nothing may look a table up by slug.
    files = {e["file"] for e in index}
    if len(files) != len(index):
        problems.append(f"index has {len(index) - len(files)} duplicate file name(s)")
    if {e["i"] for e in index} != set(range(len(index))):
        problems.append("index `i` is not 0..68")

    domains = Counter(t["domain"] for t in manifest)
    if dict(domains) != EXPECTED_DOMAINS:
        problems.append(f"domains {dict(sorted(domains.items()))} != {EXPECTED_DOMAINS}")

    if problems:
        raise ManifestError(problems)

    tables = [
        {
            "i": t["i"],
            "name": t["name"],
            "domain": t["domain"],
            "slug": index[t["i"]]["slug"],
            "file": index[t["i"]]["file"],
            "confidence": "anchored" if evidence.get(t["i"]) else "manifest",
            "evidence": evidence.get(t["i"], []),
        }
        for t in manifest
    ]
    return {
        "generated_by": "tools/map_tables.py",
        "manifest": {
            "exe": paths.EXE.name,
            "file_offset": f"0x{paths.MANIFEST_REGION[0]:08x}",
            "framing": FRAMING,
            "stop_at": STOP.pattern.decode(),
            "listing": "`_names.json` and the UTF-16LE manifest it came from are the "
                       "same 69 names alphabetised; zip them against `_index.json` "
                       "and every entry is permuted. Only this ASCII listing is in "
                       "build order.",
        },
        "tables": tables,
        "domains": dict(sorted(domains.items())),
        "anchors": anchors,
        "duplicate_slugs": _groups(index, lambda e: e["slug"]),
        "index_identical": sorted(
            ({"fingerprint": k, "i": v} for k, v in _identical(index).items()),
            key=lambda g: g["i"][0]),
    }


def _check_names(manifest: list[dict], names: list[str] | None) -> list[str]:
    """The alphabetical UTF-16 listing must hold the same 69 names as a set.

    It says nothing about order -- that is what `_names.json` cannot provide
    and what the anchors are for -- but it does catch a truncated or widened
    walk, which is how the 69th record went missing the first time.
    """
    listed = load_names() if names is None else names
    if len(listed) != EXPECTED_TABLES:
        return [f"_names.json holds {len(listed)} names, expected {EXPECTED_TABLES}"]
    got, want = sorted(t["name"] for t in manifest), []
    for entry in listed:
        m = RESOURCE.search(entry.encode())
        if m is None:
            return [f"_names.json entry {entry!r} is not a game table resource"]
        want.append(m.group("name").decode())
    if got != sorted(want):
        missing = sorted(set(want) - set(got))
        extra = sorted(set(got) - set(want))
        return [f"manifest and _names.json disagree: {len(missing)} only in _names "
                f"{missing[:4]}, {len(extra)} only in manifest {extra[:4]}"]
    return []


def _groups(index: list[dict], key) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for entry in index:
        out.setdefault(key(entry), []).append(entry["i"])
    return {k: v for k, v in sorted(out.items()) if len(v) > 1}


def _identical(index: list[dict]) -> dict[str, list[int]]:
    """Tables the index records nothing to tell apart.

    For these the manifest order is the *only* thing that says which is which,
    so they are the places where trusting the order can actually cost
    something.  Pinned by the test so the list cannot quietly grow.
    """
    def key(e: dict) -> str:
        keys = "+".join(sorted(e.get("top_keys") or ()))
        return f"{e['kind']}/{e['entries']}/{keys}@{str(e.get('source') or '').lower()}"

    return _groups(index, key)


def render(payload: dict) -> str:
    return json.dumps(payload, indent=1, ensure_ascii=False) + "\n"


def load(path: str | Path | None = None) -> dict:
    p = Path(path) if path is not None else paths.TABLE_MAP
    return json.loads(p.read_text(encoding="utf-8"))


def by_name(path: str | Path | None = None) -> dict[str, dict]:
    """canonical name -> entry, the lookup game code should use."""
    return {t["name"]: t for t in load(path)["tables"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", type=Path, default=paths.EXE)
    ap.add_argument("--out", type=Path, default=paths.TABLE_MAP)
    ap.add_argument("--check", action="store_true",
                    help="verify the committed map instead of rewriting it")
    a = ap.parse_args()

    try:
        manifest = read_manifest(a.exe)
        payload = build_payload(manifest, load_index())
    except ManifestError as e:
        for p in e.problems[:20]:
            print(f"ERROR {p}", file=sys.stderr)
        raise SystemExit(str(e)) from None

    if a.check:
        if render(payload) != a.out.read_text(encoding="utf-8"):
            raise SystemExit(f"{a.out} is stale; re-run without --check")
        print(f"{a.out} is current")
        return 0

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(render(payload), encoding="utf-8")

    tables = payload["tables"]
    anchored = sum(1 for t in tables if t["confidence"] == "anchored")
    print(f"wrote {a.out}")
    print(f"  tables  {len(tables)}  {payload['domains']}")
    print(f"  anchors {len(payload['anchors'])}/{len(ANCHORS)} confirmed: "
          + ", ".join(f"{a['i']}={a['name']}({a['fingerprint']})" for a in payload["anchors"]))
    print(f"  content {anchored}/{len(tables)} carry a fingerprint; the other "
          f"{len(tables) - anchored} rest on the manifest order alone, and "
          f"{sum(len(g['i']) for g in payload['index_identical'])} of them are "
          f"indistinguishable in the index")
    return 0


if __name__ == "__main__":
    sys.exit(main())
