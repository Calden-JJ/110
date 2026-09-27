#!/usr/bin/env python3
"""Scan the reference server's logs and emit data/protocol/opcodes.json.

The registry is evidence-only.  Six shapes count, and every one of them was
measured against the logs before being trusted:

    packet-c2s  `DEBUG PACKET conn=N C->S game (1,16) ...`      explicit field
    packet-s2c  `DEBUG PACKET conn=N S->C game ... hex=...`     header decode
    dispatch    `conn=2 (1,1554) -> 1 frame(s) 24B state=A->B`
    unhandled   `conn=2 (1,1592) body=32B has no handler`
    seen        `conn=2 ... seen=[(1,1), (1,2), ...]`
    response    `-> (1,37) ack 1B + (0,30) 5B`                  size-shaped only

Three traps in the log make a naive scan wrong, and all three are pinned by
tests:

* A bare `\\((\\d+),(\\d+)\\)` also matches cell coordinates.  Even anchoring
  on `conn=` is not enough: DCOD-PORTAL-MOVE logs `conn=19 (0,1) -> (2,4)
  named portal`, a coordinate pair sitting exactly where an opcode sits, which
  injects 102 bogus opcodes whose main is 0 or 1.  The `(?!-> \\()` guard is
  what rejects it.
* `-> (0,3) -> (0,2)` in DUNGEON-MOVE is a cell transition, not a response.
  Only refs followed by a byte count (`-> (0,29) 107B`) are responses.
* Tag suffixes collide: DUNGEON-MOVE-45 and ISPINS-MOVE-45 both name opcode
  (1,45), so a name is a list, never a single string.

LEGACY-QUERY carries no opcode at all (`conn=2 consumed 24B; no response by
design`) and so contributes nothing.

Usage:
    python tools/gen_opcodes.py [--log F]... [--out F]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths                      # noqa: E402
from uslocalserver.protocol import frame                   # noqa: E402

GAME_S2C = frame.Link.GAME_S2C
GAME_C2S = frame.Link.GAME_C2S
CHANNEL_S2C = frame.Link.CHANNEL_S2C
CHANNEL_C2S = frame.Link.CHANNEL_C2S

TAG_SUFFIX = re.compile(r"-(\d+)$")

DISPATCH_SHAPE = re.compile(r"^conn=(\d+) \((\d+),(\d+)\) -> (\d+) frame\(s\)")
UNHANDLED_SHAPE = re.compile(r"^conn=(\d+) \((\d+),(\d+)\) body=(\d+)B has no handler")
# The lookahead is load-bearing -- see the module docstring.
TAGGED_SHAPE = re.compile(r"^conn=(\d+) \((\d+),(\d+)\) (?!-> \()")
RESPONSE_SHAPE = re.compile(r"(?:->|\+)\s*\((\d+),(\d+)\)\s+(?:ack\s+)?\d+B")

# Tags whose lines carry an opcode as `conn=N (m,s)` after all four other
# shapes are accounted for.  Measured, not assumed; anything else with that
# prefix is coordinates.
TAGGED_TAGS = frozenset({"TOWN-QUEST-STATE", "TOWN-QUICKSLOT"})
CLAIMED_TAGS = frozenset({"PACKET", "DISPATCH", "UNHANDLED", "GAME"})

CHANNEL_KEY = "0x{:04x}"


class Registry:
    def __init__(self) -> None:
        self.game: dict[tuple[int, int], dict] = {}
        self.channel: dict[int, dict] = {}
        self.tagged_tags: set[str] = set()
        self.problems: list[str] = []

    def rec(self, store: dict, key, main: int, sub: int) -> dict:
        r = store.get(key)
        if r is None:
            r = store[key] = {"main": main, "sub": sub, "directions": set(),
                              "evidence": Counter(), "responses": Counter(),
                              "named_by": set(), "logged_by": set()}
        return r

    def game_rec(self, main: int, sub: int) -> dict:
        return self.rec(self.game, (main, sub), main, sub)

    def channel_rec(self, raw: int) -> dict:
        r = self.rec(self.channel, raw, raw >> 8, raw & 0xFF)
        return r

    def note(self, r: dict, source: str, direction: str, *, tag: str = "",
             frames: int | None = None) -> None:
        r["evidence"][source] += 1
        r["directions"].add(direction)
        if tag:
            r["logged_by"].add(tag)
        if frames is not None:
            r["responses"][frames] += 1


def scan_packets(reg: Registry, path: Path) -> None:
    for p in logs.iter_packets(path):
        if p.direction == "C->S":
            # The log prints the opcode for C->S; the header says the same.
            if p.opcode is None:
                reg.problems.append(f"{path.name}:{p.line_no} C->S packet without an opcode")
                continue
            main, sub = p.opcode
            if p.link == "game":
                r = reg.game_rec(main, sub)
                _check(reg, path, p.line_no, "packet-c2s", main)
                reg.note(r, "packet-c2s", "c2s")
            else:
                r = reg.channel_rec((main << 8) | sub)
                reg.note(r, "packet-c2s", "c2s")
            continue

        if p.hex is None:
            continue
        link = frame.Link(f"{p.link}-s2c")
        f = frame.try_parse(link, p.hex.data, expect_size=p.wire)
        if f is None:
            reg.problems.append(f"{path.name}:{p.line_no} undecodable S->C header")
            continue
        if p.link == "game":
            r = reg.game_rec(f.opcode.main, f.opcode.sub)
            _check(reg, path, p.line_no, "packet-s2c", f.opcode.main)
            reg.note(r, "packet-s2c", "s2c")
        else:
            raw = (f.opcode.main << 8) | f.opcode.sub
            reg.note(reg.channel_rec(raw), "packet-s2c", "s2c")


def _check(reg: Registry, path: Path, line_no: int, source: str, main: int) -> None:
    if main not in (0, 1):
        reg.problems.append(
            f"{path.name}:{line_no} {source} produced main={main}; the game "
            f"namespace only holds 0 and 1"
        )


def scan_lines(reg: Registry, path: Path) -> None:
    for ln in logs.stream(path):
        tag, msg = ln.tag, ln.msg

        if tag == "DISPATCH":
            m = DISPATCH_SHAPE.match(msg)
            if not m:
                reg.problems.append(f"{path.name}:{ln.line_no} DISPATCH shape changed: {msg[:60]}")
                continue
            main, sub, frames = int(m.group(2)), int(m.group(3)), int(m.group(4))
            _check(reg, path, ln.line_no, "dispatch", main)
            reg.note(reg.game_rec(main, sub), "dispatch", "c2s", frames=frames)

        elif tag == "UNHANDLED":
            m = UNHANDLED_SHAPE.match(msg)
            if not m:
                reg.problems.append(f"{path.name}:{ln.line_no} UNHANDLED shape changed: {msg[:60]}")
                continue
            main, sub = int(m.group(2)), int(m.group(3))
            _check(reg, path, ln.line_no, "unhandled", main)
            reg.note(reg.game_rec(main, sub), "unhandled", "c2s")

        elif tag == "GAME":
            for main, sub in logs.seen_opcodes(msg):
                _check(reg, path, ln.line_no, "seen", main)
                reg.note(reg.game_rec(main, sub), "seen", "c2s")

        elif tag in TAGGED_TAGS:
            m = TAGGED_SHAPE.match(msg)
            if m:
                main, sub = int(m.group(2)), int(m.group(3))
                _check(reg, path, ln.line_no, "tagged", main)
                reg.tagged_tags.add(tag)
                reg.note(reg.game_rec(main, sub), "tagged", "s2c", tag=tag)

        # Response refs are read from every tag, not just the ones above.
        for main, sub in RESPONSE_SHAPE.findall(msg):
            main, sub = int(main), int(sub)
            _check(reg, path, ln.line_no, "response", main)
            reg.note(reg.game_rec(main, sub), "response", "s2c")


def attach_names(reg: Registry, paths_scanned: list[Path]) -> list[str]:
    """A tag suffix names an opcode only when that opcode already has evidence."""
    candidates: dict[int, list[str]] = {}
    for path in paths_scanned:
        for ln in logs.stream(path):
            m = TAG_SUFFIX.search(ln.tag)
            if m:
                candidates.setdefault(int(m.group(1)), []).append(ln.tag)

    uncorroborated = []
    for sub in sorted(candidates):
        tags = sorted(set(candidates[sub]))
        if (1, sub) in reg.game:
            reg.game[(1, sub)]["named_by"].update(tags)
        else:
            uncorroborated.extend(tags)
    return sorted(uncorroborated)


def dump_record(r: dict) -> dict:
    evidence = r["evidence"]
    handled = True if evidence["dispatch"] else (False if evidence["unhandled"] else None)
    out = {
        "main": r["main"],
        "sub": r["sub"],
        "name": name_of(r),
        "directions": sorted(r["directions"]),
        "evidence": {k: evidence[k] for k in sorted(evidence)},
        "handled": handled,
    }
    if r["responses"]:
        out["responses"] = {str(k): r["responses"][k] for k in sorted(r["responses"])}
    if r["named_by"]:
        out["named_by"] = sorted(r["named_by"])
    if r["logged_by"]:
        out["logged_by"] = sorted(r["logged_by"])
    return out


def name_of(r: dict) -> str | None:
    if not r["named_by"]:
        return None
    return TAG_SUFFIX.sub("", sorted(r["named_by"])[0])


def build_payload(log_paths: list[Path]) -> dict:
    """Scan every log and return the registry document.  Raises RegistryError
    rather than emitting anything when a shape it depends on has changed."""
    reg = Registry()
    for path in log_paths:
        scan_packets(reg, path)
        scan_lines(reg, path)
    uncorroborated = attach_names(reg, log_paths)

    if reg.problems:
        raise RegistryError(reg.problems)

    return {
        "generated_by": "tools/gen_opcodes.py",
        "logs": [p.name for p in log_paths],
        "game": {f"{m},{s}": dump_record(reg.game[(m, s)])
                 for m, s in sorted(reg.game)},
        "channel": {CHANNEL_KEY.format(raw): dump_record(reg.channel[raw])
                    for raw in sorted(reg.channel)},
        "tagged_tags": sorted(reg.tagged_tags),
        "uncorroborated_tags": uncorroborated,
    }


class RegistryError(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__(f"{len(problems)} problem(s): " + "; ".join(problems[:3]))
        self.problems = problems


def render(payload: dict) -> str:
    return json.dumps(payload, indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", type=Path, action="append", default=None,
                    help="repeatable; defaults to paths.CORPUS_LOGS")
    ap.add_argument("--out", type=Path, default=paths.OPCODES_JSON)
    a = ap.parse_args()

    log_paths = a.log or paths.corpus_logs()
    if not log_paths:
        raise SystemExit(f"no server-*.log under {paths.LOGS_DIR}")

    try:
        payload = build_payload(log_paths)
    except RegistryError as e:
        for p in e.problems[:20]:
            print(f"ERROR {p}", file=sys.stderr)
        raise SystemExit(str(e)) from None

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(render(payload), encoding="utf-8")

    game, chan = payload["game"], payload["channel"]
    by_dir = Counter(d for r in game.values() for d in r["directions"])
    named = sum(1 for r in game.values() if r["name"])
    print(f"wrote {a.out}")
    print(f"  logs      {', '.join(payload['logs'])}")
    print(f"  game      {len(game)} opcodes ({dict(sorted(by_dir.items()))}), {named} named")
    print(f"  channel   {len(chan)} opcodes: {', '.join(chan)}")
    print(f"  handled   {sum(1 for r in game.values() if r['handled'] is True)} dispatched, "
          f"{sum(1 for r in game.values() if r['handled'] is False)} unhandled")
    print(f"  tags      {len(reg.tagged_tags)} carry opcodes {sorted(reg.tagged_tags)}, "
          f"{len(uncorroborated)} uncorroborated: {uncorroborated}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
