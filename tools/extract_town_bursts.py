#!/usr/bin/env python3
"""Extract the per-character town-entry bursts into data/game/town_bursts.json.

`data/game/replies.json` can hold one burst per entry opcode -- the M2 corpus's
33-frame `(1,143)` and the 09-28 session's 31-frame `(1,666)` -- but a burst is
really the *entering character's own* frame list: the three characters of this
save enter with 33, 31 and 30 frames (`game/town/burst.py` has the shapes).
The two captures this tool adds are the two the script file cannot hold:

    key=2  LRouDao  31 frames  server-20260927.log line 2110 (request 22:53:39)
    key=3  XJianHun 30 frames  server-20260929.log line 1149 (request 23:57:39)

Both are sent with `(1,143)` from `CharacterSelected`, in sessions logged with
`packetHexLog` on, and both were checked against the live save before this tool
existed: the giant `(0,2)` and the whole `(0,13)` bag header are byte-identical
to what `giant.body`/`burst.Inventory` build from the save today.

Every frame has to be complete.  The reference cuts its hex dumps at 4096 bytes
(4080 of body) and a burst stored half-visible would replay a half-visible
frame, so a truncated frame is an error -- except the main inventory, which is
the one frame *both* captures cut (7272B and 4136B bodies) and the one the
server never replays: it is rebuilt from the save at entry and only the other
bag frames come out of this file.

    python tools/extract_town_bursts.py                  # report
    python tools/extract_town_bursts.py --json           # write the file
    python tools/extract_town_bursts.py --logs-dir <dir> # other log directory

The file is generated, never edited: regenerate it when a new character's
burst is captured and add that capture to `SAMPLES`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
import extract_game_replies as E  # noqa: E402

OUT = paths.DATA_DIR / "game" / "town_bursts.json"

#: `(key, request_main, request_sub, log name, line of the request packet)`.
#: A sample is only worth adding when the run is complete and the request went
#: out from `CharacterSelected` -- the tool fails loudly on either.
SAMPLES = (
    (2, 1, 143, "server-20260927.log", 2110),
    (3, 1, 143, "server-20260929.log", 1149),
)

#: The frames `game.town.burst.locate` must find, as `(main, sub) -> how many`:
#: everything the server rebuilds or addresses.  The two `(0,2)` and the
#: `(0,13)` stack are counted the same way -- what says they resolve is
#: `locate` itself, which the report calls on the extracted run.
BUILT = ((0, 376), (0, 342), (0, 291), (0, 21), (0, 23), (0, 24), (0, 22),
         (0, 53))

#: The kind byte that makes a `(0,13)` the main inventory, and the opcode --
#: the only frame this tool tolerates being cut.
INVENTORY_KIND = 0
LIST_OPCODE = (0, 13)


def session_for(path: Path, line: int) -> logs.Session:
    for sess in logs.sessions(path):
        if sess.kind == "game" and sess.first <= line <= sess.last:
            return sess
    raise SystemExit(f"{path.name}: no game session covers line {line}")


def burst_of(path: Path, line: int, main: int, sub: int) -> dict:
    """The run the `(main, sub)` request at `line` drew, as the script's own dict."""
    sess = session_for(path, line)
    sess_doc, events = E.corpus_events(path, sess)
    _, scripts = E.build_script(sess_doc, events)
    rec = next((s for s in scripts
                if (s["request_main"], s["request_sub"]) == (main, sub)), None)
    if rec is None:
        raise SystemExit(f"{path.name}: no ({main},{sub}) request at line {line}")
    run = next((r for r in rec["runs"] if r["line"] == line), None)
    if run is None:
        raise SystemExit(f"{path.name}: the ({main},{sub}) run at line {line} "
                         f"has no replies")
    return run


def check(run: dict, path: Path, key: int) -> int:
    """Fail on anything the server would replay wrong, return the frame count."""
    if run["state"] != ["CharacterSelected", "InTown"]:
        raise SystemExit(f"{path.name} key={key}: the run at line {run['line']} "
                         f"left state {run['state']}, not CharacterSelected->InTown")
    seen: dict[tuple[int, int], int] = {}
    for i, p in enumerate(run["replies"]):
        op = (p["main"], p["sub"])
        seen[op] = seen.get(op, 0) + 1
        plain = E.plaintext_of(p["main"], p["sub"], p["body"])
        if plain is None:
            raise SystemExit(f"{path.name} key={key}: frame {i} {op} is generated, "
                             f"not a captured body")
        if not p["truncated"]:
            continue
        inventory = op == LIST_OPCODE and plain[0] == INVENTORY_KIND
        if not inventory:
            raise SystemExit(f"{path.name} key={key}: frame {i} {op} is cut "
                             f"({len(plain)} of {len(p['body']) + p['missing']}B) "
                             f"and the server would replay it half-visible")
        print(f"    frame {i} {op} is cut at {len(plain)}B "
              f"(rebuild from the save at entry; never replayed)")
    for op in BUILT:
        if seen.get(op) != 1:
            raise SystemExit(f"{path.name} key={key}: {seen.get(op, 0)} frame(s) "
                             f"of {op}, expected exactly 1")
    return len(run["replies"])


def main(argv: list[str]) -> int:
    logs_dir = paths.LOGS_DIR
    if "--logs-dir" in argv:
        i = argv.index("--logs-dir")
        if i + 1 >= len(argv):
            raise SystemExit("--logs-dir needs a path")
        logs_dir = Path(argv[i + 1])

    bursts = []
    for key, main, sub, name, line in SAMPLES:
        path = logs_dir / name
        if not path.exists():
            raise SystemExit(f"missing log {path}")
        run = burst_of(path, line, main, sub)
        print(f"key={key} ({main},{sub}) {name}:{line} ts={run['line']} "
              f"frames={len(run['replies'])}")
        frames = check(run, path, key)
        bursts.append({
            "key": key,
            "request_main": main,
            "request_sub": sub,
            "capture": name,
            "line": line,
            "state": run["state"],
            "notes": [[lv, tag, msg] for lv, tag, msg in run["notes"]],
            "replies": [E.frame_doc(p) for p in run["replies"]],
        })
        for i, p in enumerate(run["replies"]):
            plain = E.plaintext_of(p["main"], p["sub"], p["body"])
            print(f"  {i:2d} ({p['main']},{p['sub']}) n={len(plain)}"
                  + (" TRUNC" if p["truncated"] else ""))
        print(f"  -> {frames} frames\n")

    if "--json" not in argv:
        return 0
    doc = {
        "generated_by": "tools/extract_town_bursts.py",
        "note": ("The town-entry burst per character, keyed by the character's "
                 "slot key and the opcode the client entered through.  Bodies "
                 "are stored decrypted like data/game/replies.json's, and the "
                 "run shapes are the same; `game.town.burst.locate` addresses "
                 "the frames by opcode because the lists differ per character. "
                 "The main inventory (0,13) frame is rebuilt from the save at "
                 "entry and its stored copy here is the capture's cut prefix -- "
                 "never replay it."),
        "bursts": bursts,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"wrote {OUT.relative_to(paths.REPO_ROOT)} ({OUT.stat().st_size}B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
