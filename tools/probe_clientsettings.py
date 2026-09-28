#!/usr/bin/env python3
"""One login that pins every request body the corpus never dumped.

The corpus cannot answer any of these; the run answers them all at once:

* which u16 in the 492B blob the reference prints as `recommendedGuideShown`.
  Every line since 09-19 21:36 prints 1, and 49 u16 slots hold 1, so the slot
  is ambiguous.  `setup` copies the save and replaces each of those slots with
  a unique 2000+i, then points `storage.dataDirectory` at the copy -- the push
  line the reference logs then names its own offset.
* what the client sends on `(1,197)` / `(1,439)` (the save lines print one
  size; the dump's `body=` settles 492 vs the padded 496/504).
* the request bodies of `(1,21)` NPC-BUY, `(1,309)` NPC-REDEEM, `(1,64)`
  SHOP-BUY and `(1,44)` ITEM-USE -- not one has ever been dumped, and
  `(0,292)`'s empty-list reply to `(1,309)` is unobserved too.
* the **reply** frames those requests draw, and the ones a cargo move
  (`(1,19)` into or out of `list=2`) draws: the reference answers all of them
  with a run of frames, and no dump in the corpus holds a single one, so
  `report` pairs every probed request with the frames that follow it.

The live `uslocalserver.db` is never the server's database: the copy under
`_csprobe/data/` is what `dataDirectory` points at, and `server.reference.json`
documents an absolute path as the way to an independent test DB.  `setup`
still backs the live set up; `report` checks it did not move; `restore` puts
`server.json` and the live save back.

    python tools/probe_clientsettings.py setup
    # launch the reference as usual, log in, and pick *LRouDao* -- the
    #   character no dump ever captured, which is what makes its 1296B
    #   `(1,4)` body the first second-character sample; then buy something at
    #   a shop NPC, open the buyback/redeem list, use a consumable, move one
    #   item into the account cargo and one back out, quit normally
    python tools/probe_clientsettings.py report
    python tools/probe_clientsettings.py restore
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import struct
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.launcher import ports as launcher_ports  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402

#: Patched slots read 2000, 2001, ...; the value the live blob's slot holds
#: (and the reference's lines print) is what gets replaced.
PATCH_BASE = 2000
DEFAULT_SLOT_VALUE = 1
ROW_SIZE = 492

USER_JSON = (Path(os.environ.get("LOCALAPPDATA", "")) / "USLocalServer"
             / "Tester" / "server.json")
SCRATCH = paths.REPO_ROOT / "_csprobe"
DATA_DIR = SCRATCH / "data"
LIVE_BAK = SCRATCH / "live"
JSON_BAK = SCRATCH / "server.json.bak"
BLOB_BAK = SCRATCH / "blob.orig"
CANDIDATES = SCRATCH / "candidates.json"
LOG_DIR = paths.REPO_ROOT / "Logs-csprobe"

#: C->S opcodes whose request body has never been dumped.  `report` decrypts
#: each and appends it to `_csprobe/c2s-<main>-<sub>.hex`.
BODY_OPS = ((1, 197), (1, 439), (1, 21), (1, 309), (1, 64), (1, 44), (1, 19))

#: A `PACKET conn=N C->S game` dump is the whole frame; its header is 13 bytes
#: (`frame.header_len(Link.GAME_C2S)`), the body follows.
C2S_HEADER = frame.header_len(frame.Link.GAME_C2S)

#: The live save's file set: the DB and, when present, its write-ahead log.
LIVE_SET = tuple(Path(str(paths.SAVE_DB) + suf) for suf in ("", "-wal", "-shm"))

PUSH_RE = re.compile(r"S0/173\s+(\d+)B\s+recommendedGuideShown=(\d+)")
SAVE_RE = re.compile(r"saved C1/197\s+(\d+)B\s+recommendedGuideShown=(\d+)")


def _refuse_if_running() -> None:
    taken = launcher_ports.occupants()
    if taken:
        raise SystemExit("ports busy: " + "; ".join(str(o) for o in taken)
                         + "\nclose the reference server first")


def _set_key(lines: list[str], key: str, value) -> bool:
    """Replace the one `"key": ...` line, keeping the file's shape."""
    for i, line in enumerate(lines):
        if f'"{key}"' in line:
            indent = line[:len(line) - len(line.lstrip())]
            comma = "," if line.rstrip().endswith(",") else ""
            lines[i] = f'{indent}"{key}": {json.dumps(value)}{comma}\n'
            return True
    return False


def _effective_json() -> dict:
    return json.loads(USER_JSON.read_text(encoding="utf-8-sig"))


def _last_printed_value() -> tuple[int, str] | None:
    """The newest `recommendedGuideShown=N` in the reference's own logs."""
    for log in reversed(paths.server_logs()):
        last = None
        for ln in logs.stream(log):
            if ln.tag != "CLIENT-SETTINGS":
                continue
            m = PUSH_RE.search(ln.msg) or SAVE_RE.search(ln.msg)
            if m:
                last = (int(m.group(2)), ln.ts)
        if last:
            return last
    return None


def cmd_setup(_args: argparse.Namespace) -> int:
    if not USER_JSON.is_file():
        raise SystemExit(f"no per-user server.json at {USER_JSON}")
    if _effective_json().get("storage", {}).get("dataDirectory") == str(DATA_DIR):
        raise SystemExit(f"{USER_JSON} already points at {DATA_DIR}"
                         " -- run `restore` first")
    _refuse_if_running()

    value = DEFAULT_SLOT_VALUE
    if found := _last_printed_value():
        value, ts = found
        print(f"the live blob prints recommendedGuideShown={value} (last: {ts})")

    SCRATCH.mkdir(parents=True, exist_ok=True)
    LIVE_BAK.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # A leftover -wal from an earlier run must not pair with the fresh main
    # file -- wipe both dirs so the copy is exactly the live set.
    for d in (LIVE_BAK, DATA_DIR):
        for f in d.iterdir():
            f.unlink()

    copied, live_state = [], {}
    for src in LIVE_SET:
        if not src.exists():
            continue
        shutil.copy2(src, LIVE_BAK / src.name)
        shutil.copy2(src, DATA_DIR / src.name)
        copied.append(src.name)
        st = src.stat()
        live_state[src.name] = {"mtime": st.st_mtime, "size": st.st_size}
    print(f"backed up and copied: {', '.join(copied)}")

    db = DATA_DIR / paths.SAVE_DB.name
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("select account_id, options "
                            "from account_client_settings").fetchall()
        if len(rows) != 1:
            raise SystemExit(f"expected one account_client_settings row, "
                             f"found {len(rows)}")
        account, options = rows[0]
        if len(options) != ROW_SIZE:
            raise SystemExit(f"the row is {len(options)}B, expected {ROW_SIZE}B")
        BLOB_BAK.write_bytes(options)

        blob = bytearray(options)
        values: dict[str, int] = {}
        for off in range(0, ROW_SIZE - 1, 2):
            if struct.unpack_from("<H", blob, off)[0] == value:
                v = PATCH_BASE + len(values)
                struct.pack_into("<H", blob, off, v)
                values[str(v)] = off
        if not values:
            raise SystemExit(f"no u16 slot holds {value} -- nothing to patch")
        conn.execute("update account_client_settings set options = ? "
                     "where account_id = ?", (bytes(blob), account))
        conn.commit()
    finally:
        conn.close()

    CANDIDATES.write_text(json.dumps({
        "account_id": account,
        "patched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "patched_epoch": time.time(),
        "slot_value": value,
        "values": values,
        "live_state": live_state,
        "live_db": str(paths.SAVE_DB),
        "scratch_db": str(db),
    }, indent=2), encoding="utf-8")
    print(f"patched {len(values)} slots holding {value} -> "
          f"{PATCH_BASE}..{PATCH_BASE + len(values) - 1} (account {account})")

    lines = USER_JSON.read_text(encoding="utf-8-sig").splitlines(keepends=True)
    # 4096 truncated 16 frames in the 09-27 session (the largest S->C frame is
    # 12568B); at 16384 one login dumps every frame whole.
    wanted = {"dataDirectory": str(DATA_DIR), "logDirectory": str(LOG_DIR),
              "packetHexLog": True, "packetHexMaxBytes": 16384}
    missing = [k for k, v in wanted.items() if not _set_key(lines, k, v)]
    if missing:
        raise SystemExit(f"{USER_JSON}: no line for {', '.join(missing)}")
    shutil.copy2(USER_JSON, JSON_BAK)
    USER_JSON.write_text("".join(lines), encoding="utf-8-sig")

    diag = _effective_json()
    print(f"server.json  dataDirectory = {diag['storage']['dataDirectory']}")
    print(f"server.json  logDirectory  = {diag['diagnostics']['logDirectory']}")
    print(f"server.json  packetHexLog  = {diag['diagnostics']['packetHexLog']} "
          f"maxBytes={diag['diagnostics']['packetHexMaxBytes']}")
    print(f"backup       {JSON_BAK}")
    print("\nNext: launch the reference server as usual, log in, and pick "
          "LRouDao\n      (every dump so far is XRenYing -- this is the first "
          "second-character\n      `(1,4)` sample), let the town load.  Also do "
          "exactly one of each, so\n      every reply run has a witness: buy one"
          " item at a shop NPC, open the\n      buyback/redeem list, use one "
          "consumable, and move one item into the\n      account cargo and one "
          "back out.  Then quit the client normally."
          "\n      python tools/probe_clientsettings.py report")
    return 0


def _offsets_of(blob: bytes, target: int) -> list[str]:
    hits = [f"u16@{off}" for off in range(0, ROW_SIZE - 1)
            if struct.unpack_from("<H", blob, off)[0] == target]
    hits += [f"u32@{off}" for off in range(0, ROW_SIZE - 3)
             if struct.unpack_from("<I", blob, off)[0] == target]
    return hits


def _report_guide(log: Path, values: dict[str, int], blob: bytes | None) -> None:
    print("\n== CLIENT-SETTINGS lines ==")
    pushes: list[tuple[str, int, int]] = []
    saves: list[tuple[str, int, int]] = []
    for ln in logs.stream(log):
        if ln.tag != "CLIENT-SETTINGS":
            continue
        if m := PUSH_RE.search(ln.msg):
            pushes.append((ln.ts, int(m.group(1)), int(m.group(2))))
        elif m := SAVE_RE.search(ln.msg):
            saves.append((ln.ts, int(m.group(1)), int(m.group(2))))
    for kind, rows in (("push", pushes), ("save", saves)):
        for ts, size, n in rows:
            slot = values.get(str(n))
            print(f"  {kind} {ts} {size}B recommendedGuideShown={n}"
                  + (f"  -> slot {slot}" if slot is not None else ""))
    if not pushes and not saves:
        print("  (none -- the client never reached character selection)")

    for n in sorted({p[2] for p in pushes} | {s[2] for s in saves}):
        if str(n) in values:
            print(f"\n>>> GUIDE_SHOWN_AT = {values[str(n)]} "
                  f"(the reference prints {n} from it)")
        elif blob is not None:
            print(f"\n!! {n} is not one of the patched values; it reads as "
                  f"{_offsets_of(blob, n) or 'nothing'} in the scratch blob")
        elif n == DEFAULT_SLOT_VALUE:
            print(f"\n!! the push still prints {n} -- the reference did not "
                  f"open {DATA_DIR};\n   the live save is untouched, check "
                  "the dataDirectory line above")


def _report_body(log: Path) -> None:
    print("\n== C->S request bodies ==")
    counts: dict[tuple[int, int], int] = {}
    for p in logs.iter_packets(log):
        if p.direction != "C->S" or p.link != "game" or p.hex is None:
            continue
        if p.opcode not in BODY_OPS:
            continue
        plain = None
        try:
            # The dump is the whole frame; the game C->S header is 13 bytes.
            plain = tiles.decrypt_body(tiles.algo_id(p.opcode[1]),
                                       p.frame_bytes[C2S_HEADER:])
        except Exception as exc:  # noqa: BLE001 -- report it, do not crash
            note = f"  decrypt failed: {exc}"
        else:
            shown = plain if len(plain) <= 64 else plain[:64]
            note = f"  plain={len(plain)}B {shown.hex()}"
            if len(plain) > 64:
                note += " ..."
            if p.opcode == (1, 197):
                note += ("  <- the 492B blob" if len(plain) == ROW_SIZE
                         else "  <- NOT the 492B blob")
        if plain is None and p.truncated:
            note += " (hex truncated)"
        counts[p.opcode] = counts.get(p.opcode, 0) + 1
        print(f"  {p.ts} ({p.opcode[0]},{p.opcode[1]}) wire={p.wire} "
              f"body={p.body_len} hex={len(p.frame_bytes)}B{note}")
        if plain is not None:
            out = SCRATCH / f"c2s-{p.opcode[0]}-{p.opcode[1]}.hex"
            with out.open("a", encoding="utf-8") as fh:
                fh.write(f"# {p.ts} wire={p.wire} body={p.body_len}\n"
                         f"{plain.hex()}\n")
    if not counts:
        print("  (none of " + ", ".join(f"({m},{s})" for m, s in BODY_OPS)
              + " were dumped -- packetHexLog off, or nothing was done)")
    else:
        print("  written -> " + ", ".join(
            f"{SCRATCH / f'c2s-{m}-{s}.hex'} ({n})"
            for (m, s), n in sorted(counts.items())))


#: Lines between a request and the next one that say nothing about it.
_QUIET = frozenset({"PACKET", "CONNECT", "ROUTE", "DISCONNECT", "STUN",
                    "SESSION", "LOGIN", "CHANNEL", "HANDSHAKE", "CHANNELINFO",
                    "LEGACY-QUERY", "GET_USERINFO"})

#: Per-run caps: this is a report to read, not a log to ship.
MAX_RUN_NOTES = 12
NOTE_WIDTH = 130


def _reply_line(p: logs.PacketRecord) -> str:
    wire = "?" if p.wire is None else p.wire
    if p.hex is None:
        return f"      (?,?) wire={wire}B (no hex dump)"
    if p.truncated:
        return (f"      (?,?) wire={wire}B (hex cut at {len(p.hex.data)}B; "
                f"raise packetHexMaxBytes)")
    fr = frame.parse(frame.Link.GAME_S2C, p.frame_bytes, strict=False)
    plain = tiles.decrypt_body(tiles.algo_id(fr.opcode.sub), fr.body)
    shown = plain if len(plain) <= 96 else plain[:96]
    return (f"      {fr.opcode} wire={wire}B plain={len(plain)}B {shown.hex()}"
            + (" ..." if len(plain) > 96 else ""))


def _report_runs(log: Path) -> None:
    """Each probed request with everything the reference answered with.

    The corpus holds no reply frame for any of these opcodes -- every one of
    them predates a dump window, or (for a cargo move) never appears in one --
    so the run of frames plus the lines written in between *is* the shape a
    handler has to reproduce.
    """
    print("\n== request -> reply runs ==")
    packets = {p.line_no: p for p in logs.iter_packets(log) if p.link == "game"}
    runs: list[dict] = []
    run = None
    for ln in logs.stream(log):
        p = packets.get(ln.line_no)
        if p is None:
            if (run is not None and ln.tag not in _QUIET
                    and len(run["lines"]) < MAX_RUN_NOTES):
                run["lines"].append(f"      {ln.level:5} {ln.tag:14} "
                                    f"{ln.msg[:NOTE_WIDTH]}")
            continue
        if p.direction == "C->S":
            run = None
            if p.opcode in BODY_OPS:
                req = None
                if p.hex is not None and not p.truncated:
                    req = tiles.decrypt_body(tiles.algo_id(p.opcode[1]),
                                             p.frame_bytes[C2S_HEADER:])
                run = {"op": p.opcode, "ts": p.ts, "body": p.body_len,
                       "req": req, "lines": []}
                runs.append(run)
            continue
        if run is not None:
            run["lines"].append(_reply_line(p))

    if not runs:
        print("  (no probed request was sent -- nothing to pair)")
        return
    for r in runs:
        req = "" if r["req"] is None else f" {r['req'].hex()}"
        print(f"  ({r['op'][0]},{r['op'][1]}) {r['ts']} "
              f"request body={r['body']}B{req}")
        for line in r["lines"] or ["      (no reply frame)"]:
            print(line)


def cmd_report(args: argparse.Namespace) -> int:
    log = args.log
    if log is None:
        logs_here = sorted(LOG_DIR.glob("server-*.log"))
        if not logs_here:
            raise SystemExit(f"no server-*.log under {LOG_DIR} -- run `setup` "
                             "and the reference first")
        log = logs_here[-1]
    print(f"log: {log}")
    for s in logs.sessions(log):
        print(f"  session {s}  hex_dumps={s.hex_dumps}")

    values: dict[str, int] = {}
    blob = None
    if CANDIDATES.exists():
        cand = json.loads(CANDIDATES.read_text(encoding="utf-8"))
        values = cand["values"]
        print(f"candidates: {len(values)} patched slots (account "
              f"{cand['account_id']}, {cand['patched_at']})")
        scratch = Path(cand["scratch_db"])
        if scratch.exists():
            conn = sqlite3.connect(f"file:{scratch}?mode=ro", uri=True)
            try:
                blob = conn.execute("select options from account_client_settings "
                                    "where account_id = ?",
                                    (cand["account_id"],)).fetchone()[0]
            finally:
                conn.close()
            wrote = scratch.stat().st_mtime >= cand["patched_epoch"]
            print(f"scratch db: {len(blob)}B row, written during the session: "
                  f"{'yes' if wrote else 'no'}")
        for name, st in cand["live_state"].items():
            live = Path(cand["live_db"] + name[len(paths.SAVE_DB.name):])
            now = live.stat() if live.exists() else None
            same = (now is not None
                    and abs(now.st_mtime - st["mtime"]) < 1
                    and now.st_size == st["size"])
            print(f"live {live.name}: {'unchanged' if same else 'CHANGED'}"
                  + ("" if same else "  <- run `restore`"))
    else:
        print("no candidates.json -- run `setup` first")

    _report_guide(log, values, blob)
    _report_body(log)
    _report_runs(log)
    print("\nWhen the two answers are recorded, run "
          "`python tools/probe_clientsettings.py restore`.")
    return 0


def cmd_restore(_args: argparse.Namespace) -> int:
    _refuse_if_running()
    if JSON_BAK.exists():
        shutil.copy2(JSON_BAK, USER_JSON)
        print(f"server.json restored from {JSON_BAK}")
    elif USER_JSON.is_file():
        print(f"{JSON_BAK} is missing -- server.json left as it is")
    if LIVE_BAK.is_dir():
        for p in LIVE_SET:
            if p.exists():
                p.unlink()
        for f in sorted(LIVE_BAK.iterdir()):
            shutil.copy2(f, paths.SAVE_DB.parent / f.name)
            print(f"restored {f.name} -> {paths.SAVE_DB.parent}")
    else:
        print(f"{LIVE_BAK} is missing -- the live save was left as it is")
    print(f"scratch kept at {SCRATCH} (delete it once the findings are "
          "written down)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup", help="patch the copy and point the config at it")
    rep = sub.add_parser("report", help="read the probe log")
    rep.add_argument("--log", type=Path, default=None,
                     help="default: newest server-*.log under Logs-csprobe")
    sub.add_parser("restore", help="put server.json and the live save back")
    args = p.parse_args()
    return {"setup": cmd_setup, "report": cmd_report,
            "restore": cmd_restore}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
