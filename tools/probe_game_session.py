#!/usr/bin/env python3
"""Dump the captured game session (conn=2) as an ordered request/reply script.

`server-20260926.log` holds six game sessions and `conn=` restarts from 1
across server restarts, so keying on `conn=` alone silently concatenates them.
Only the *last* session (log lines 6390..6930) has `packetHexLog` on -- 6
channel dumps + 282 game dumps -- and only that one can be a corpus.  It is the
session that reaches town, so it is what the M1 game server has to reproduce.

Two packet line shapes, both decoded here from the hex rather than from the
prose fields:

    DEBUG PACKET conn=2 C->S game (1,1554) wire=29 body=16 state=Connected->Connected hex=...
    DEBUG PACKET conn=2 S->C game raw=527 sent hex=...

The S->C line carries no opcode at all; it is recovered by framing the hex with
`protocol.frame`.  The C->S line does carry one, and `--check` asserts the two
agree, which is a free regression on the framer.

    python tools/probe_game_session.py                 # ordered script
    python tools/probe_game_session.py --tag TOWN-SELF
    python tools/probe_game_session.py --pairs           # request -> replies
    python tools/probe_game_session.py --json            # data/game/session.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402

LOG = paths.LOGS_DIR / "server-20260926.log"
OUT = paths.DATA_DIR / "game" / "session.json"

LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) \+\d\d:\d\d (\w+)\s+(\S+)\s+(.*)$")
CONN_RE = re.compile(r"conn=(\d+) (game|channel):(\d+)")
PKT_RE = re.compile(r"conn=(\d+)\s+(C->S|S->C)\s+(game|channel)\b")
OP_RE = re.compile(r"\((\d+),(\d+)\)")
HEX_RE = re.compile(r"\bhex=([0-9a-fA-F]+)")
STATE_RE = re.compile(r"state=(\w+)->(\w+)")


def sessions():
    """Every connection in the log: dict(conn, kind, port, first, last, hex)."""
    out = []
    cur = None
    with open(LOG, encoding="utf-8", errors="replace") as f:
        for i, ln in enumerate(f, 1):
            m = LINE_RE.match(ln)
            if not m:
                continue
            lvl, tag, msg = m.group(2), m.group(3), m.group(4)
            if lvl == "INFO" and tag == "CONNECT":
                c = CONN_RE.search(msg)
                cur = {"conn": int(c.group(1)), "kind": c.group(2),
                       "port": int(c.group(3)), "first": i, "last": i, "hex": 0}
                out.append(cur)
            elif cur is not None:
                if lvl == "DEBUG" and tag == "PACKET" and "hex=" in msg:
                    cur["hex"] += 1
                cur["last"] = i
                if lvl == "INFO" and tag == "DISCONNECT" and " after " in msg:
                    cur = None
    return out


def pick_session(index: int | None = None):
    """The hex-carrying game session to use as the corpus."""
    gs = [s for s in sessions() if s["kind"] == "game" and s["hex"] > 0]
    if not gs:
        raise SystemExit("no game session has packetHexLog data")
    return gs[-1] if index is None else gs[index]


def parse_hex(hexs: str, link):
    """Frame the logged hex.  Returns (opcode, body, truncated) or None."""
    raw = bytes.fromhex(hexs)
    try:
        fr = frame.parse(link, raw, strict=False)
    except frame.ProtocolError:
        return None
    return fr.opcode, fr.body, fr.header


def rows(sess):
    """Walk the session, yielding packets decoded, and prose notes verbatim."""
    conn = sess["conn"]
    with open(LOG, encoding="utf-8", errors="replace") as f:
        for i, ln in enumerate(f, 1):
            if i < sess["first"] or i > sess["last"]:
                continue
            m = LINE_RE.match(ln)
            if not m:
                continue
            ts, lvl, tag, msg = m.groups()
            m2 = PKT_RE.search(msg)
            if m2 and m2.group(3) == "game" and m2.group(1) == str(conn):
                hm = HEX_RE.search(msg)
                if not hm:
                    continue
                link = (frame.Link.GAME_C2S if m2.group(2) == "C->S"
                        else frame.Link.GAME_S2C)
                got = parse_hex(hm.group(1), link)
                st = STATE_RE.search(msg)
                yield {"line": i, "ts": ts[11:], "kind": "packet",
                       "dir": m2.group(2), "truncated": "(+" in msg,
                       "state": list(st.groups()) if st else None,
                       "decoded": got,
                       "logged_op": ([int(x) for x in OP_RE.search(msg).groups()]
                                     if OP_RE.search(msg) else None)}
            elif m2 is None and not (lvl == "DEBUG" and tag == "PACKET"):
                yield {"line": i, "ts": ts[11:], "kind": "note",
                       "level": lvl, "tag": tag, "msg": msg}


def main(argv: list[str]) -> int:
    tag_filter = None
    as_json = False
    pairs = False
    index = None
    it = iter(argv)
    for a in it:
        if a == "--tag":
            tag_filter = next(it)
        elif a == "--json":
            as_json = True
        elif a == "--pairs":
            pairs = True
        elif a == "--session":
            index = int(next(it))

    sess = pick_session(index)
    print(f"# session conn={sess['conn']} {sess['kind']}:{sess['port']} "
          f"lines {sess['first']}..{sess['last']}\n")

    records = []
    pending: list = []
    bad = 0
    for r in rows(sess):
        if r["kind"] == "note":
            if tag_filter and r["tag"] != tag_filter:
                continue
            records.append(r)
            print(f"{r['line']:>5} {r['ts']} {r['level']:<5} {r['tag']}: {r['msg'][:140]}")
            continue
        got = r["decoded"]
        if got is None:
            r["op"] = None
            print(f"{r['line']:>5} {r['ts']} {r['dir']} <unframed> "
                  f"{'trunc' if r['truncated'] else ''}")
            records.append(r)
            continue
        op, body, _hdr = got
        r["op"] = [op.main, op.sub]
        nbytes = len(body) + frame.header_len(
            frame.Link.GAME_C2S if r["dir"] == "C->S" else frame.Link.GAME_S2C)
        records.append(r)
        if tag_filter:
            continue
        st = f" {r['state'][0]}->{r['state'][1]}" if r["state"] else ""
        if r["logged_op"] is not None and r["logged_op"] != [op.main, op.sub]:
            bad += 1
            print(f"!! line {r['line']}: log says {r['logged_op']} frame says "
                  f"({op.main},{op.sub})")
        print(f"{r['line']:>5} {r['ts']} {r['dir']} ({op.main},{op.sub})"
              f" body={len(body):<6} wire={nbytes:<6}{st}"
              + ("  [truncated]" if r["truncated"] else ""))

    if pairs:
        print("\n--- request -> replies ---")
        cur_req = None
        for r in records:
            if r["kind"] != "packet" or r["op"] is None:
                continue
            op = tuple(r["op"])
            if r["dir"] == "C->S":
                cur_req = (op, r)
            else:
                req = f"({cur_req[0][0]},{cur_req[0][1]})" if cur_req else "?"
                print(f"  {req:>10} -> ({op[0]},{op[1]}) body={len(r['decoded'][1])}")

    if as_json:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(
            {"session": {k: sess[k] for k in ("conn", "kind", "port", "first", "last")},
             "records": records}, indent=1), encoding="utf-8")
        print(f"\nwrote {OUT.relative_to(paths.REPO_ROOT)} ({OUT.stat().st_size}B)")
    if bad:
        print(f"\n{bad} opcode disagreement(s)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
