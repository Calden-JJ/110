#!/usr/bin/env python3
"""Turn the captured game session into the game server's reply script.

The corpus is the single `packetHexLog`-on session (`probe_game_session.py`
picks it): `conn=2 game:10013`, log lines 6390..6930, 221 C->S + 61 S->C.

The script is keyed by the C->S opcode that triggers each reply run, because
that is exactly what the server needs on dispatch.  The *bodies* are stored
decrypted, not as wire bytes:

* S->C bodies round-trip byte-exactly through `tiles.encrypt_body(sub % 14, p)`
  on all 57 untruncated frames, so replaying ciphertext would only hide a
  broken cipher in the live path.  Storing plaintext forces the server through
  the same tile + header code the reference runs.
* The `(0,1)` CHANNELINFO is not a tile at all: it is `rol8(b ^ 0xb5, 2)`, the
  pre-cipher bootstrap frame the log announces with "session ciphers
  initialized".  It is also a pure function of (server, channel, host,
  unixSeconds) -- `tools/probe_chaninfo_build.py` reproduces the captured
  511B byte-for-byte -- so the server generates it.  Only the transform name
  is recorded here.
* The 3-byte nonce at `hdr[12:15]` is captured verbatim.  Nothing says the
  client validates it; nothing says it does not.

The 4096-byte dump cap loses less than it looks.  All four truncated frames cut
at a 16-byte body boundary (4080B visible = 255 whole blocks), and ECB with a
passthrough trailing partial block means the visible ciphertext decrypts to the
*true* plaintext prefix.  So they ship as a prefix plus a byte count rather
than as an unreadable stub.

`--completion <log>` finishes them.  The corpus is the only log with packet
dumps, so its own missing bytes are nowhere in it; the way to get them is to
replay the session's C->S frames at the reference with `packetHexMaxBytes`
raised, which is what `tools/replay_capture.py --external` does.  That log's
S->C frames come back whole and, frame for frame, are the corpus's own --
`--completion` proves it rather than assuming it: the tile is a block cipher,
so encrypting the completion's plaintext must reproduce the ciphertext the
corpus *did* write down, and opcode and declared length must agree too.  Any
disagreement is an error, not a silently rewritten script.

    python tools/extract_game_replies.py             # report
    python tools/extract_game_replies.py --json      # write data/game/replies.json
    python tools/extract_game_replies.py --json --completion Logs/reference-replay-20260927.log
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402
import probe_game_session as P  # noqa: E402

OUT = paths.DATA_DIR / "game" / "replies.json"
CHANNELINFO = (0, 1)
HDR = frame.header_len(frame.Link.GAME_S2C)


def transform_of(main: int, sub: int) -> str:
    """`rol8xor` for the bootstrap frame, else the tile the opcode selects."""
    return "rol8xor" if (main, sub) == CHANNELINFO else f"tile{tiles.algo_id(sub)}"


def plaintext_of(main: int, sub: int, body: bytes) -> bytes | None:
    """None when the frame is generated from inputs rather than decrypted."""
    if (main, sub) == CHANNELINFO:
        return None
    return tiles.decrypt_body(tiles.algo_id(sub), body)


DISPATCH = re.compile(r"conn=\d+ \((\d+),(\d+)\) -> (\d+) frame\(s\) (\d+)B "
                      r"state=(\w+)->(\w+)")

#: Note text is stored as a template.  Three things in it belong to the live
#: frame, not to the capture, so they become placeholders and the server fills
#: them from what it actually received -- a note that echoed the capture's
#: bytes would read as evidence while proving nothing.
NOTE_SUBS = (
    (re.compile(r"conn=\d+"), "conn={conn}"),
    (re.compile(r"body=\d+B"), "body={n}B"),
    (re.compile(r"consumed \d+B"), "consumed {n}B"),
    (re.compile(r"plain=[0-9a-fA-F]*(\.\.\.\(\+\d+B\))?"), "plain={plain}"),
)


#: `--completion <log>`: the full plaintext of the frames this corpus cut, keyed
#: by the frame's index among the session's S->C frames.  Empty until
#: `load_completion` fills it.
COMPLETION: dict[int, tuple[frame.Opcode, int, bytes]] = {}


def load_completion(path: Path) -> dict[int, tuple[frame.Opcode, int, bytes]]:
    """Read a replay log of the same session, keyed by S->C frame index.

    Indexing by position rather than by line number is what makes the two logs
    comparable at all: the replay's line numbers are its own, but the S->C
    sequence is the same sequence.
    """
    sess = logs.corpus_session(path)
    out: dict[int, tuple[frame.Opcode, int, bytes]] = {}
    for pk in logs.iter_packets(path):
        if not (sess.first <= pk.line_no <= sess.last):
            continue
        if pk.link != "game" or pk.conn != sess.conn or pk.hex is None:
            continue
        if pk.direction != "S->C":
            continue
        if pk.hex.truncated:
            raise SystemExit(f"{path}:{pk.line_no} is truncated too; a completion "
                             f"log must have been captured with the dump cap raised")
        fr = frame.parse(frame.Link.GAME_S2C, pk.hex.data, strict=False)
        algo = tiles.algo_id(fr.opcode.sub)
        out[len(out)] = (fr.opcode, pk.hex.full_size,
                         tiles.decrypt_body(algo, fr.body))
    return out


def fill_truncated(events: list[dict]) -> int:
    """Replace the cut bodies with the completion's full ones, after proving them.

    Three things have to agree before a body is accepted: the opcode, the
    declared wire size, and -- the strong one -- the ciphertext.  Tiles are
    block ciphers, so re-encrypting the completion's plaintext must reproduce
    the bytes this corpus *did* write down, byte for byte.  A completion log
    that is a different session, or a differently-encrypted one, fails here
    instead of silently rewriting the script.
    """
    filled = 0
    for e in events:
        if e["kind"] != "packet" or e["dir"] != "S->C" or not e["truncated"]:
            continue
        want = COMPLETION.get(e["index"])
        if want is None:
            raise SystemExit(f"no completion for S->C frame #{e['index']} "
                             f"({e['main']},{e['sub']}) at line {e['line']}")
        op, wire, plain = want
        if (op.main, op.sub) != (e["main"], e["sub"]) or wire != e["wire"]:
            raise SystemExit(f"S->C frame #{e['index']} is ({e['main']},{e['sub']}) "
                             f"wire={e['wire']} here but ({op.main},{op.sub}) "
                             f"wire={wire} in the completion log")
        body = tiles.encrypt_body(tiles.algo_id(e["sub"]), plain)
        if body[:len(e["body"])] != e["body"]:
            raise SystemExit(f"S->C frame #{e['index']} ({e['main']},{e['sub']}): the "
                             f"completion's plaintext does not re-encrypt to the "
                             f"ciphertext this corpus recorded")
        e["body"], e["truncated"], e["missing"] = body, False, 0
        filled += 1
    return filled


def corpus_events():
    """The session as `(sess, events)` in line order.

    Packets carry their decoded frame; everything else that is not a PACKET or
    DISPATCH line is a `note` -- the per-opcode prose the reference emits
    (`HANDSHAKE ... built success response`, `WARN UNHANDLED ...`).  Those are
    what makes the rewritten log diffable against the capture, so they are part
    of the script rather than something the rewrite invents.
    """
    sess = P.pick_session()
    packets = {}
    s2c_seen = 0
    for pk in logs.iter_packets(P.LOG):
        if not (sess["first"] <= pk.line_no <= sess["last"]):
            continue
        if pk.link != "game" or pk.conn != sess["conn"] or pk.hex is None:
            continue
        link = (frame.Link.GAME_C2S if pk.direction == "C->S"
                else frame.Link.GAME_S2C)
        fr = frame.parse(link, pk.hex.data, strict=False)
        index = None
        if link is frame.Link.GAME_S2C:
            index, s2c_seen = s2c_seen, s2c_seen + 1
        packets[pk.line_no] = {
            "line": pk.line_no,
            "kind": "packet",
            "dir": pk.direction,
            "op": (fr.opcode.main, fr.opcode.sub),
            "main": fr.opcode.main,
            "sub": fr.opcode.sub,
            "body": fr.body,
            "header": fr.header if link is frame.Link.GAME_S2C else None,
            "nonce": fr.header[12:15] if link is frame.Link.GAME_S2C else None,
            "wire": pk.hex.full_size,
            "index": index,
            "missing": pk.hex.declared or 0,
            "truncated": pk.hex.truncated,
            "ref_body": pk.body_len,
        }
    if COMPLETION:
        print(f"completions applied: {fill_truncated(list(packets.values()))}")

    events = []
    for ln in logs.stream(P.LOG):
        if not (sess["first"] <= ln.line_no <= sess["last"]):
            continue
        if ln.line_no in packets:
            events.append(packets[ln.line_no])
        elif ln.tag == "DISPATCH" and (m := DISPATCH.search(ln.msg)):
            events.append({"line": ln.line_no, "kind": "dispatch",
                           "request": (int(m.group(1)), int(m.group(2))),
                           "state": (m.group(5), m.group(6))})
        elif ln.tag != "PACKET":
            events.append({"line": ln.line_no, "kind": "note", "level": ln.level,
                           "tag": ln.tag, "msg": ln.msg})
    events.sort(key=lambda e: e["line"])
    return sess, events


def build_script(sess, events):
    """Split the stream into runs, one per C->S request, with its own notes.

    A run is everything between one C->S frame and the next, *including* the
    zero-length run when the request draws no reply -- `(1,36)` is sent five
    times and answers `(0,23)+(0,24)` each time, `(1,433)` three times with a
    different `(1,433)` each, and `(1,2126)` eleven times with silence.  Keeping
    the runs separate is what lets the server pick the n-th variant instead of
    confusing a repeated request for one long reply.
    """
    first_c2s = next((i for i, e in enumerate(events)
                      if e["kind"] == "packet" and e["dir"] == "C->S"), len(events))
    connect = [e for e in events[:first_c2s] if e["kind"] == "packet"]

    scripts: list[dict] = []
    by_op: dict[tuple[int, int], dict] = {}
    cur = None
    for e in events[first_c2s:]:
        if e["kind"] == "packet" and e["dir"] == "C->S":
            key = e["op"]
            cur = by_op.get(key)
            if cur is None:
                cur = {"request_main": key[0], "request_sub": key[1], "runs": []}
                by_op[key] = cur
                scripts.append(cur)
            cur["runs"].append({"line": e["line"], "replies": [], "notes": [],
                                "state": None})
        elif e["kind"] == "packet":
            if cur is not None:
                cur["runs"][-1]["replies"].append(e)
        elif e["kind"] == "dispatch":
            if cur is not None:
                cur["runs"][-1]["state"] = list(e["state"])
        elif cur is not None:
            msg = e["msg"]
            for pat, rep in NOTE_SUBS:
                msg = pat.sub(rep, msg)
            cur["runs"][-1]["notes"].append([e["level"], e["tag"], msg])
    return connect, scripts


def frame_doc(p: dict) -> dict:
    plain = plaintext_of(p["main"], p["sub"], p["body"])
    return {
        "main": p["main"],
        "sub": p["sub"],
        "transform": transform_of(p["main"], p["sub"]),
        "plain_hex": plain.hex() if plain is not None else None,
        "body_len": len(p["body"]),
        "wire_body_len": (len(p["body"]) + p["missing"]) if p["truncated"] else len(p["body"]),
        "nonce": p["nonce"].hex(),
        "truncated": p["truncated"],
        "missing_bytes": p["missing"],
    }


def check(packets) -> int:
    """Re-derive the two claims the script depends on, and fail loudly on either."""
    bad = 0
    s2c = [p for p in packets if p["dir"] == "S->C"]
    live = [p for p in s2c if not p["truncated"] and (p["main"], p["sub"]) != CHANNELINFO]
    print(f"-- checks over {len(packets)} frames ({len(s2c)} S->C) --")

    ok = 0
    for p in live:
        algo = tiles.algo_id(p["sub"])
        ok += tiles.encrypt_body(algo, tiles.decrypt_body(algo, p["body"])) == p["body"]
    print(f"  tile round-trip (decrypt->encrypt == wire): {ok}/{len(live)}")
    bad += ok != len(live)

    ok = 0
    for p in s2c:
        if p["truncated"]:
            continue
        h = p["header"]
        v = frame.header_tag(frame.body_digest(p["body"]))
        ok += h[7:11] == struct.pack("<I", v) and h[11] == v & 0xFF and h[15] == 0
    print(f"  header [7:11]==LE32(tag(crc32(body))), [11]==its low byte, [15]==0: "
          f"{ok}/{len(s2c) - sum(1 for p in s2c if p['truncated'])}")
    bad += ok != len(s2c) - sum(1 for p in s2c if p["truncated"])

    rebuilt = 0
    for p in live:
        op = frame.Opcode(p["main"], p["sub"], frame.OpcodeEncoding.U8_U16LE, True)
        algo = tiles.algo_id(p["sub"])
        wire = frame.build_s2c(op, tiles.encrypt_body(algo, plaintext_of(p["main"], p["sub"], p["body"])),
                               nonce=p["nonce"])
        rebuilt += wire == p["header"] + p["body"]
    print(f"  rebuild byte-identical (encrypt + derived header + stored nonce): "
          f"{rebuilt}/{len(live)}")
    bad += rebuilt != len(live)
    return bad


def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    completion = None
    if "--completion" in argv:
        i = argv.index("--completion")
        if i + 1 >= len(argv):
            raise SystemExit("--completion needs a log path")
        completion = Path(argv[i + 1])
        COMPLETION.update(load_completion(completion))
    sess, events = corpus_events()
    connect, scripts = build_script(sess, events)

    print(f"# conn={sess['conn']} game:{sess['port']} lines "
          f"{sess['first']}..{sess['last']}\n")

    print(f"pre-request S->C frames: {len(connect)}")
    for p in connect:
        print(f"  ({p['main']},{p['sub']}) body={len(p['body'])} "
              f"transform={transform_of(p['main'], p['sub'])} "
              f"nonce={p['nonce'].hex()}")

    print()
    check([e for e in events if e["kind"] == "packet"])

    n_rep = sum(len(r["replies"]) for s in scripts for r in s["runs"])
    print(f"\n{len(scripts)} distinct C->S opcodes, {n_rep} replies attributed")
    silent = [s for s in scripts if not any(r["replies"] for r in s["runs"])]
    print(f"silent: {len(silent)}  ->  "
          + ", ".join(f"(1,{s['request_sub']})" for s in silent))

    print("\n-- reply runs --")
    for s in scripts:
        states = {tuple(r["state"]) for r in s["runs"] if r["state"]}
        shape = "+".join(str(len(r["replies"])) for r in s["runs"])
        print(f"  (1,{s['request_sub']}) x{len(s['runs'])} run(s), sizes {shape}"
              + ("   state " + " / ".join(f"{a}->{b}" for a, b in states) if states else ""))
        for n in s["runs"][0]["notes"]:
            print(f"      note {n[0]:5} {n[1]:12} {n[2][:96]}")
        for r in s["runs"]:
            for p in r["replies"]:
                flag = f"   TRUNC +{p['missing']}B" if p["truncated"] else ""
                print(f"      ({p['main']},{p['sub']}) body={len(p['body']):<6}"
                      f" {transform_of(p['main'], p['sub']):<10}"
                      f" nonce={p['nonce'].hex()}{flag}")

    if as_json:
        doc = {
            "generated_by": "tools/extract_game_replies.py",
            "source": f"Logs/server-20260926.log, the game session with "
                      f"packetHexLog on (conn={sess['conn']}, port {sess['port']})"
                      + (f"; the four bodies its 4096B dump cap cut are completed "
                         f"from {completion.name}, a replay of the same session at "
                         f"the reference with packetHexMaxBytes raised" if completion
                         else ""),
            "note": ("Bodies are stored decrypted.  At send time the server must "
                     "re-encrypt with tiles.encrypt_body(sub % 14, plain), "
                     "recompute tag over the ciphertext and rebuild the 16B "
                     "header with the stored nonce.  (0,1) is generated from "
                     "inputs, not replayed -- see tools/probe_chaninfo_build.py."),
            "connect_frames": [frame_doc(p) for p in connect],
            "scripts": [{
                "request_main": s["request_main"],
                "request_sub": s["request_sub"],
                "runs": [{
                    "state": r["state"],
                    "notes": r["notes"],
                    "replies": [frame_doc(p) for p in r["replies"]],
                } for r in s["runs"]],
            } for s in scripts],
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(doc, indent=1), encoding="utf-8")
        print(f"\nwrote {OUT.relative_to(paths.REPO_ROOT)} ({OUT.stat().st_size}B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
