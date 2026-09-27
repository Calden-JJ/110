#!/usr/bin/env python3
"""Pull the per-packet hex log out of a USLocalServer log file.

The server can log every packet it reads and writes when
`diagnostics.packetHexLog` is true.  Each line carries a direction, an
opcode, a length and a hex dump -- exactly what is needed to line the wire
bytes up against the decrypted bodies.

The exact line shape is not fixed, so fields are scraped by name rather than
by position: anything matching `key=value` is kept, plus the first long hex
run on the line.

Usage:
    python extract_packet_log.py <logfile>
    python extract_packet_log.py <logfile> --json out.json
    python extract_packet_log.py <logfile> --dir S->C --limit 20
    python extract_packet_log.py <logfile> --dump-dir captured_bodies
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) ([+-]\d\d:\d\d) (\w+)\s+(\S+)\s+(.*)$")
KV = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=(\S+)")
# the direction is a BARE token `C->S` / `S->C`, NOT a key=value.
# `state=Connected->Connected` must not match: the char right before `->`
# there is `d`, not C or S.
DIR = re.compile(r"\b([CS])->([CS])\b")
KIND = re.compile(r"\b(channel|game)\b")
OPCODE = re.compile(r"\((\d+),(\d+)\)")
HEXRUN = re.compile(r"\b([0-9a-fA-F]{16,})\b")
LEADHEX = re.compile(r"[0-9a-fA-F]*")
TRUNC = re.compile(r"\.\.\.\(\+(\d+)B\)")
HEX_CAP = 4096                      # packetHexMaxBytes: longer dumps get cut


def _hex(s: str) -> str:
    """Leading hex run only -- `key=\\S+` swallows whatever token follows the dump."""
    s = LEADHEX.match(s or "").group()
    return s[:len(s) - len(s) % 2]


def _len(v):
    """`body=400B` -> 400; `wire=43` -> 43."""
    if v is None:
        return None
    m = re.match(r"\d+", v)
    return int(m.group()) if m else None


def derived_opcode(direction: str, kind: str, b: bytes):
    """The log prints `(a,b)` only for C->S; S->C opcodes live in the header.

    game-s2c    : [0] u8 main, [1:3] u16LE sub   (verified 61/61)
    channel-s2c : [0:2] u16 BE                   (3/3)
    """
    if direction != "S->C" or not b:
        return None
    if kind == "game" and len(b) >= 3:
        return b[0], int.from_bytes(b[1:3], "little")
    if kind == "channel" and len(b) >= 2:
        return b[0], b[1]
    return None


def parse_line(msg: str, tag: str = "") -> dict | None:
    fields = {}
    for k, v in KV.findall(msg):
        fields.setdefault(k, v)

    d = DIR.search(msg)
    if not d:
        # `WARN UNHANDLED conn=2 (1,2126) body=400B has no handler plain=<hex>`
        # has no direction token -- it is an inbound packet the server could not
        # route, and its `plain=` is the only decrypted body we get for free.
        if tag != "UNHANDLED" and "has no handler" not in msg:
            return None
        direction = "C->S"
        source = "unhandled"
    else:
        direction = f"{d.group(1)}->{d.group(2)}"
        source = "packet"

    # c2s PACKET lines carry hex=<wire bytes>; UNHANDLED lines carry plain= only
    hexrun = _hex(fields.get("hex", ""))
    if not hexrun and source == "packet":
        # only PACKET lines have a bare hex run; on UNHANDLED it would pick up
        # the plaintext and silently mislabel it as wire bytes
        runs = HEXRUN.findall(msg)
        hexrun = _hex(max(runs, key=len)) if runs else ""

    plain = _hex(fields.get("plain", ""))

    op = OPCODE.search(msg)
    if op:
        fields.setdefault("main", op.group(1))
        fields.setdefault("sub", op.group(2))

    kind = KIND.search(msg)
    trunc = TRUNC.search(msg)
    # c2s logs `wire=` + `body=`; s2c logs `raw=` only.  Both are header+body.
    total = _len(fields.get("wire") or fields.get("raw"))

    if kind:
        kname = kind.group(1)
    elif source == "unhandled":
        kname = "channel" if fields.get("conn") == "1" else "game"
    else:
        kname = "?"
    if "main" not in fields and hexrun:
        der = derived_opcode(direction, kname, bytes.fromhex(hexrun))
        if der:
            fields["main"], fields["sub"] = str(der[0]), str(der[1])

    return {
        "source": source,
        "direction": direction,
        "kind": kname,
        "conn": fields.get("conn", "?"),
        "sent": bool(re.search(r"\bsent\b", msg)),
        "opcode": f"({fields['main']},{fields['sub']})" if "main" in fields else "?",
        "main": int(fields["main"]) if "main" in fields else None,
        "sub": int(fields["sub"]) if "sub" in fields else None,
        "total": total,                              # wire=/raw=: header + body
        "body_len": _len(fields.get("body")),
        "state": fields.get("state"),
        "hex": hexrun,
        "bytes": len(hexrun) // 2,                   # bytes actually in the dump
        "wire_capped": len(hexrun) // 2 >= HEX_CAP,  # dump hit packetHexMaxBytes
        "plain": plain,
        "plain_bytes": len(plain) // 2,
        "plain_truncated": int(trunc.group(1)) if trunc else 0,
        "raw": msg,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", type=Path)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--dir", dest="only_dir", default=None,
                    help="filter by direction, e.g. S->C")
    ap.add_argument("--kind", dest="only_kind", default=None,
                    choices=("channel", "game"),
                    help="filter by link, channel = port 7001, game = 10011+")
    ap.add_argument("--source", dest="only_source", default=None,
                    choices=("packet", "unhandled"),
                    help="packet = framed line with hex=, unhandled = plain= only")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--dump-dir", type=Path, default=None,
                    help="write each packet body as a .bin file here")
    args = ap.parse_args()

    if not args.log.exists():
        print(f"no such file: {args.log}", file=sys.stderr)
        return 2

    text = args.log.read_text(encoding="utf-8", errors="replace")
    records = []
    tag_counts: Counter = Counter()
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        _ts, _tz, _level, tag, msg = m.groups()
        tag_counts[tag] += 1
        rec = parse_line(msg, tag)
        if rec:
            records.append(rec)

    print(f"log      : {args.log}")
    print(f"lines    : {len(text.splitlines())}")
    print(f"packets  : {len(records)}")
    if not records:
        print("\nNo direction+hex lines found.  Top tags present:")
        for tag, n in tag_counts.most_common(25):
            print(f"   {n:8d}  {tag}")
        print("\nIf PACKET is absent the hex log did not turn on -- check that "
              "diagnostics.packetHexLog is true in the config the server "
              "actually loaded (the startup banner prints 'packet hex: on').")
        return 0

    dirs = Counter(r["direction"] for r in records)
    srcs = Counter(r["source"] for r in records)
    print(f"directions: {dict(dirs)}   sources: {dict(srcs)}")
    n_plain = sum(1 for r in records if r["plain"])
    print(f"decrypted : {n_plain} records carry plain= "
          f"({sum(r['plain_bytes'] for r in records):,} bytes of known plaintext)")

    by_op = defaultdict(Counter)
    for r in records:
        by_op[(r["source"], r["direction"])][r["opcode"]] += 1
    for (src, d), c in by_op.items():
        top = ", ".join(f"{op}x{n}" for op, n in c.most_common(8))
        print(f"  {src:9} {d}: {len(c)} opcodes -- {top}")

    shown = [r for r in records
             if (not args.only_dir or r["direction"] == args.only_dir)
             and (not args.only_kind or r["kind"] == args.only_kind)
             and (not args.only_source or r["source"] == args.only_source)]
    print(f"\nfirst {min(args.limit, len(shown))} packets:")
    print(f"  {'dir':6} {'kind':8} {'conn':5} {'opcode':11} {'src':10} {'sent':4} "
          f"{'total':>6} {'body':>5} {'wire':>5} {'plain':>6}")
    for r in shown[:args.limit]:
        wire = str(r["bytes"]) if r["bytes"] else "-"
        if r["wire_capped"]:
            wire += "*"                              # hit packetHexMaxBytes
        pl = str(r["plain_bytes"]) if r["plain_bytes"] else "-"
        if r["plain_truncated"]:
            pl += f"+{r['plain_truncated']}"
        preview = r["hex"] or r["plain"]
        print(f"  {r['direction']:6} {r['kind']:8} {r['conn']:5} {r['opcode']:11} "
              f"{r['source']:10} {'S' if r['sent'] else '.':4} "
              f"{str(r['total'] or '-'):>6} {str(r['body_len'] or '-'):>5} "
              f"{wire:>5} {pl:>6}  {preview[:36]}")

    if args.dump_dir:
        args.dump_dir.mkdir(parents=True, exist_ok=True)
        for i, r in enumerate(shown):
            safe = r["direction"].replace(">", "to").replace("-", "")
            op = r["opcode"].strip("()").replace(",", "_")
            tag = f"{i:04d}_{r['kind']}_{safe}_{op}"
            if r["hex"]:
                (args.dump_dir / f"{tag}.bin").write_bytes(bytes.fromhex(r["hex"]))
            # UNHANDLED lines carry no wire bytes, only the decrypted body
            if r["plain"]:
                (args.dump_dir / f"{tag}.plain.bin").write_bytes(
                    bytes.fromhex(r["plain"]))
        print(f"\nwrote bodies to {args.dump_dir} "
              f"(.bin = wire, .plain.bin = decrypted)")

    if args.json:
        args.json.write_text(json.dumps(records, indent=1), encoding="utf-8")
        print(f"wrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
