#!/usr/bin/env python3
"""Which cipher does each C->S frame use?  Derive the rule, don't guess it.

`UNHANDLED` lines carry the *plaintext* of a C->S body as a full `plain=` hex
dump.  That is a free known-plaintext oracle: 200+ frames have their plaintext
written down next to them.

An earlier attempt paired frame -> plaintext by line proximity and got
`NEITHER: 137 / DFO-16B: 5 / Xor32: 1`.  That is a **methodology artifact**:
`(1,2126)` occurs ~150 times with `body=400` and *different* plaintexts each
time (timestamps, process lists), so "nearest line wins" mis-pairs it.

Fix: never pair.  Build the set of candidate plaintexts keyed by
`(opcode, len)`, then ask of each frame "is my decryption a member of that
set?"  Membership is immune to ordering.

Outputs a verdict per frame plus a table of verdict x seq so the switch point
(if any) is visible.
"""
from __future__ import annotations

import collections
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import crypto as C  # noqa: E402

LOG = paths.LOGS_DIR / "server-20260926.log"
KEY16 = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()[278:294]
K32 = bytes.fromhex("06831f52")

OP = re.compile(r"conn=\d+\s+\((\d+),(\d+)\)")


def xor32(data: bytes) -> bytes:
    return bytes(c ^ K32[i & 3] for i, c in enumerate(data))


def link_of(msg: str) -> str | None:
    m = re.search(r"(C->S|S->C)\s+(game|channel)\b", msg)
    return m.group(2) if m else None


def body_of(frame: bytes, link: str) -> bytes:
    return frame[13:] if link == "game" else frame[11:]


def seq_of(frame: bytes) -> int | None:
    return int.from_bytes(frame[11:13], "little") if len(frame) >= 13 else None


def main() -> int:
    plains: dict[tuple[int, int], set[bytes]] = collections.defaultdict(set)
    frames: list[tuple[int, int, str, int, tuple[int, int], bytes]] = []
    n_plain_lines = 0

    for ln in logs.stream(LOG):
        f = logs.find_hex_field(ln.msg, "plain")
        m = OP.search(ln.msg)
        if f is not None and m is not None and not f.is_length and not f.truncated:
            plains[(int(m.group(1)), int(m.group(2)))].add(f.data)
            n_plain_lines += 1

    for p in logs.iter_packets(LOG):
        if p.direction != "C->S" or p.hex is None or p.hex.truncated:
            continue
        link = p.link
        frame = p.hex.data
        body = body_of(frame, link)
        frames.append((p.line_no, p.conn, link, seq_of(frame) or 0, p.opcode or (0, 0), body))

    print(f"{len(plains)} distinct (opcode,len) keys from {n_plain_lines} plain= dumps")
    print(f"{len(frames)} C->S frames with a complete hex dump\n")

    verdicts = []
    for lno, conn, link, seq, op, body in frames:
        cands = plains.get((op[0], op[1]), set()) | plains.get((op[0], len(body)), set())
        cands = {c for c in cands if len(c) == len(body)}
        pt16 = C.ecb_decrypt(C.dfo16_decrypt, body, KEY16, 16) if len(body) >= 16 else b""
        v = "no-cand"
        if cands:
            v = ("plain" if body in cands else
                 "xor32" if xor32(body) in cands else
                 "dfo16" if pt16 in cands else "NEITHER")
        verdicts.append((lno, conn, link, seq, op, len(body), v, len(cands)))

    print("== verdict x seq ==")
    grid: dict[tuple[str, int], int] = collections.Counter(
        (v, min(seq, 999)) for _, _, _, seq, _, _, v, _ in verdicts)
    for seq in sorted({s for _, _, _, s, _, _, _, _ in verdicts}):
        row = "  ".join(f"{v}={grid.get((v, min(seq, 999)), 0):3d}"
                        for v in ("plain", "xor32", "dfo16", "NEITHER", "no-cand"))
        print(f"   seq={seq:4d}  {row}")

    print("\n== totals ==")
    for v, n in collections.Counter(x[6] for x in verdicts).most_common():
        print(f"   {v:8s} {n:4d}")

    print("\n== per opcode ==")
    per: dict[tuple[int, int], collections.Counter] = collections.defaultdict(collections.Counter)
    for _, _, _, _, op, _, v, _ in verdicts:
        per[op][v] += 1
    for op in sorted(per, key=lambda o: -sum(per[o].values())):
        c = per[op]
        tot = sum(c.values())
        det = " ".join(f"{k}={v}" for k, v in c.most_common())
        print(f"   ({op[0]:3d},{op[1]:5d})  n={tot:4d}  {det}")

    print("\n== a NEITHER sample, in case the candidate set is the problem ==")
    shown = 0
    for lno, conn, link, seq, op, blen, v, ncand in verdicts:
        if v == "NEITHER" and shown < 6:
            print(f"   line {lno} conn={conn} {link} seq={seq} ({op[0]},{op[1]}) "
                  f"body={blen} cands={ncand}")
            shown += 1

    print("\n== frames with NO candidate plaintext at all ==")
    miss: dict[tuple[int, int], int] = collections.Counter(
        op for _, _, _, _, op, _, v, _ in verdicts if v == "no-cand")
    for op, n in miss.most_common(20):
        print(f"   ({op[0]:3d},{op[1]:5d})  {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
