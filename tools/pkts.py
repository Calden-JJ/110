#!/usr/bin/env python3
"""Parse all 'S->C/C->S game raw=' packet dumps from a server log into a table.

  python pkts.py [logfile] [--hex] [--dir S|C] [--sub N] [--conn N]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

LOG = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\Logs\server-20260926.log")

ALGOS = [
    ("XTEA-BE", 16, 8), ("CAST-128", 16, 8), ("RC6-480-DFO", 60, 16),
    ("Twofish-256", 32, 16), ("AES-128", 16, 16), ("Skipjack", 10, 8),
    ("MISTY1-DFO", 16, 8), ("Blowfish-DFO", 56, 8), ("XTEA-LE", 16, 8),
    ("DFO-Rijndael12", 16, 16), ("XOR-32", 8, 4), ("Khazad-like", 16, 8),
    ("DFO-Custom-16B", 16, 16), ("Custom-8B", 40, 8),
]

RE = re.compile(
    r"DEBUG PACKET\s+conn=(\d+)\s+([SC])->([SC]) game raw=(\d+) sent hex=([0-9a-f]+)")


def parse(hexs: str):
    b = bytes.fromhex(hexs)
    if len(b) < 16:
        return None
    main = b[0]
    sub = int.from_bytes(b[1:3], "little")
    total = int.from_bytes(b[3:7], "little")
    a = int.from_bytes(b[7:11], "little")
    c = int.from_bytes(b[11:15], "little")
    flag = b[15]
    body = b[16:total] if total <= len(b) else b[16:]
    return dict(main=main, sub=sub, total=total, a=a, c=c, flag=flag, body=body,
                tail=b[total:] if total < len(b) else b"")


def main():
    args = sys.argv[1:]
    path = LOG
    show_hex = "--hex" in args
    fdir = None
    fsub = None
    fconn = None
    skip = -1
    for i, a in enumerate(args):
        if i == skip:
            continue
        if a == "--dir":
            fdir = args[i + 1]
            skip = i + 1
        elif a == "--sub":
            fsub = int(args[i + 1], 0)
            skip = i + 1
        elif a == "--conn":
            fconn = int(args[i + 1])
            skip = i + 1
        elif not a.startswith("--"):
            path = Path(a)
    print(f"# {path.name}")
    n = 0
    for ln, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        m = RE.search(line)
        if not m:
            continue
        conn, d1, d2, raw, hexs = m.groups()
        if d1 == "C" and d2 == "C":
            continue
        d = f"{d1}->{d2}"
        if fdir and not d.startswith(fdir):
            continue
        if fconn is not None and int(conn) != fconn:
            continue
        p = parse(hexs)
        if not p:
            continue
        if fsub is not None and p["sub"] != fsub:
            continue
        n += 1
        ai = p["sub"] % 14
        name, klen, bs = ALGOS[ai]
        body = p["body"]
        b, r = divmod(len(body), bs)
        suff = ""
        if len(body) >= 2 * bs and body[-bs:] == body[-2 * bs:-bs]:
            k = 1
            while len(body) >= (k + 2) * bs and body[-(k + 2) * bs:-(k + 1) * bs] == body[-bs:]:
                k += 1
            suff = f" trail_rep={k + 1}x{bs}B({body[-bs:].hex()})"
        ts = ""
        if len(body) >= 8:
            ts = f" last8={body[-8:].hex()}"
        print(f"{ln:5d} c{conn} {d} main={p['main']:02x} sub={p['sub']:#06x}({p['sub']:5d}) "
              f"ai={ai:2d} {name:<15} bs={bs:2d} kb={klen:2d} total={p['total']:5d} "
              f"hdrA={p['a']:08x} hdrC={p['c']:08x} fl={p['flag']:02x} "
              f"body={len(body):4d} blk={b}+{r} {suff}{ts}"
              + (f"\n        {body.hex()}" if show_hex else ""))
    print(f"# {n} packets")


if __name__ == "__main__":
    main()
