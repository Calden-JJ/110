"""Rewrite the `channels` list of one `channelServers` entry in server.json.

    python tools/chan_cfg.py --server 0 --channels 1:10011,#ch.1 6:10012,#ch.6
    python tools/chan_cfg.py --show

Keeps the file's comments and formatting elsewhere untouched; only the lines
between `"channels": [` and `]` of the selected entry are regenerated.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CFG = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\server.json")

ENTRY_RE = re.compile(
    r'("serverId":\s*(?P<sid>\d+),[\s\S]*?"channels":\s*\[)'
    r'(?P<body>[\s\S]*?)'
    r'(\s*\])')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", type=int, help="serverId whose channel list to rewrite")
    ap.add_argument("--channels", help="comma list of no:port:name")
    ap.add_argument("--show", action="store_true")
    args = ap.parse_args()

    text = CFG.read_text(encoding="utf-8")
    if args.show or args.server is None:
        for m in ENTRY_RE.finditer(text):
            print(f"serverId {m.group('sid')}: {m.group('body').strip()}")
        return 0

    lines = []
    for spec in args.channels.split(","):
        no, port, name = spec.split(":")
        lines.append(f'        {{ "channelNo": {int(no)}, "gamePort": {int(port)}, '
                     f'"wireName": "{name}" }}')
    body = "\n" + ",\n".join(lines) + "\n      "

    def sub(m: re.Match) -> str:
        if int(m.group("sid")) != args.server:
            return m.group(0)
        return m.group(1) + body + m.group(4)

    new, n = ENTRY_RE.subn(sub, text)
    if n == 0:
        print("no channelServers entry matched", file=sys.stderr)
        return 1
    CFG.write_text(new, encoding="utf-8")
    print(f"rewrote serverId {args.server}: {len(lines)} channels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
