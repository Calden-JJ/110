"""Probe the 0.4.4 exe for its embedded data tables.

0.3.6 carried one contiguous ~81 MB plaintext UTF-8 region holding 69 JSON
documents, and the skill's extractor finds it with a "printable run >= 20000
bytes" regex.  The 0.4.4 image is 41.7 MB with a 19.9 MB .rdata, so either the
region moved, got compressed, or the data is no longer embedded at all (0.4.4
ships an 883 MB pvf-cache instead).

This prints what is actually there so the extractor can be re-derived instead
of guessed at.
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

NEW = Path(r"E:\DFO_2.31.1.117\DFO110-0.4.4\Server\USLocalServer.Server.exe")
OLD = Path(r"E:\DFO_2.31.1.117\dfo-server\_saveaudit\srv\USLocalServer.Server.exe")

NAME_PREFIX = "USLocalServer."
NAME_SUFFIX = ".json"
TEXT_REGION = re.compile(rb"[\x09\x0a\x0d\x20-\x7e\x80-\xff]{20000,}", re.DOTALL)


def sections(d: bytes):
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt = pe + 24
    optsize = struct.unpack_from("<H", d, pe + 20)[0]
    out = []
    for i in range(nsec):
        o = opt + optsize + i * 40
        name = d[o:o + 8].rstrip(b"\x00").decode("latin1")
        vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
        out.append((name, va, vs, ra, rs))
    return out


def find_utf16_names(raw: bytes) -> list[str]:
    needle = "json".encode("utf-16-le")
    names, seen, idx = [], set(), 0
    while True:
        i = raw.find(needle, idx)
        if i < 0:
            break
        idx = i + 1
        j = i + len(needle)
        chars = []
        while j >= 2:
            pair = raw[j - 2:j]
            if pair[1] == 0 and 0x20 <= pair[0] <= 0x7E:
                chars.append(pair.decode("utf-16-le"))
                j -= 2
            else:
                break
        name = "".join(reversed(chars))
        if name.startswith(NAME_PREFIX) and name.endswith(NAME_SUFFIX) and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def ascii_names(raw: bytes) -> list[str]:
    """0.4.4 might store the manifest as plain UTF-8 instead of UTF-16LE."""
    out, seen = [], set()
    for m in re.finditer(rb"USLocalServer\.(?:[A-Za-z0-9_.]+)\.json", raw):
        s = m.group().decode("ascii", "replace")
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def report(label: str, path: Path) -> None:
    raw = path.read_bytes()
    print(f"===== {label}  {path.name}  {len(raw):,} bytes =====")
    for name, va, vs, ra, rs in sections(raw):
        print(f"  {name:9} VA={va:#010x} VS={vs:#010x} RAW={ra:#010x} RS={rs:#010x}")

    u16 = find_utf16_names(raw)
    a8 = ascii_names(raw)
    print(f"  UTF-16LE manifest names: {len(u16)}")
    print(f"  UTF-8   manifest names: {len(a8)}")
    for n in (u16[:3] + u16[-2:]) if u16 else []:
        print(f"     u16 {n}")
    for n in (a8[:3] + a8[-2:]) if a8 else []:
        print(f"     u8  {n}")

    runs = sorted(((m.end() - m.start(), m.start(), m.end())
                   for m in TEXT_REGION.finditer(raw)), reverse=True)[:8]
    print(f"  printable runs >= 20000: {len(runs)} biggest first")
    for size, s, e in runs:
        head = raw[s:s + 60]
        print(f"     {size:>12,} @{s:#010x}  head={head[:48]!r}")

    # Does any top-level JSON document parse anywhere?
    hits = 0
    for m in re.finditer(rb'\{"source"', raw):
        hits += 1
        if hits <= 3:
            print(f"     '{{\"source\"' @{m.start():#010x} "
                  f"{raw[m.start():m.start() + 70]!r}")
    print(f"  occurrences of '{{\"source\"': {hits}")

    for probe in (b'"source"', b'"client"', b'"pvfSha256"', b'"exeSha256"',
                  b'_110us.json'):
        print(f"  count {probe!r}: {raw.count(probe)}")
    print()


report("0.4.4", NEW)
report("0.3.6 (backup copy)", OLD)
