#!/usr/bin/env python3
"""Read the 0.4.4 server's log -- it is hashed, not compiled away.

The 0.4.4 build ships with the readable diagnostics gone: a session's log holds
one line per event and nothing else --

    2026-09-30 17:57:04.082 +08:00 WARN  EVENT      conn=2 event=DFA486E77ACE

-- where the 0.3.6 build printed the label itself (`UNHANDLED`, `STUN`, ...).
What looked like a wall turned out to be a cipher: `event=` is
`sha256(label)[:12].upper()` of the very literal the old build printed, and
NativeAOT keeps those literals in the image's UTF-16 string table (they are
still needed to compute the digest).  Hash every string in the exe and the
dictionary falls out, so the log decodes again -- at *event-kind* granularity
only.  Payload details (opcode, size, hex) are still not in it; the relay plus
`join_capture.py` covers those.

    python tools/ref044/decode_events044.py labels [--grep TEXT] [--all]
    python tools/ref044/decode_events044.py decode [LOG ...] [--json OUT] [--unknown]

With no LOG, the newest `server-*.log` under the active reference's `Logs/` is
used.  `--unknown` additionally lists digests that are not in the dictionary --
a composed label (not a bare literal) would land there.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from uslocalserver import paths  # noqa: E402

#: `event=<12 hex>` -- 48 bits of sha256, which is what the build prints.
DIGEST_LEN = 12

_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")
_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \S+ "
    r"(?P<level>INFO|WARN|ERROR|DEBUG|TRACE)\s+(?P<category>\S+)\s+(?P<rest>.*)$")
_FIELD = re.compile(r"([A-Za-z_]\w*)=(\S+)")
#: Labels are bare upper-case tokens: `UNHANDLED`, `TOWN-SELF-DATA`.
_LABEL_SHAPED = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$")


def event_digest(label: str) -> str:
    """The id the 0.4.4 log prints for `label`."""
    return hashlib.sha256(label.encode("utf-8")).hexdigest()[:DIGEST_LEN].upper()


def utf16_strings(blob: bytes, min_len: int = 3) -> set[str]:
    """Every printable ASCII run stored as UTF-16LE in `blob`."""
    return {m.group().decode("utf-16le") for m in _UTF16.finditer(blob)
            if len(m.group()) >= 2 * min_len}


def build_dictionary(exe: Path) -> dict[str, str]:
    """digest -> the literal it was computed from, over an exe's whole table.

    48 bits over ~18k strings collides with probability ~1e-6, so a collision
    keeps the first label rather than raising.
    """
    out: dict[str, str] = {}
    for text in utf16_strings(exe.read_bytes()):
        out.setdefault(event_digest(text), text)
    return out


def default_log() -> Path | None:
    """The newest `server-*.log` of the active reference tree, if any."""
    files = sorted(paths.ACTIVE.logs_dir.glob("server-*.log"),
                   key=lambda p: (p.stat().st_mtime, p.name))
    return files[-1] if files else None


@dataclass(frozen=True, slots=True)
class Event:
    ts: str                    # "2026-09-30 17:57:04.082"
    level: str
    category: str
    conn: int | None
    digest: str
    label: str | None = None

    @property
    def seconds(self) -> float:
        """Seconds within the day -- the clock the relay logs in too."""
        h, m, s = self.ts[11:].split(":")
        return int(h) * 3600 + int(m) * 60 + float(s)

    @property
    def date(self) -> str:
        return self.ts[:10]

    def named(self, dictionary: dict[str, str]) -> "Event":
        return replace(self, label=dictionary.get(self.digest))


def parse_line(line: str) -> Event | None:
    """One log line into an `Event`; None for anything else (blanks, notes)."""
    m = _LINE.match(line.strip())
    if m is None:
        return None
    fields = dict(_FIELD.findall(m.group("rest")))
    digest = fields.get("event")
    if digest is None:
        return None
    conn = int(fields["conn"]) if "conn" in fields else None
    return Event(m.group("ts"), m.group("level"), m.group("category"), conn,
                 digest.upper())


def read_events(path: Path) -> list[Event]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    return [e for e in (parse_line(line) for line in text.splitlines())
            if e is not None]


# -- CLI ---------------------------------------------------------------------

def _cmd_labels(args: argparse.Namespace) -> int:
    exe = Path(args.exe)
    if not exe.exists():
        print(f"exe not found: {exe}", file=sys.stderr)
        return 2
    dictionary = build_dictionary(exe)
    pattern = args.grep.lower() if args.grep else None
    rows: list[tuple[str, str]] = []
    for digest, label in dictionary.items():
        if pattern is not None:
            keep = pattern in label.lower()
        else:
            keep = args.all or bool(_LABEL_SHAPED.match(label))
        if keep:
            rows.append((label, digest))
    for label, digest in sorted(rows):
        print(f"{digest}  {label}")
    print(f"\n{len(rows)} of {len(dictionary)} string(s) in {exe.name}")
    return 0


def _cmd_decode(args: argparse.Namespace) -> int:
    dictionary = {}
    exe = Path(args.exe)
    if exe.exists():
        dictionary = build_dictionary(exe)
    else:
        print(f"warning: no exe at {exe}; digests will print raw", file=sys.stderr)

    targets: list[Path] = [Path(p) for p in args.logs]
    if not targets:
        newest = default_log()
        if newest is None:
            print(f"no server-*.log under {paths.ACTIVE.logs_dir}", file=sys.stderr)
            return 2
        targets = [newest]

    as_json: dict[str, dict[str, int]] = {}
    unknown = collections.Counter()
    for path in targets:
        events = [e.named(dictionary) for e in read_events(path)]
        counts = collections.Counter(e.label or f"?{e.digest}" for e in events)
        levels = collections.Counter(e.level for e in events)
        print(f"--- {path}  ({len(events)} event(s)) ---")
        print("   levels:", dict(levels))
        for name, n in counts.most_common():
            print(f"   {n:6d}  {name}")
        unknown.update(name for name in counts if name.startswith("?"))
        as_json[str(path)] = dict(counts)

    if unknown:
        print("\nunknown digest(s): " + ", ".join(f"{k[1:]}×{v}" for k, v in unknown.items()))
    elif not args.unknown:
        pass
    if args.json:
        Path(args.json).write_text(json.dumps(as_json, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
        print(f"\n[out] {args.json}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exe", default=str(paths.ACTIVE.exe),
                        help="server exe to harvest labels from")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_labels = sub.add_parser("labels", help="dump the digest -> label dictionary")
    p_labels.add_argument("--grep", default=None, help="substring filter (case-insensitive)")
    p_labels.add_argument("--all", action="store_true",
                          help="every string, not just label-shaped ones")
    p_labels.set_defaults(func=_cmd_labels)

    p_decode = sub.add_parser("decode", help="decode one or more server logs")
    p_decode.add_argument("logs", nargs="*")
    p_decode.add_argument("--json", default=None, help="also write counts here")
    p_decode.add_argument("--unknown", action="store_true",
                          help="list digests missing from the dictionary")
    p_decode.set_defaults(func=_cmd_decode)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
