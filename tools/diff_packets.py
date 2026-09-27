#!/usr/bin/env python3
"""Diff two server logs: opcode table, body sizes, response distribution.

PLAN.md calls this the first thing M1 needs and the most valuable tool in the
rewrite -- it turns "does the rewritten server behave like the real one" from
a feeling into a scripted comparison.

Both sides are logs in the format `uslocalserver.logs` parses.  S->C frames do
not carry their opcode in the log text, so it is decoded from the frame header
with `protocol.frame`, which also means a rewrite that gets a length field or
a trailer wrong shows up as `bad`, not as silence.

    python tools/diff_packets.py REF.log NEW.log      # exit 1 when they differ
    python tools/diff_packets.py LOG                  # just the digest
    python tools/diff_packets.py REF.log NEW.log --bodies --session game --json d.json

A log diffed against itself is the tool's own self-test: the diff must come
out empty.

`--session` is how two logs are made comparable.  One reference log holds many
sessions and `conn=` restarts from 1 on every server restart, so a whole-file
compare of a six-session capture against a one-session replay reports the five
sessions it did not replay.  `--session game` narrows each log to its last
hex-carrying game session -- the same rule `logs.corpus_session` uses -- and
repeating the flag unions the ranges, which for the capture is exactly its
channel session immediately followed by its game session.

`--bodies` adds the comparison everything above is blind to: the S->C bodies'
*content*, decrypted (the game link's 14 tiles) or inflated (the channel
link's zlib), matched up frame by frame within each opcode.  Without it a
rewrite that sends the right *number* of the wrong bytes -- a stale
timestamp, a channel number off by one, a tile chosen by the wrong rule --
diffs as `(identical)`, because sizes are all this tool otherwise sees.

Against the capture a correct replay differs in exactly two places, both
clock readings, and they are worth knowing by heart: CHANNELINFO's field 11
and CONNECT_ACK's date.  A third pair is waiting in `(1,4)` SELECTION-4 -- two
u24 counters that the reference moves with the session while a replay keeps
the capture's -- so `(1,4)` is the first body to suspect the day a real client
stalls after picking a character.  Anything else is a bug in the rewrite.

C->S is deliberately not compared: those bytes are the *client's*, the capture
already prints their plaintext, and a replay sends the capture's own frames.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs  # noqa: E402
from uslocalserver.protocol import channelinfo, frame, opcodes  # noqa: E402
from uslocalserver.protocol.crypto import tiles  # noqa: E402

RESP_N = re.compile(r"->\s*(\d+)\s+frame\(s\)")


def link_of(p: logs.PacketRecord) -> frame.Link:
    if p.link == "channel":
        return (frame.Link.CHANNEL_C2S if p.direction == "C->S"
                else frame.Link.CHANNEL_S2C)
    return frame.Link.GAME_C2S if p.direction == "C->S" else frame.Link.GAME_S2C


def label_of(link: frame.Link, op: frame.Opcode) -> str:
    """Channel opcodes get their own namespace -- `main` there is the
    unexplained 0x7c prefix and must never merge with game opcodes."""
    if link.namespace == "channel":
        return f"ch[{op.to_bytes().hex()}]"
    return f"({op.main},{op.sub})"


_ARROW_PAIR = re.compile(r"\s*->\s*\(\d+,\d+\)")


def request_opcode(msg: str) -> str | None:
    """The opcode a log line is about, or None.

    `conn=` anchoring alone is not enough.  DUNGEON-ENTER and DCOD-PORTAL-MOVE
    write a cell *transition* the same way they would write an opcode --
    `conn=2 (2,4) -> (0,1) named portal` -- and the cells that land on main 0
    or 1 slip past the `main in (0,1)` guard `gen_opcodes.py` uses.  What
    actually separates the two is the arrow: an opcode is never the source of
    a `(a,b) -> (c,d)` pair.
    """
    m = logs.OPCODE.search(msg)
    if m is None:
        return None
    if _ARROW_PAIR.match(msg, m.end()):
        return None
    main, sub = int(m.group(1)), int(m.group(2))
    return f"({main},{sub})" if main in (0, 1) else None


def display(key: str) -> str:
    """A digest key plus the registry's name for it, when it has one."""
    if key.startswith("ch["):
        rec = opcodes.channel_lookup(int(key[3:-1], 16))
    else:
        main, sub = (int(x) for x in key.strip("()").split(","))
        rec = opcodes.lookup(main, sub)
    return f"{key:>11} {rec.name if rec and rec.name else '':<22}"


@dataclass(frozen=True, slots=True)
class Body:
    """One S->C frame's content, in the shape the client reads it."""
    size: int                      # plaintext bytes recovered
    full_size: int                 # what the frame's length field claims
    digest: str                    # sha1[:16] of `plain`; equality without the bytes
    truncated: bool                # the logger's 4096B cap cut the dump
    opaque: bool                   # content could not be recovered at all
    plain: bytes = field(repr=False, default=b"")

    def same(self, other: "Body") -> bool:
        if self.opaque or other.opaque:
            return False
        return self.digest == other.digest

    def as_dict(self) -> dict:
        return {"size": self.size, "full_size": self.full_size, "sha1": self.digest,
                "truncated": self.truncated, "opaque": self.opaque}


def _is_zlib(body: bytes) -> bool:
    """The standard 2-byte zlib header check, not a guess at `78 9c`."""
    return len(body) >= 2 and body[0] == 0x78 and (body[0] << 8 | body[1]) % 31 == 0


def s2c_content(f: frame.Frame, *, truncated: bool) -> bytes | None:
    """The client-readable body, or None when the dump cannot yield it.

    Game bodies go through the tile their opcode selects -- except `(0,1)`,
    which goes out before the session ciphers exist and is `rol8(b ^ 0xb5, 2)`
    instead (`protocol.channelinfo`).  Channel bodies are plain or zlib.

    A dump cut by the logger's 4096B cap still yields everything it kept --
    ECB blocks are independent, so the prefix decrypts correctly.  Only a zlib
    stream can come back unreadable, since a truncated one does not inflate.
    """
    if f.link is frame.Link.GAME_S2C:
        if f.opcode.main == 0 and f.opcode.sub == 1:
            return channelinfo.decode(f.body)
        return tiles.decrypt_body(tiles.algo_id(f.opcode.sub), f.body)
    if _is_zlib(f.body):
        try:
            return zlib.decompress(f.body)
        except zlib.error:
            return None
    return f.body


@dataclass
class Stat:
    frames: int = 0
    directions: collections.Counter = field(default_factory=collections.Counter)
    body_sizes: collections.Counter = field(default_factory=collections.Counter)
    resp_refs: collections.Counter = field(default_factory=collections.Counter)

    def as_dict(self) -> dict:
        return {
            "frames": self.frames,
            "directions": dict(self.directions),
            "body_sizes": {str(k): v for k, v in sorted(self.body_sizes.items())},
            "resp_refs": dict(sorted(self.resp_refs.items())),
        }


@dataclass
class Digest:
    label: str
    lines: int = 0
    packets: int = 0
    stats: dict[str, Stat] = field(default_factory=dict)
    resp_refs: collections.Counter = field(default_factory=collections.Counter)
    resp_frames: collections.Counter = field(default_factory=collections.Counter)
    bad: collections.Counter = field(default_factory=collections.Counter)
    notes: collections.Counter = field(default_factory=collections.Counter)
    #: opcode label -> its S->C frames in wire order.  Only filled by
    #: `--bodies`; the pairing between two logs is by index within the key.
    bodies: dict[str, list[Body]] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "lines": self.lines,
            "packets": self.packets,
            "opcodes": {k: v.as_dict() for k, v in sorted(self.stats.items())},
            "resp_refs": dict(sorted(self.resp_refs.items())),
            "resp_frames": {str(k): v for k, v in sorted(self.resp_frames.items())},
            "bad": dict(self.bad),
            "notes": dict(self.notes),
            "bodies": {k: [b.as_dict() for b in v] for k, v in sorted(self.bodies.items())},
        }


def spans(path: Path, kinds: list[str]) -> list[tuple[int, int]] | None:
    """The line ranges `--session` selected, or None for the whole file."""
    if not kinds:
        return None
    out = []
    for kind in kinds:
        try:
            s = logs.corpus_session(path, kind)
        except LookupError as e:
            raise SystemExit(str(e))
        out.append((s.first, s.last))
    return out


def digest(path: str | Path, label: str | None = None,
           kinds: list[str] | None = None, *, bodies: bool = False) -> Digest:
    """Summarise one log.  `bodies` also recovers each S->C body's content."""
    path = Path(path)
    d = Digest(label=label or path.name)
    # Response refs are collected first and attached afterwards: a `-> (m,s)`
    # names an opcode that may never appear as a packet in this log, and it
    # must not invent a 0-frame row for it.
    by_request: dict[str, collections.Counter] = {}
    keep = spans(path, kinds or [])

    def want(line_no: int) -> bool:
        return keep is None or any(a <= line_no <= b for a, b in keep)

    for ln in logs.stream(path):
        if not want(ln.line_no):
            continue
        d.lines += 1
        m = RESP_N.search(ln.msg)
        if m:
            d.resp_frames[int(m.group(1))] += 1

        req = request_opcode(ln.msg)
        for main, sub in logs.response_opcodes(ln.msg):
            rk = f"({main},{sub})"
            d.resp_refs[rk] += 1
            if req:
                by_request.setdefault(req, collections.Counter())[rk] += 1

    for p in logs.iter_packets(path):
        if not want(p.line_no):
            continue
        link = link_of(p)
        if p.hex is None or p.hex.is_length:
            d.notes["no hex dump"] += 1
            continue
        try:
            f = frame.parse(link, p.hex.data, strict=False,
                            expect_size=p.hex.full_size if p.hex.truncated else None)
        except frame.ProtocolError as e:
            d.bad[f"{type(e).__name__}: {e}"[:70]] += 1
            continue
        for w in f.warnings:
            d.notes[w[:70]] += 1

        d.packets += 1
        st = d.stats.setdefault(label_of(link, f.opcode), Stat())
        st.frames += 1
        st.directions[p.direction] += 1
        # The declared size, not the bytes on hand.  A `hex=` dump cut at the
        # logger's 4096B cap keeps only 4080B of body, and the rewrite's
        # replacement for such a frame is currently exactly that long -- so
        # measuring what is visible reads as identical while the capture's own
        # `raw=4688` says the real frame was 592B bigger.  The length field is
        # the frame's claim about itself and it is what has to match.
        st.body_sizes[f.wire_size - f.header_len] += 1

        if bodies and p.direction == "S->C":
            plain = s2c_content(f, truncated=p.truncated)
            data = b"" if plain is None else plain
            d.bodies.setdefault(label_of(link, f.opcode), []).append(Body(
                size=len(data), full_size=f.wire_size - f.header_len,
                digest=hashlib.sha1(data).hexdigest()[:16],
                truncated=p.truncated, opaque=plain is None, plain=data))

    for req_label, refs in by_request.items():
        st = d.stats.get(req_label)
        if st is None:
            d.notes[f"response refs from {req_label}, which has no packet"] += sum(refs.values())
            continue
        st.resp_refs.update(refs)

    return d


def _cnt(c: collections.Counter) -> str:
    return " ".join(f"{k}x{v}" for k, v in sorted(c.items(), key=lambda kv: str(kv[0])))


def _delta(a: collections.Counter, b: collections.Counter, limit: int) -> str:
    """`-dropped +added key:old->new ...` for the keys whose counts differ."""
    parts = []
    for k in sorted(set(a) | set(b), key=str):
        av, bv = a.get(k), b.get(k)
        if av == bv:
            continue
        if av is None:
            parts.append(f"+{k}")
        elif bv is None:
            parts.append(f"-{k}")
        else:
            parts.append(f"{k}:{av}->{bv}")
    return " ".join(parts[:limit]) + (" ..." if len(parts) > limit else "")


def _diff_runs(x: bytes, y: bytes) -> list[tuple[int, int]]:
    """Half-open `[start, stop)` ranges where the two bodies disagree, adjacent
    offsets merged.  A length difference counts as disagreement."""
    n = max(len(x), len(y))
    out: list[tuple[int, int]] = []
    start: int | None = None
    for i in range(n):
        differ = i >= len(x) or i >= len(y) or x[i] != y[i]
        if differ and start is None:
            start = i
        elif not differ and start is not None:
            out.append((start, i))
            start = None
    if start is not None:
        out.append((start, n))
    return out


def _runs_str(runs: list[tuple[int, int]], limit: int = 6) -> str:
    parts = [f"0x{s:03x}" if e - s == 1 else f"0x{s:03x}..0x{e - 1:03x}" for s, e in runs]
    if len(parts) > limit:
        return ", ".join(parts[:limit]) + f", ... (+{len(parts) - limit} more)"
    return ", ".join(parts)


def _body_delta(x: Body, y: Body) -> str:
    """One line saying how two frames' bodies differ, byte-level."""
    size = (f"{x.full_size}B" if x.full_size == y.full_size
            else f"{x.full_size}B vs {y.full_size}B")
    if x.opaque or y.opaque:
        which = "both sides" if x.opaque and y.opaque else ("new" if y.opaque else "ref")
        return f"{size}: zlib stream does not inflate ({which})"
    if x.truncated or y.truncated:
        size += ", partial dump"
    runs = _diff_runs(x.plain, y.plain)
    if not runs:
        return f"{size}: equal through the dumped prefix"

    def at(p: bytes, i: int) -> str:
        return f"{p[i]:02x}" if i < len(p) else "--"

    first = runs[0]
    changed = sum(e - s for s, e in runs)
    return (f"{size}: {changed}B differ in {len(runs)} run(s) [{_runs_str(runs)}]; "
            f"first @0x{first[0]:x} {at(x.plain, first[0])}->{at(y.plain, first[0])}")


def diff_bodies(a: Digest, b: Digest, *, top: int = 4) -> list[str]:
    """The `--bodies` section: S->C content, frame by frame within an opcode.

    Frames are paired by their position within the opcode, which is the order
    both servers answered in.  A count difference is reported before the pairs
    it shifts, because that is what it is -- everything past the gap otherwise
    reads as a body difference.
    """
    out: list[str] = []
    for k in sorted(set(a.bodies) | set(b.bodies)):
        ea, eb = a.bodies.get(k, []), b.bodies.get(k, [])
        if len(ea) != len(eb):
            out.append(f"  ~ {display(k):<34} body count {len(ea)} -> {len(eb)}")
        n = min(len(ea), len(eb))
        differing = [i for i in range(n) if not ea[i].same(eb[i])]
        if not differing:
            continue
        out.append(f"  ~ {display(k):<34} {len(differing)}/{n} S->C bodies differ")
        for i in differing[:top]:
            out.append(f"      body[{i}] {_body_delta(ea[i], eb[i])}")
        if len(differing) > top:
            out.append(f"      ... {len(differing) - top} more")
    return out


def diff(a: Digest, b: Digest, *, top: int = 12) -> list[str]:
    out: list[str] = []

    # A side with no packet dumps (packetHexLog off, or the logger never got
    # that far) would otherwise read as "this server never sent that frame".
    for d in (a, b):
        if d.packets == 0 and d.lines:
            out.append(f"  ! {d.label} has no DEBUG PACKET dumps at all -- "
                       f"nothing below can be trusted as a behavioural difference")

    for k in sorted(set(a.stats) - set(b.stats)):
        out.append(f"  - {display(k):<34} only in {a.label}   x{a.stats[k].frames}")
    for k in sorted(set(b.stats) - set(a.stats)):
        out.append(f"  + {display(k):<34} only in {b.label}   x{b.stats[k].frames}")

    for k in sorted(set(a.stats) & set(b.stats)):
        sa, sb = a.stats[k], b.stats[k]
        if sa.frames != sb.frames:
            out.append(f"  ~ {display(k):<34} frames {sa.frames} -> {sb.frames}")
        if sa.body_sizes != sb.body_sizes:
            out.append(f"  ~ {display(k):<34} body sizes "
                       f"[{_cnt(sa.body_sizes)}] -> [{_cnt(sb.body_sizes)}]")
        if sa.resp_refs != sb.resp_refs:
            out.append(f"  ~ {display(k):<34} responses "
                       f"[{_cnt(sa.resp_refs)}] -> [{_cnt(sb.resp_refs)}]")

    for name, ca, cb in (("response refs", a.resp_refs, b.resp_refs),
                         ("response frames", a.resp_frames, b.resp_frames),
                         ("bad frames", a.bad, b.bad),
                         ("notes", a.notes, b.notes)):
        if ca != cb:
            out.append(f"  ~ {name:<34} {_delta(ca, cb, top)}")

    # Empty unless both sides were digested with `bodies=True`, so `--bodies`
    # is what turns this on -- `diff` itself stays flag-free.
    out += diff_bodies(a, b, top=top)
    return out


def render(d: Digest, *, top: int) -> str:
    rows = sorted(d.stats.items(), key=lambda kv: (-kv[1].frames, kv[0]))[:top]
    width = max((len(display(k)) for k, _ in rows), default=0)
    lines = [
        f"== {d.label} ==",
        f"lines {d.lines}   packets {d.packets}   opcodes {len(d.stats)}"
        f"   bad {sum(d.bad.values())}   notes {sum(d.notes.values())}",
    ]
    for k, st in rows:
        dirs = "+".join(sorted(st.directions))
        sizes = _cnt(st.body_sizes)
        resp = f"   -> {_cnt(st.resp_refs)}" if st.resp_refs else ""
        lines.append(f"  {display(k):<{width}}  {dirs:<9} x{st.frames:<5} "
                     f"body=[{sizes}]{resp}")
    if d.bad:
        lines.append("  -- unparsable --")
        lines += [f"     {n}x {why}" for why, n in d.bad.most_common()]
    if d.notes:
        lines.append("  -- notes --")
        lines += [f"     {n}x {why}" for why, n in d.notes.most_common(8)]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logs", nargs="+", help="one log to describe, two to diff")
    ap.add_argument("--json", metavar="OUT", help="write both digests as JSON here")
    ap.add_argument("--top", type=int, default=25,
                    help="rows per digest, and per-opcode body-diff lines "
                         "(default 25; 0 = all)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="only print the difference lines")
    ap.add_argument("--bodies", action="store_true",
                    help="also compare S->C body content, decrypted/inflated; "
                         "two clock fields are expected to differ (see above)")
    ap.add_argument("--session", action="append", default=[], metavar="KIND",
                    help="scope every log to its last hex-carrying session of "
                         "this kind (game|channel); repeatable, ranges are unioned")
    args = ap.parse_args()

    digests = [digest(p, kinds=args.session, bodies=args.bodies) for p in args.logs]
    top = args.top or 10 ** 9

    if not args.quiet:
        for d in digests:
            print(render(d, top=top))
            print()

    changes: list[str] = []
    if len(digests) == 2:
        changes = diff(digests[0], digests[1])
        print(f"== diff {digests[0].label} -> {digests[1].label} ==")
        print("\n".join(changes) if changes else "  (identical)")
    elif len(digests) > 2:
        print("more than two logs given; only the digest of each is shown")

    if args.json:
        payload = {"digests": [d.as_dict() for d in digests], "diff": changes}
        Path(args.json).write_text(json.dumps(payload, indent=1, ensure_ascii=False),
                                   encoding="utf-8")
        print(f"\nwrote {args.json}")

    return 1 if changes else 0


if __name__ == "__main__":
    raise SystemExit(main())
