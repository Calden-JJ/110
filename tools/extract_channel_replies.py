#!/usr/bin/env python3
"""Pull the channel server's three S->C bodies out of a reference capture.

    (0,11)  32B  ->  (124,12) CONNECT_ACK   36B  plain
    (0,9)    0B  ->  (124,10) SCRIPT_ACK  1213B  zlib -> 1392B
    (0,1)    0B  ->  (124,3)  CHANNEL_ACK  351B  zlib ->  416B

The two compressed bodies are `zlib(AES-128-ECB(zero-pad-to-16(content),
key))`, keyed by `"yyyyMMdd" + "000008"` NUL-padded to 16 ASCII bytes -- the
token CONNECT_ACK carries in the clear, so the day needs no capture
(`uslocalserver.server.channel.seal`; solved 2026-09-29, see the module
docstring there).  Their *content* is config-derived and day-independent,
measured across 09-27..29.

What this tool extracts is therefore the **plaintext**: it unseals the two
bodies with the day the exchange itself names, proves the decryption by
re-sealing the plaintext and demanding the captured ciphertext back byte for
byte, and stores that plaintext plus the capture's day and ciphertext SHA-256
for the test to re-check.  The server seals the checked-in copy against the
live clock on every send, so there is no per-day re-sampling any more.

Content still depends on the **port block** the capture came from -- the
endpoints are inside CHANNEL_ACK -- so a copy captured elsewhere sends the
client stale endpoints and it drops silently after the third ACK.  Regenerate
when the channel config moves, and note that live takeovers do not read this
file at all: `tools/live_swap.py` probes the running reference.

Defaults to the newest `server-*.log`.  A channel exchange is three
request/reply pairs in order; a day's log holds one exchange per client launch
(and one block per session), and the newest exchange from `--block` is taken --
by default the block the rewrite itself binds.  `--block 0` takes the newest
exchange whatever the block, for reproducing a drifted one.

Bodies are stored, not whole frames, so the server has to go through
`frame.build()` to send them and a framing regression cannot hide.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import probe_channel_link  # noqa: E402
from uslocalserver import paths  # noqa: E402
from uslocalserver.server import channel  # noqa: E402

OUT = paths.DATA_DIR / "channel" / "replies.json"

NAMES = {0x7C0C: "CONNECT_ACK", 0x7C0A: "SCRIPT_ACK", 0x7C03: "CHANNEL_ACK"}

# `INFO CHANNEL conn=1 sent SCRIPT_ACK (plain=1384B) wire=1213B` -- the size the
# reference *reports*, which for the two zlib bodies is 8B / 4B below what
# inflating actually yields.  Log fidelity means echoing its number, not ours.
PLAIN_RE = re.compile(r"sent (\w+) \(plain=(\d+)B\) wire=(\d+)B")


START_RE = re.compile(r" START\s+bind=\S+ advertise=\S+ channel=(\d+)")

#: `(0,11)` C->S: the frame every channel exchange opens with.
CONNECT_RAW = 0x000B


def split_exchanges(frames) -> list[list]:
    """Cut the channel frames into exchanges, one per client launch.

    A cut is the CONNECT request, not every third pair: a session whose client
    died mid-handshake must not shift the grouping of the ones after it.
    """
    out, cur = [], []
    for f in frames:
        if f[3] == "C->S" and int.from_bytes(f[4][:2], "big") == CONNECT_RAW:
            if cur:
                out.append(cur)
            cur = [f]
        elif cur:
            cur.append(f)
    if cur:
        out.append(cur)
    return out


def start_lines(log: Path) -> list[tuple[int, int]]:
    """`(line number, channel port)` for every reference START line."""
    out = []
    with open(log, encoding="utf-8", errors="replace") as f:
        for i, ln in enumerate(f, 1):
            m = START_RE.search(ln)
            if m:
                out.append((i, int(m.group(1))))
    return out


def block_before(line: int, starts: list[tuple[int, int]]) -> int | None:
    prior = [port for ln, port in starts if ln < line]
    return prior[-1] if prior else None


def reference_plain_sizes(log: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    with open(log, encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = PLAIN_RE.search(ln)
            if m:
                out.setdefault(m.group(1), int(m.group(2)))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", type=Path, default=None,
                    help="reference log holding the exchange (default: newest server-*.log)")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--block", type=int, default=channel.CHANNEL_PORT,
                    help=f"take the newest exchange from this port block (default "
                         f"{channel.CHANNEL_PORT}, the block the rewrite binds); 0 = newest "
                         f"whatever the block, for a takeover that reproduces one")
    a = ap.parse_args()

    log = a.log or paths.server_logs()[-1]
    probe_channel_link.LOG = log
    plain = reference_plain_sizes(log)
    starts = start_lines(log)

    groups = split_exchanges(probe_channel_link.channel_frames())
    print(f"{log.name}: {len(groups)} exchange(s)")
    usable = []
    for g in groups:
        reqs_g = [f for f in g if f[3] == "C->S"]
        reps_g = [f for f in g if f[3] == "S->C"]
        block = block_before(g[0][0], starts)
        whole = len(reqs_g) == 3 and len(reps_g) == 3
        print(f"  line {g[0][0]:>6}  block {block if block else '?':>5}  "
              + ("complete" if whole else f"partial ({len(reqs_g)}+{len(reps_g)})"))
        if whole:
            usable.append((block, reqs_g, reps_g, g[0][0]))
    if not usable:
        print(f"no complete 3-pair exchange in {log.name}")
        return 1
    picked = [x for x in usable if x[0] == a.block] if a.block else []
    if a.block and not picked:
        blocks = sorted({x[0] for x in usable if x[0] is not None})
        print(f"no exchange from block {a.block} in {log.name}; blocks present: {blocks}\n"
              f"another block's body is not a fallback -- the client accepts all three "
              f"ACKs and resets silently.  Run the reference on block {a.block} first.")
        return 1
    if not picked:
        picked = usable
        print(f"taking block {picked[-1][0]} (--block 0): content is that block's")
    block, reqs, reps, first_line = picked[-1]
    print(f"selected block {block}, session from line {first_line}")
    reqs = [(f[4], f[5]) for f in reqs]
    reps = [(f[4], f[5]) for f in reps]

    # The exchange's own CONNECT_ACK names the day the reference was keyed on;
    # trust it over the log's filename, and check the two agree.
    assert int.from_bytes(reqs[0][0][:2], "big") == CONNECT_RAW, \
        "exchange must open with CONNECT_ACK"
    day = reps[0][1][4:12].decode("ascii")   # the reply's token
    log_day = re.sub(r"\D", "", log.stem)[:8]
    if log_day and log_day != day:
        print(f"!! log is {log_day}, CONNECT_ACK token says {day}; using {day}")

    frames = []
    for i, ((rhdr, rbody), (shdr, sbody)) in enumerate(zip(reqs, reps)):
        req_raw = int.from_bytes(rhdr[:2], "big")
        rep_raw = int.from_bytes(shdr[:2], "big")
        name = NAMES.get(rep_raw, "?")
        sealed = sbody[:1] == b"\x78"
        if sealed:
            # one complete zlib stream and nothing after it, then the day-keyed
            # blocks; the padding is left on the plaintext so `seal` round-trips.
            d = zlib.decompressobj()
            cipher = d.decompress(sbody)
            assert d.eof and not d.unused_data, "truncated or trailing bytes"
            assert not len(cipher) % 16, f"{name}: {len(cipher)}B is not a whole block count"
            content = channel.unseal(sbody, day)
            # the reference's own deflate does not reproduce byte-for-byte under
            # CPython's zlib, but the AES layer under it is deterministic: the
            # capture must come back exactly, or the key or the read is wrong.
            again = zlib.decompress(channel.seal(content, day))
            assert again == cipher, f"{name}: re-sealing does not reproduce the capture"
            sha = hashlib.sha256(cipher).hexdigest()
        else:
            content, sha = sbody, None
        reference_plain = plain.get(name, len(content))
        if sealed and not 0 <= len(content) - reference_plain < 16:
            print(f"!! {name}: reference plain={reference_plain}B does not match "
                  f"{len(content)}B of padded plaintext")
        frames.append({
            "request_raw": f"0x{req_raw:04x}",
            "request_main": req_raw >> 8,
            "request_sub": req_raw & 0xFF,
            "reply_main": rep_raw >> 8,
            "reply_sub": rep_raw & 0xFF,
            "name": name,
            "sealed": sealed,
            "wire_len": len(sbody),
            "plain_len": reference_plain,
            "plain_hex": content.hex(),
            "cipher_sha256": sha,
        })
        print(f"  {name:<12} (0,{req_raw & 0xFF}) -> ({rep_raw >> 8},{rep_raw & 0xFF})"
              f"  wire {len(sbody)}B"
              + (f"  zlib-> {len(content)}B plain  reference plain={reference_plain}B"
                 f"  sha={sha[:16]}" if sealed else "  plain"))

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({
        "generated_by": "tools/extract_channel_replies.py",
        "block": block,
        "day": day,
        "source": (f"Logs/{log.name}, block {block} exchange from line {first_line} "
                   f"({len(groups)} exchange(s) in the log)"),
        "note": ("`plain_hex` is the body before sealing: CONNECT_ACK's 36B body as "
                 "captured, and for the two `sealed` frames the zero-padded plaintext "
                 "of zlib(AES-128-ECB(plain, key)), key = ('yyyyMMdd' + '000008') "
                 "padded to 16 ASCII bytes -- the token CONNECT_ACK itself carries.  "
                 "The server re-keys the plaintext against the live clock on every "
                 "send (server.channel.seal), so this copy does not go stale with the "
                 "day; `day` and `cipher_sha256` are the capture it was proved "
                 "against.  The content is config-derived and the *game ports* in "
                 "CHANNEL_ACK are this block's, which is why a copy is per port "
                 "block: a body from another block sends stale ports and the client "
                 "resets silently after the third ACK.  The advertiseAddress is not "
                 "a constraint -- the server re-stamps it to its own "
                 "(server.channel.with_advertise); the captured value is the machine "
                 "the reference answered on that day.  Regenerate only when the "
                 "channel config moves; live takeovers probe the running reference "
                 "instead (tools/live_swap.py).  Wire framing is NOT stored -- "
                 "rebuild it with protocol.frame.build."),
        "frames": frames,
    }, indent=1), encoding="utf-8")
    print(f"\nwrote {a.out.relative_to(paths.REPO_ROOT)}  ({a.out.stat().st_size}B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
