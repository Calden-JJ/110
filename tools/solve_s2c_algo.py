#!/usr/bin/env python3
"""Test `AlgoId = sub % 14` on S->C, and use it to crack tiles 0 and 8.

The C->S rule was proven on the `plain=` oracle.  S->C has no oracle, but it
does not need one: a *wrong* decryption of a binary DTO is uniform noise,
while a right one leaves runs of 0x00 and repeated 4-byte fields.  Two
independent hand-checks already agree with the rule:

    (0,53)  16B  53 % 14 = 11  -> dfo11   01f47801000100000000000000000000
    (0,13)   8B  13 % 14 = 13  -> dfo13   2d08000000000000
    (1,433)  8B 433 % 14 = 13  -> dfo13   0100000000000000

So for every S->C game frame this decrypts with the *predicted* tile and
scores the result, then does the same with all 14 tiles to check the
prediction actually wins -- a rule that predicts the wrong tile would show up
as a predicted score near the random floor while some other tile scores high.

Tiles 0 and 8 have no oracle at all (they are the two unresolved AlgoId
slots); the S->C frames that land on them are the only lever on those two, so
their scores are printed per tile with the best candidate named.

Since this was first written both of those got resolved (0 = XTEA-BE,
8 = XTEA-LE -- see `crypto.SELFTEST`), so all 14 tiles now decrypt.  What is
left is `(0,1)` CHANNELINFO, whose 511-byte body defeats every tile here, and
`(0,21)`, which is reported as a *tie* rather than a mismatch: blowfish's
output for it is not noise (`b4010000` is 436 = len(body) - 4, followed by a
monotone u16 id list) but the score cannot see that.
"""
from __future__ import annotations

import collections
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402
from uslocalserver.protocol.crypto import tiles as T  # noqa: E402

LOG = paths.LOGS_DIR / "server-20260926.log"
K32 = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()[258:262]

TILES = [(name, span, bs) for name, span, bs, _, _ in T.TILES]


def decrypt(tile: int, data: bytes) -> bytes | None:
    # `tiles.decrypt_body` passes a trailing partial block through, which is
    # what the server does -- but it means a tile whose block size does *not*
    # divide the body still returns output, with real plaintext in the tail
    # inflating its score.  As a candidate it is disqualified outright.
    name, _, bs = TILES[tile]
    if not data or bs != 4 and len(data) % bs:
        return None
    return T.decrypt_body(tile, data)


def score(d: bytes) -> float:
    """Layout score: zero bytes plus repeated 4-byte words, per byte."""
    if len(d) < 4:
        return 0.0
    zeros = d.count(0)
    words = [d[i:i + 4] for i in range(0, len(d) - 3, 4)]
    dup = len(words) - len(set(words))
    return (zeros + 4 * dup) / len(d)


def s2c_frames():
    for pk in logs.iter_packets(LOG):
        if pk.direction != "S->C" or pk.link != "game" or pk.hex is None:
            continue
        try:
            f = frame.parse(frame.Link.GAME_S2C, pk.hex.data, strict=False,
                            expect_size=pk.hex.full_size if pk.hex.truncated else None)
        except frame.ProtocolError:
            continue
        if f.body:
            yield pk.line_no, f.opcode, f.body


def main() -> int:
    print(f"Xor32 key = {K32.hex()}   (blob[258:262])\n")
    print(f"{'line':>5} {'opcode':>10} {'len':>5} {'algo':>7} "
          f"{'pred':>6} {'best':>6} best_tile  verdict")

    ok = bad = 0
    misses = []
    for line, op, body in s2c_frames():
        tile = op.sub % 14
        pred = decrypt(tile, body)
        p = score(pred) if pred is not None else -1.0

        best_t, best_s = None, -2.0
        for t in range(14):
            d = decrypt(t, body)
            if d is None:
                continue
            s = score(d)
            if s > best_s:
                best_t, best_s = t, s

        # `score` only credits zeros and repeated words, so a plaintext that
        # is neither (a sorted id list, say) ties with the noise.  A tie is
        # not evidence against the rule and is reported as such.
        agree = best_t == tile or abs(best_s - p) < 1e-9
        ok += agree
        if not agree:
            bad += 1
            misses.append((line, op, body))
        name = TILES[tile][0]
        verdict = "ok" if agree else "MISMATCH"
        if agree and best_t != tile:
            verdict = f"tie(t{best_t})"
        print(f"{line:>5} {str(op):>10} {len(body):>5} {str(name):>7} "
              f"{p:>6.3f} {best_s:>6.3f} {best_t:>9}  {verdict}")

    print(f"\nprediction ranked best on {ok}/{ok + bad} frames")

    if misses:
        print("\n== mismatches, with the winning tile's output (tile 0/8 have "
              "no candidate, so they always 'lose') ==")
        for line, op, body in misses[:8]:
            t = op.sub % 14
            print(f"  line {line} {op} {len(body)}B  predicted tile {t} ({TILES[t][0]})")
            for cand in (t, 0, 8):
                d = decrypt(cand, body)
                print(f"     tile {cand:>2} ({str(TILES[cand][0]):>12}): "
                      f"{d.hex() if d else '-'}")

    print("\n== tile 0 / 8 frames: what the (unknown) ciphers must produce ==")
    for t in (0, 8):
        rows = [(line, op, body) for line, op, body in s2c_frames() if op.sub % 14 == t]
        print(f"  AlgoId {t}: {len(rows)} frames")
        for line, op, body in rows[:6]:
            print(f"     line {line:>5} {str(op):>10} {len(body):>3}B {body.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
