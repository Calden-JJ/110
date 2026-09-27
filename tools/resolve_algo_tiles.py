#!/usr/bin/env python3
"""Resolve the two remaining AlgoId tiles and confirm the `sub % 14` rule.

`channelinfo_key_blob.bin` is a 334-byte table of 14 concatenated key entries,
laid out in AlgoId order -- verified 8/8 against oracle-covered frames, and
tile 10's tail `blob[258:262]` is byte-for-byte the XOR32 key proven
independently:

    [  0: 16] idx  0  ?             [238:254] idx  9  dfo9    (DFO-Rij12)
    [ 16: 32] idx  1  cast128       [254:262] idx 10  xor32
    [ 32: 92] idx  2  rc6           [262:278] idx 11  dfo11   (Khazad)
    [ 92:124] idx  3  twofish       [278:294] idx 12  dfo16   (DFO-16B)
    [124:140] idx  4  aes128        [294:334] idx 13  dfo13   (Custom 8B)
    [140:150] idx  5  skipjack
    [150:166] idx  6  misty1_dfo
    [166:222] idx  7  blowfish_dfo  <- proven: E(0^8) == (1,693) body
    [222:238] idx  8  ?

`E(0^8) == a1f06778a2857dfe` for `(1,693)` (whose `UNHANDLED` plaintext is all
zeros) matched **only** `blowfish_dfo` at offset 166, across every encrypt
function x every key window.

Two things this settles:

* which function sits on tiles 0 and 8 (they carry real M1 traffic: subs
  1554/140/1302 and 36/8/848/666/120 respectively);
* whether the rule is `sub % 14` or `sub % 28` -- `(1,35)` and `(1,693)` agree
  under 14 and disagree under 28, and `(1,693)` is already pinned.
"""
from __future__ import annotations

import collections
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import crypto as C  # noqa: E402

LOG = paths.LOGS_DIR / "server-20260926.log"
B = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()

DECS = sorted((n, getattr(C, n)) for n in dir(C)
              if n.endswith("_decrypt") and n != "ecb_decrypt")
KEYLENS = (10, 16, 32, 40, 56, 60)


def oracles() -> dict[int, set[bytes]]:
    out: dict[int, set[bytes]] = collections.defaultdict(set)
    for ln in logs.stream(LOG):
        f = logs.find_hex_field(ln.msg, "plain")
        if f is None or f.is_length or f.truncated:
            continue
        for a, b in logs.OPCODE.findall(ln.msg):
            if int(a) == 1:
                out[int(b)].add(f.data)
    return out


def frames() -> dict[int, list[bytes]]:
    out: dict[int, list[bytes]] = collections.defaultdict(list)
    for p in logs.iter_packets(LOG):
        if p.direction != "C->S" or p.hex is None or p.hex.truncated or not p.opcode:
            continue
        if p.opcode[0] == 1:
            out[p.opcode[1]].append(p.hex.data[13:])
    return out


def brute(dec_name: str, dec, bodies: list[bytes], plains: set[bytes]):
    """Every key window x every block size; return matches.

    Both block sizes must be tried for *every* body: 8 divides a 16- or 32-byte
    body too, so an early `break` silently skips the 16-byte-block ciphers.
    """
    hits = []
    for klen in KEYLENS:
        for o in range(0, len(B) - klen + 1):
            k = B[o:o + klen]
            for bs in (8, 16):
                ok = 0
                for b in bodies:
                    if len(b) % bs:
                        continue
                    try:
                        if C.ecb_decrypt(dec, b, k, bs) in plains:
                            ok += 1
                    except Exception:
                        pass
                if ok:
                    hits.append((ok, dec_name, o, klen, bs))
    return hits


def main() -> int:
    orc, fam = oracles(), frames()

    print("== resolve tiles 0, 2, 8 (and re-confirm 7) ==")
    for sub, idx in [(1302, 0), (140, 0), (1554, 0),
                     (1360, 2), (35, 7), (36, 8), (848, 8), (666, 8), (120, 8)]:
        bodies = fam.get(sub, [])
        plains = orc.get(sub, set())
        print(f"\n-- (1,{sub})  AlgoId {idx}   {len(bodies)} frames, {len(plains)} oracle samples")
        if not bodies:
            print("   no frames in this log")
            continue
        if not plains:
            print("   no oracle -- cannot resolve by plaintext match")
            continue
        allhits = []
        for name, dec in DECS:
            allhits += brute(name, dec, bodies, plains)
        if not allhits:
            print("   UNREACHABLE: no function x key window reproduces the oracle")
        for ok, name, o, klen, bs in sorted(set(allhits), reverse=True):
            print(f"   HIT {name:<20} blob[{o}:{o+klen}] bs={bs}  matched {ok}/{len(bodies)}")

    print("\n== mod 14 or mod 28?  (1,35) vs (1,693) ==")
    for sub in (35, 693):
        for b in fam.get(sub, [])[:2]:
            pt = C.ecb_decrypt(C.blowfish_dfo_decrypt, b, B[166:222], 8)
            print(f"   (1,{sub})  sub%14={sub%14}  sub%28={sub%28}  "
                  f"blowfish_dfo@166 -> {pt.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
