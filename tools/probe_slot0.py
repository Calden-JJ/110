#!/usr/bin/env python3
"""Last sweep on the AlgoId-0 probe frame `(1,1302)`.

Everything else is pinned:

* 14 key tiles tile `channelinfo_key_blob.bin` exactly; slot N uses tile N
  (10/14 confirmed against oracle plaintexts, including slot 10 whose tile tail
  is byte-identical to the independently-proven XOR32 key).
* Key-size constraints leave slots 0 and 8 to {blowfish, misty1} -- rc6 needs
  60B and neither tile is bigger than 16B, and every other function is already
  placed.

But no function reproduces `(1,1302)`'s logged plaintext in plain ECB, which is
how every *other* slot works.  So either slot 0 is not ECB, or its key is not a
tile, or the pairing is wrong.

`(1,1302)` is the only slot-0 opcode with a `plain=` oracle (line 6905, its
PACKET dump is line 6904 -- adjacent, so the pairing is certain).  This tries
every mode and direction before concluding.
"""
from __future__ import annotations

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import paths  # noqa: E402
from uslocalserver.protocol import crypto as C  # noqa: E402

B = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()

BODY = bytes.fromhex("a63e03e6afabe22b41b658d12b0c53978fe3111e212bda7a94c6b7441a8ee699")
PLAIN = bytes.fromhex("3e16fe0ccd0cdc0c93fa0000859f0000ca002f01ca00ca000000000000000000")

FNS = [(n[:-8], getattr(C, n)) for n in dir(C)
       if n.endswith("_encrypt") and n != "ecb_encrypt"]
KEYLENS = (8, 10, 16, 24, 32, 40, 56, 60)


def blocks(data: bytes, bs: int):
    return [data[i:i + bs] for i in range(0, len(data) - len(data) % bs, bs)]


def cbc_dec(dec, data: bytes, key: bytes, bs: int, iv: bytes) -> bytes:
    out, prev = b"", iv
    for blk in blocks(data, bs):
        d = dec(blk, key)
        out += bytes(a ^ b for a, b in zip(d, prev))
        prev = blk
    return out + data[len(out):]


def main() -> int:
    print(f"slot 0 probe: body={len(BODY)}B plain={len(PLAIN)}B")
    print(f"body  {BODY.hex()}\nplain {PLAIN.hex()}\n")

    found = []

    # 1. ECB / raw, both directions, every function x every key window x both
    #    block sizes, including sub-ranges of the body.
    spans = [(0, 16), (16, 32), (0, 32)]
    for name, enc in FNS:
        dec = getattr(C, name + "_decrypt")
        for klen in KEYLENS:
            for o in range(0, len(B) - klen + 1):
                k = B[o:o + klen]
                for bs in (8, 16):
                    for a, b in spans:
                        if (b - a) % bs:
                            continue
                        seg, want = BODY[a:b], PLAIN[a:b]
                        try:
                            if dec(seg, k) == want:
                                found.append(f"ECB-dec {name} blob[{o}:{o+klen}] bs={bs} span[{a}:{b}]")
                            if enc(want, k) == seg:
                                found.append(f"ECB-enc {name} blob[{o}:{o+klen}] bs={bs} span[{a}:{b}]")
                        except Exception:
                            pass

    # 2. CBC with plausible IVs (zero, the frame nonce, first plaintext block)
    ivs = {"zero": bytes(16), "nonce": bytes.fromhex("da650839d200a63e03e6afabe22b41b6"),
           "plain0": PLAIN[:16], "body0": BODY[:16]}
    for name, _e in FNS:
        dec = getattr(C, name + "_decrypt")
        for klen in KEYLENS:
            for o in range(0, len(B) - klen + 1):
                k = B[o:o + klen]
                for bs in (8, 16):
                    for ivn, iv in ivs.items():
                        try:
                            if cbc_dec(dec, BODY, k, bs, iv[:bs]) == PLAIN:
                                found.append(f"CBC-dec {name} blob[{o}:{o+klen}] bs={bs} iv={ivn}")
                        except Exception:
                            pass

    # 3. plain XOR with any 4/8-byte repeating key window
    for unit in (4, 8, 16):
        for o in range(0, len(B) - unit + 1):
            k = B[o:o + unit]
            if bytes(c ^ k[i % unit] for i, c in enumerate(BODY)) == PLAIN:
                found.append(f"XOR-{unit} blob[{o}:{o+unit}]")

    if found:
        for f in sorted(set(found)):
            print("  HIT", f)
    else:
        print("  NOTHING -- no mode, direction, function or key window reproduces it")

    print("\n== for reference, what the neighbours look like ==")
    print("  slot  2 = rc6_dfo    @ blob[32:92]   (confirmed on (1,1360))")
    print("  slot  7 = blowfish_dfo @ blob[166:222] (E(0^8) fingerprint)")
    print("  slot 10 = xor32      @ blob[258:262] (== 06831f52)")
    print(f"  blob[0:16] = {B[0:16].hex()}")
    print(f"  blob[222:238] = {B[222:238].hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
