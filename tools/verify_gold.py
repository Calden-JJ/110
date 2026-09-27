#!/usr/bin/env python3
"""Validate implemented ciphers against the log's gold (ct, plain) pairs.

The server logs `WARN ... plain=<hex>` for unhandled packets, which pairs the
ciphertext on the wire with the decrypted body.  Decrypted output may be
trailing-zero-trimmed relative to the body, so a match is "pt is a prefix of
the decrypted bytes and the remainder is zeros".

  python verify_gold.py            # all algos
  python verify_gold.py 0 8        # only these algo ids
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from dfocipher import xtea_decrypt, xor32_crypt  # noqa
import dfo_ciphers as DC  # noqa

BLOB = Path(r"E:\DFO_2.31.1.117\dfo-server\data\crypto\channelinfo_key_blob.bin")
LOG = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\Logs\server-20260926.log")
HDR = {"S->C": 16, "C->S": 13}
RE_CS = re.compile(r"DEBUG PACKET\s+conn=(\d+)\s+([SC])->([SC]) game \((\d+),(\d+)\)"
                   r" wire=(\d+) body=(\d+) state=\S+ hex=([0-9a-f]+)")
RE_SC = re.compile(r"DEBUG PACKET\s+conn=(\d+)\s+([SC])->([SC]) game raw=(\d+) sent hex=([0-9a-f]+)")

# algo id -> (name, key slice in blob, block size, decrypt(ct, key) -> pt)
def _xt(key_off, io_be):
    return lambda ct, k: b"".join(
        xtea_decrypt(ct[i:i + 8], k, io_be) for i in range(0, len(ct) - len(ct) % 8, 8))


def _ecb(fn, bs):
    return lambda ct, k: DC.ecb_decrypt(fn, ct, k, bs)


# algo id -> list of candidate decryptors; candidates beyond the first are
# alternates probed for comparison (e.g. MISTY1 stock RFC vs the DFO variant).
CIPHERS = {
    0: [("XTEA-BE", (0, 16), 8, _xt(0, True))],
    1: [("CAST-128", (16, 16), 8, _ecb(DC.cast128_decrypt, 8))],
    2: [("RC6-480-DFO", (32, 60), 16, _ecb(DC.rc6_dfo_decrypt, 16)),
        ("stock", (32, 60), 16, _ecb(DC.rc6_decrypt, 16))],
    3: [("Twofish256", (92, 32), 16, _ecb(DC.twofish_decrypt, 16))],
    4: [("AES-128", (124, 16), 16, _ecb(DC.aes128_decrypt, 16))],
    5: [("Skipjack", (140, 10), 8, _ecb(DC.skipjack_decrypt, 8))],
    6: [("MISTY1-DFO", (150, 16), 8, _ecb(DC.misty1_dfo_decrypt, 8)),
        ("stock", (150, 16), 8, _ecb(DC.misty1_decrypt, 8))],
    7: [("Blowfish-DFO", (166, 56), 8, _ecb(DC.blowfish_dfo_decrypt, 8)),
        ("stock", (166, 56), 8, _ecb(DC.blowfish_decrypt, 8))],
    8: [("XTEA-LE", (222, 16), 8, _xt(222, False))],
    9: [("DFO-Rijndael12", (238, 16), 16, _ecb(DC.dfo9_decrypt, 16))],
    10: [("XOR-32", (254, 8), 4, lambda ct, k: xor32_crypt(ct, k))],
    11: [("Khazad-like", (262, 16), 8, _ecb(DC.dfo11_decrypt, 8))],
    12: [("DFO-16B", (278, 16), 16, _ecb(DC.dfo16_decrypt, 16))],
    13: [("Custom 8B", (294, 40), 8, _ecb(DC.dfo13_decrypt, 8))],
}


def gold_pairs():
    lines = LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    last = None
    out = []
    for line in lines:
        m = RE_CS.search(line)
        if m:
            _c, d1, d2, _m, sub, _w, _b, hexs = m.groups()
            d = f"{d1}->{d2}"
            b = bytes.fromhex(hexs)
            last = (int(sub), b[HDR[d]:])
            continue
        m = RE_SC.search(line)
        if m:
            _c, d1, d2, _r, hexs = m.groups()
            d = f"{d1}->{d2}"
            b = bytes.fromhex(hexs)
            last = (int.from_bytes(b[1:3], "little"), b[HDR[d]:])
            continue
        # >=8 hex bytes: the CHANNELINFO line's `plain=511B` is a byte count
        m = re.search(r"plain=([0-9a-fA-F]{16,})(\.\.\.\(\+\d+B\))?", line)
        if m and last is not None:
            out.append((last[0], last[1], bytes.fromhex(m.group(1)),
                        m.group(2) is not None))
            last = None
    return out


def main(argv):
    want = {int(a, 0) for a in argv}
    blob = BLOB.read_bytes()
    stats = {}
    prim_failed = [False]
    for sub, ct, pt, trunc in gold_pairs():
        ai = sub % 14
        if want and ai not in want:
            continue
        cands = CIPHERS.get(ai)
        if cands is None:
            key = (ai, "-", "n/a")
            stats[key] = stats.get(key, 0) + 1
            continue
        verdicts = []
        first_bad = None
        for idx, (name, (off, ln), _bs, fn) in enumerate(cands):
            key = blob[off:off + ln]
            got = fn(ct, key)
            ok = got[:len(pt)] == pt and (trunc or not any(got[len(pt):]))
            # alternates (idx > 0) are deliberate comparisons, not regressions
            if idx == 0 and not ok:
                prim_failed[0] = True
            stats[(ai, name, "OK" if ok else "FAIL", idx == 0)] = \
                stats.get((ai, name, "OK" if ok else "FAIL", idx == 0), 0) + 1
            verdicts.append(("OK " if ok else "FAIL") + " " + name)
            if not ok and first_bad is None:
                first_bad = (name, got)
        print(f"  [{' | '.join(verdicts):24}] algo {ai:2d} sub={sub:5d} "
              f"ct={len(ct):4d}B pt={len(pt):4d}B{'(trunc)' if trunc else ''}")
        if first_bad is not None:
            print(f"        got  {first_bad[1].hex()[:120]}  ({first_bad[0]})")
            print(f"        want {pt.hex()[:120]}")
    print("\nsummary:")
    for (ai, name, st, prim), n in sorted(stats.items()):
        tag = "" if prim else "  (alt)"
        print(f"  algo {ai:2d}: {n:3d} {st:4} {name}{tag}")
    return 1 if prim_failed[0] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
