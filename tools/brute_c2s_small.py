#!/usr/bin/env python3
"""Why do the small C->S frames fail both known ciphers?

`derive_c2s_cipher.py` (set-membership, no line pairing) says the frames with
an `UNHANDLED` plaintext oracle split into:

    dfo16      5   (seq 10, 19, 39, 211, 215)
    xor32      1   (seq  2)
    NEITHER   ~10   all with body in {8, 16, 32, 48} at low seq on conn=2

so the rule "seq<=2 Xor32, seq>=3 DFO-16B" is *nearly* right but not complete.
This brute-forces every algorithm in the suite at every key window in
`channelinfo_key_blob.bin`, in both directions, against the oracle plaintext --
for the unresolved frames only.  If the answer is in the suite at all, it is
in this table.
"""
from __future__ import annotations

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import logs, paths  # noqa: E402
from uslocalserver.protocol import crypto as C  # noqa: E402

LOG = paths.LOGS_DIR / "server-20260926.log"
BLOB = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()
K32 = bytes.fromhex("06831f52")

# The frames derive_c2s_cipher.py could not resolve, keyed by line number.
WANTED = {
    6406: (1, 171, 48),
    6408: (1, 468, 16),
    6553: (1, 693, 8),
    6575: (1, 495, 8),
    6579: (1, 1499, 8),
    6581: (1, 1563, 32),
}


def xor32(data: bytes) -> bytes:
    return bytes(c ^ K32[i & 3] for i, c in enumerate(data))


def candidates() -> dict[tuple[int, int, int], set[bytes]]:
    out: dict[tuple[int, int, int], set[bytes]] = {}
    for ln in logs.stream(LOG):
        f = logs.find_hex_field(ln.msg, "plain")
        if f is None or f.is_length or f.truncated:
            continue
        ops = logs.OPCODE.findall(ln.msg)
        if not ops:
            continue
        for a, b in ops:                       # a line may cite several opcodes
            out.setdefault((int(a), int(b), len(f.data)), set()).add(f.data)
    return out


def main() -> int:
    cands = candidates()
    frames = {}
    for p in logs.iter_packets(LOG):
        if p.line_no in WANTED and p.hex is not None:
            frames[p.line_no] = p

    for lno in sorted(WANTED):
        main_, sub, blen = WANTED[lno]
        p = frames.get(lno)
        if p is None:
            print(f"line {lno}: frame not found")
            continue
        frame = p.hex.data
        body = frame[13:] if p.link == "game" else frame[11:]
        seq = int.from_bytes(frame[11:13], "little") if len(frame) >= 13 else -1
        keyset = cands.get((main_, sub, blen), set())
        print(f"\n=== line {lno}  conn={p.conn} ({main_},{sub}) seq={seq} "
              f"body={len(body)}  oracle_plaintexts={len(keyset)}")
        for i, k in enumerate(sorted(keyset)):
            print(f"    pt[{i}] = {k.hex()}")

        hits = []
        for name, _enc, dec, _ko, klen, bs in C.SELFTEST:
            for o in range(0, len(BLOB) - klen + 1):
                k = BLOB[o:o + klen]
                try:
                    pt = C.ecb_decrypt(dec, body, k, bs)
                except Exception:
                    continue
                if pt in keyset:
                    hits.append(f"{name.strip()} blob[{o}:{o+klen}]")
        if body in keyset:
            hits.append("PLAINTEXT (no cipher)")
        if xor32(body) in keyset:
            hits.append("XOR32 06831f52")
        # a key window may also be a *repeating* unit shorter than klen
        for unit in (2, 4, 8, 16):
            for o in range(0, len(BLOB) - unit + 1):
                k = BLOB[o:o + unit]
                pt = bytes(c ^ k[i % unit] for i, c in enumerate(body))
                if pt in keyset:
                    hits.append(f"XOR-{unit} blob[{o}:{o+unit}]")
        print(f"    -> {hits if hits else 'NOTHING in the suite reproduces it'}")

        print(f"    body  = {body.hex()}")
        for i, k in enumerate(sorted(keyset)):
            print(f"    xor32 = {xor32(body).hex() if i == 0 else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
