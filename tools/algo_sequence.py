#!/usr/bin/env python3
"""The C->S cipher is not fixed -- recover the selection sequence.

`brute_c2s_small.py` found that each unresolved C->S frame is reproduced by a
*different* algorithm at a *different* `channelinfo_key_blob.bin` offset:

    (1,171)  48B  Twofish256 blob[92:124]     (1,495)  8B  Skipjack    blob[140:150]
    (1,468)  16B  MISTY1-DFO blob[150:166]    (1,1499) 8B  CAST-128   blob[16:32]
                                              (1,1563) 32B DFO-Rij12  blob[238:254]

Meanwhile `(1,2126)`/`(1,782)`/`(1,390)`/`(1,1566)`/`(1,250)` are all DFO-16B
at blob[278:294], and `(1,1592)` at seq 2 is Xor32.

So the cipher varies per packet.  This walks every oracle-covered C->S frame in
log order and prints which (algo, offset) reproduces it, so the *rule* is
visible as a sequence rather than inferred from scattered samples.
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
BLOB = (paths.CRYPTO_TABLES / "channelinfo_key_blob.bin").read_bytes()
K32 = bytes.fromhex("06831f52")


def xor32(d: bytes) -> bytes:
    return bytes(c ^ K32[i & 3] for i, c in enumerate(d))


def load_oracles() -> dict[tuple[int, int, int], set[bytes]]:
    out: dict[tuple[int, int, int], set[bytes]] = collections.defaultdict(set)
    for ln in logs.stream(LOG):
        f = logs.find_hex_field(ln.msg, "plain")
        if f is None or f.is_length or f.truncated:
            continue
        for a, b in logs.OPCODE.findall(ln.msg):
            out[(int(a), int(b), len(f.data))].add(f.data)
    return out


def main() -> int:
    oracles = load_oracles()
    rows = []
    for p in logs.iter_packets(LOG):
        if p.direction != "C->S" or p.hex is None or p.hex.truncated:
            continue
        frame = p.hex.data
        body = frame[13:] if p.link == "game" else frame[11:]
        seq = int.from_bytes(frame[11:13], "little") if len(frame) >= 13 else -1
        keyset = oracles.get((p.opcode or (0, 0)) + (len(body),), set())
        if not keyset:
            continue
        hit = "-"
        off = -1
        if body in keyset:
            hit, off = "PLAIN", 0
        elif xor32(body) in keyset:
            hit, off = "XOR32", 0
        else:
            for name, _e, dec, _ko, klen, bs in C.SELFTEST:
                if len(body) % bs:
                    continue
                for o in range(0, len(BLOB) - klen + 1):
                    if C.ecb_decrypt(dec, body, BLOB[o:o + klen], bs) in keyset:
                        hit, off = name.strip(), o
                        break
                if hit != "-":
                    break
        rows.append((p.line_no, p.conn, p.link, seq, p.opcode, len(body), hit, off))

    print(f"{len(rows)} oracle-covered C->S frames, log order\n")
    print(f"{'line':>6} {'conn':>4} {'link':>7} {'seq':>5} {'opcode':>12} {'len':>4}  algo            blob_off")
    for lno, conn, link, seq, op, blen, hit, off in rows:
        opc = f"({op[0]},{op[1]})" if op else "?"
        print(f"{lno:6d} {conn:4d} {link:>7} {seq:5d} {opc:>12} {blen:4d}  {hit:<15} {off if off >= 0 else '-'}")

    print("\n== by algo ==")
    for k, n in collections.Counter(r[6] for r in rows).most_common():
        offs = sorted({r[7] for r in rows if r[6] == k})
        print(f"   {k:<16} {n:3d}   offsets={offs}")

    print("\n== candidate record layout of channelinfo_key_blob.bin ==")
    print(f"   blob is {len(BLOB)}B; offsets seen so far map to key material:")
    for name, _e, _d, ko, klen, bs in C.SELFTEST:
        print(f"   {name.strip():<12} klen={klen:3d} block={bs:3d}  (suite default offset {ko})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
