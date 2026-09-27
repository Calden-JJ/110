#!/usr/bin/env python3
"""Recover the opcode -> algorithm table for C->S bodies.

Evidence chain so far:

* Keys are NOT per packet -- every match landed on the suite's own default blob
  offset (CAST-128@16, Skipjack@140, Twofish256@92, MISTY1@150, DFO-16B@278,
  DFO-Rij12@238, Custom8B@294).  So the blob is a fixed key table, one entry
  per algorithm.
* The algorithm IS fixed per opcode -- all 162 `(1,2126)` frames decrypt to
  coherent process telemetry under DFO-16B, both `(1,495)` frames give clean
  u32 pairs under Skipjack.

So there is a hardcoded `opcode -> algo` table shared by client and server (the
`AlgoId` the exe strings mention).  This recovers it from the log: for each
opcode that has an `UNHANDLED` plaintext oracle, find which algorithm
reproduces that plaintext for *every* sample.

`hdr[7:11]` is an unrelated per-frame 4-byte value (221 distinct across 221
frames), not a selector.
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


def suites():
    """(name, decrypt, default_key_offset, klen, block_size), plus Xor32 first."""
    yield ("XOR32", None, 0, 4, 0)
    for name, _enc, dec, ko, klen, bs in C.SELFTEST:
        yield (name.strip(), dec, ko, klen, bs)


def load_oracles() -> dict[tuple[int, int], set[bytes]]:
    out: dict[tuple[int, int], set[bytes]] = collections.defaultdict(set)
    for ln in logs.stream(LOG):
        f = logs.find_hex_field(ln.msg, "plain")
        if f is None or f.is_length or f.truncated:
            continue
        for a, b in logs.OPCODE.findall(ln.msg):
            out[(int(a), int(b))].add(f.data)
    return out


def frames_by_opcode() -> dict[tuple[int, int], list[bytes]]:
    out: dict[tuple[int, int], list[bytes]] = collections.defaultdict(list)
    for p in logs.iter_packets(LOG):
        if p.direction != "C->S" or p.hex is None or p.hex.truncated:
            continue
        b = p.hex.data[13:] if p.link == "game" else p.hex.data[11:]
        out[p.opcode or (0, 0)].append(b)
    return out


def main() -> int:
    oracles = load_oracles()
    fams = frames_by_opcode()

    print(f"{len(oracles)} opcodes have a plaintext oracle\n")
    print(f"{'opcode':>13} {'samples':>7} {'frames':>6}  algo")
    table = {}
    for op in sorted(oracles):
        plains = oracles[op]
        frm = fams.get(op, [])
        winners = []
        for name, dec, ko, klen, bs in suites():
            ok = 0
            for b in frm:
                if name == "XOR32":
                    pt = xor32(b)
                else:
                    k = BLOB[ko:ko + klen] if ko + klen <= len(BLOB) else None
                    if k is None:
                        continue
                    if bs and len(b) % bs:
                        continue
                    pt = C.ecb_decrypt(dec, b, k, bs)
                if pt in plains:
                    ok += 1
            if ok:
                winners.append((ok, name))
        winners.sort(reverse=True)
        table[op] = winners
        w = ", ".join(f"{n}x{c}" for c, n in winners) or "?"
        print(f"   ({op[0]:3d},{op[1]:5d}) {len(plains):7d} {len(frm):6d}  {w}")

    print("\n== uniqueness check ==")
    amb = {op: w for op, w in table.items() if len(w) > 1}
    print(f"   {len(table) - len(amb)} unambiguous, {len(amb)} with >1 algo matching")
    for op, w in sorted(amb.items()):
        print(f"   ({op[0]},{op[1]}) {w}")

    print("\n== is the algo a function of `sub`? ==")
    names = [n for n, *_ in suites()]
    by_algo = collections.defaultdict(list)
    for op, w in table.items():
        if w:
            by_algo[w[0][1]].append(op[1])
    for algo in names:
        subs = sorted(by_algo.get(algo, []))
        if subs:
            print(f"   {algo:<12} subs={subs}  mod12={[s % 12 for s in subs]}"
                  f"  mod14={[s % 14 for s in subs]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
