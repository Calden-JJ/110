#!/usr/bin/env python3
"""Second-stage cipher analysis.

The frame formats are settled; this answers *which transform* is applied to
*which packet*:

  * block-reuse structure per link (is the body a block cipher or a keystream?)
  * the zero-block constant E(0) for each direction
  * whether the legacy 4-byte XOR 06 83 1f 52 still applies to some opcodes
  * candidate AES keys vs the observed E(0)

Usage:
    python analyze_cipher.py <log>                 # block structure report
    python analyze_cipher.py <log> --keys          # + AES candidate-key test
    python analyze_cipher.py <log> --pairs         # + known-plaintext XOR table
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from extract_packet_log import LINE, parse_line          # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LEGACY = bytes.fromhex("06831f52")
HDR = {("C->S", "game"): 13, ("S->C", "game"): 16,
       ("C->S", "channel"): 11, ("S->C", "channel"): 11}


def body_of(r: dict) -> bytes:
    if not r["hex"]:
        return b""
    h = HDR.get((r["direction"], r["kind"]))
    if h is None:
        return b""
    return bytes.fromhex(r["hex"])[h:]


def period(b: bytes, maxp: int = 64) -> tuple[int, int]:
    """Smallest p with b[i] == b[i % p].  Returns (period, coverage)."""
    n = len(b)
    for p in range(1, min(maxp, n) + 1):
        if all(b[i] == b[i % p] for i in range(n)):
            return p, n
    return 0, 0


def top_block(b: bytes, size: int) -> tuple[bytes, int, int]:
    """Most common `size`-aligned block: (block, occurrences, packets)."""
    blocks = [b[i:i + size] for i in range(0, len(b) - size + 1, size)]
    if not blocks:
        return b"", 0, 0
    c = Counter(blocks)
    blk, n = c.most_common(1)[0]
    return blk, n, len(blocks)


def load(log: Path):
    recs = []
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE.match(line)
        if not m:
            continue
        ts, _tz, _lvl, tag, msg = m.groups()
        r = parse_line(msg, tag)
        if r:
            r["ts"] = ts
            r["body"] = body_of(r)
            recs.append(r)
    return recs


def report_blocks(recs):
    for direction in ("C->S", "S->C"):
        for kind in ("game", "channel"):
            sel = [r for r in recs if r["direction"] == direction
                   and r["kind"] == kind and len(r["body"]) >= 16]
            if not sel:
                continue
            print(f"\n=== {direction} {kind}: {len(sel)} packets with a body >= 16B")
            for size in (16, 8):
                agg = Counter()
                pktcount = defaultdict(set)
                for r in sel:
                    b = r["body"]
                    if len(b) < size:
                        continue
                    for i in range(0, len(b) - size + 1, size):
                        blk = b[i:i + size]
                        agg[blk] += 1
                        pktcount[blk].add(r["opcode"])
                print(f"  -- top aligned {size}B blocks "
                      f"({len(agg)} distinct)")
                for blk, n in agg.most_common(6):
                    ops = sorted(pktcount[blk])[:6]
                    print(f"     {blk.hex():{size*2}}  x{n:<6} in {len(pktcount[blk])} opcodes "
                          f"e.g. {ops}")
            # is this packet a pure keystream repeat?
            print("  -- packets whose whole body is a <=64B period "
                  "(keystream / ECB-on-zeros signature)")
            seen = Counter()
            for r in sel:
                p, _ = period(r["body"])
                if p:
                    seen[(r["opcode"], len(r["body"]), p, r["body"][:p].hex())] += 1
            for (op, ln, p, unit), n in seen.most_common(14):
                print(f"     {op:11} len={ln:<6} period={p:<3} x{n:<4} unit={unit[:48]}")


def report_legacy(recs):
    """Packets whose body is pure 06831f52* -- i.e. legacy XOR over zeros."""
    print("\n=== legacy 4-byte XOR 06 83 1f 52 (body is a pure repeat over zeros)")
    for direction in ("C->S", "S->C"):
        for r in recs:
            if r["direction"] != direction or not r["body"]:
                continue
            b = r["body"]
            p, _ = period(b)
            if p and p <= 4 and b[0:4] == LEGACY:
                print(f"  {r['ts'][11:]} {direction} {r['kind']:8} {r['opcode']:11} "
                      f"len={len(b):<6} = 06831f52 * {len(b)//4}")
            # leading-zero plaintext: ciphertext starts with the legacy key
            elif b[:4] == LEGACY and len(b) >= 8:
                print(f"  {r['ts'][11:]} {direction} {r['kind']:8} {r['opcode']:11} "
                      f"len={len(b):<6} starts 06831f52 (plain[0:4]==0)")


def report_pairs(recs, full_below=96):
    """Exact pairs: the UNHANDLED line sits directly under its PACKET line."""
    pairs = []
    for i, r in enumerate(recs):
        if r["source"] != "unhandled" or not r["plain"]:
            continue
        for j in range(i - 1, max(-1, i - 4), -1):
            p = recs[j]
            if p["source"] == "packet" and p["opcode"] == r["opcode"] and p["hex"]:
                pairs.append((p, r))
                break
    print(f"\n=== known-plaintext pairs (adjacency-matched): {len(pairs)}")
    print(f"  {'time':12} {'opcode':11} {'ctr':>4} {'wire':>5} {'plain':>5} "
          f"{'xor len':>7}  period")
    for p, u in pairs:
        wb = bytes.fromhex(p["hex"])[13:]
        pb = bytes.fromhex(u["plain"])
        raw = bytes.fromhex(p["hex"])
        ctr = int.from_bytes(raw[11:13], "little") if len(raw) >= 13 else -1
        n = min(len(wb), len(pb))
        x = bytes(a ^ b for a, b in zip(wb[:n], pb[:n]))
        per, _ = period(x)
        print(f"  {p['ts'][11:]} {p['opcode']:11} {ctr:>4} {len(wb):>5} "
              f"{len(pb):>5} {n:>7}  {per or '-'}")
        if max(len(wb), len(pb)) <= full_below:
            print(f"      wire  {wb.hex()}")
            print(f"      plain {pb.hex()}")
            print(f"      xor   {x.hex()}")

    # aggregate: does any xor recur across packets?
    agg = Counter()
    for p, u in pairs:
        wb = bytes.fromhex(p["hex"])[13:]
        pb = bytes.fromhex(u["plain"])
        n = min(len(wb), len(pb))
        agg[bytes(a ^ b for a, b in zip(wb[:n], pb[:n]))[:16]] += 1
    print("\n  -- most common 16B XOR prefixes")
    for x, n in agg.most_common(8):
        print(f"     {x.hex()} x{n}")


def _sec(ts: str) -> float:
    h, m, s = ts[11:].split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


# ---------------------------------------------------------------- AES (pure)

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _exp_key(key: bytes) -> bytes:
    n = len(key)
    nk, nr = {16: (4, 10), 24: (6, 12), 32: (8, 14)}[n]
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return bytes(b for word in w for b in word), nr


def _xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _enc_block(rk: bytes, nr: int, s: bytes) -> bytes:
    st = [a ^ b for a, b in zip(s, rk[0:16])]
    for r in range(1, nr + 1):
        st = [_SBOX[b] for b in st]                                        # SubBytes
        st = [st[4 * ((i // 4 + i % 4) % 4) + (i % 4)] for i in range(16)]  # ShiftRows
        if r < nr:
            ns = []
            for c in range(4):
                a = st[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                ns += [a[0] ^ t ^ _xt(a[0] ^ a[1]),
                       a[1] ^ t ^ _xt(a[1] ^ a[2]),
                       a[2] ^ t ^ _xt(a[2] ^ a[3]),
                       a[3] ^ t ^ _xt(a[3] ^ a[0])]
            st = ns
        st = [a ^ b for a, b in zip(st, rk[16 * r:16 * r + 16])]
    return bytes(st)


def aes_ecb(key: bytes, data: bytes) -> bytes:
    rk, nr = _exp_key(key)
    return b"".join(_enc_block(rk, nr, data[i:i + 16])
                    for i in range(0, len(data), 16))


def key_tests(c2s_zero: bytes, s2c_zero: bytes):
    print("\n=== AES candidate keys vs the observed E(0)")
    print(f"  target C->S E(0) = {c2s_zero.hex()}")
    print(f"  target S->C E(0) = {s2c_zero.hex()}")
    k4 = bytes.fromhex("06831f52")
    cands = {
        "06831f52 *4": k4 * 4,
        "06831f52 +0*12": k4 + b"\0" * 12,
        "0*12 + 06831f52": b"\0" * 12 + k4,
        "zeros": b"\0" * 16,
        "ascii 06831f52 x2": b"06831f52" * 2,
        "C->S E(0) as key": c2s_zero,
        "S->C E(0) as key": s2c_zero,
        "08d27a963cae098d *2": bytes.fromhex("08d27a963cae098d") * 2,
        "e0ec8f4a1f63450e *2": bytes.fromhex("e0ec8f4a1f63450e") * 2,
        "C->S E(0) as plain": None,
    }
    z = b"\0" * 16
    for name, k in cands.items():
        if k is None:
            continue
        try:
            got = aes_ecb(k, z)
        except Exception as e:                          # noqa: BLE001
            print(f"  {name:22} ERROR {e}")
            continue
        flags = []
        if got == c2s_zero:
            flags.append("*** == C->S E(0)")
        if got == s2c_zero:
            flags.append("*** == S->C E(0)")
        print(f"  {name:22} E(0)={got.hex()} {' '.join(flags)}")
    # sanity: does the table even match the standard?
    std = aes_ecb(b"\0" * 16, b"\0" * 16).hex()
    print(f"  [sanity] AES-128(0 key, 0 plain) = {std} "
          f"(expect 66e94bd4ef8a2c3b884cfa59ca342b2e)")


def pairs(recs):
    """UNHANDLED sits directly under its PACKET line -- pair on adjacency."""
    out = []
    for i, r in enumerate(recs):
        if r["source"] != "unhandled" or not r["plain"]:
            continue
        for j in range(i - 1, max(-1, i - 4), -1):
            p = recs[j]
            if p["source"] == "packet" and p["opcode"] == r["opcode"] and p["hex"]:
                out.append((p, r))
                break
    return out


def report_ecb(recs, size: int = 8):
    """Every known-plaintext pair, cut into `size`-byte blocks: does an
    identical plaintext block always give an identical ciphertext block?"""
    pp = pairs(recs)
    print(f"\n=== ECB-{size} check over {len(pp)} known-plaintext pairs")
    p2c = defaultdict(set)
    c2p = defaultdict(set)
    who = defaultdict(set)
    for p, u in pp:
        wb = p["body"]
        pb = bytes.fromhex(u["plain"])
        n = min(len(wb), len(pb))
        for i in range(0, n - size + 1, size):
            p2c[pb[i:i + size]].add(wb[i:i + size])
            c2p[wb[i:i + size]].add(pb[i:i + size])
            who[pb[i:i + size]].add(p["opcode"].strip("()").replace(",", ":"))
    conflicts = {k: v for k, v in p2c.items() if len(v) > 1}
    print(f"  {len(p2c)} distinct plaintext blocks, {len(conflicts)} with >1 ciphertext")
    for k, v in sorted(conflicts.items(), key=lambda kv: -len(kv[1]))[:12]:
        print(f"    P={k.hex()} -> {len(v)} x C: {' '.join(sorted(x.hex() for x in v)[:5])}")
        print(f"         ops={sorted(who[k])}")
    conflicts2 = {k: v for k, v in c2p.items() if len(v) > 1}
    print(f"  {len(c2p)} distinct ciphertext blocks, {len(conflicts2)} with >1 plaintext")
    for k, v in sorted(conflicts2.items(), key=lambda kv: -len(kv[1]))[:8]:
        print(f"    C={k.hex()} -> {len(v)} x P: {' '.join(sorted(x.hex() for x in v)[:5])}")
    z = b"\0" * size
    print(f"  zero block -> {[x.hex() for x in p2c.get(z, [])] or 'not seen'}")


def report_phase(recs, size: int = 8):
    """Are the conflicts above just a block-GRID artifact?

    Slicing at body offset 0 assumes the cipher's 8-byte grid is aligned with
    the body.  If encryption covers `header||body` as one stream, the body sits
    at wire offset 13 -> grid phase 13 % 8 = 5.  So try every phase and see
    which one makes identical plaintext blocks give identical ciphertext."""
    pp = pairs(recs)
    print(f"\n=== grid-phase sweep over {len(pp)} known-plaintext pairs "
          f"(block={size})")
    for phase in range(size):
        p2c = defaultdict(set)
        for p, u in pp:
            wb = p["body"]
            pb = bytes.fromhex(u["plain"])
            n = min(len(wb), len(pb))
            for i in range(phase, n - size + 1, size):
                p2c[pb[i:i + size]].add(wb[i:i + size])
        conf = sum(1 for v in p2c.values() if len(v) > 1)
        extra = sum(len(v) - 1 for v in p2c.values() if len(v) > 1)
        mark = "  <== clean" if conf == 0 else ""
        print(f"  phase {phase}: {len(p2c):4d} distinct P blocks, "
              f"{conf:3d} conflicting, {extra:3d} extra ciphertexts{mark}")


def report_grid(recs):
    """Locate the cipher grid from ciphertext alone.

    In a long zero-plaintext run, an ECB-shaped cipher emits a repeating
    ciphertext block whose period == block size, and whose START is on the
    grid.  Scan each packet's tail (the zero-padding region) for the smallest
    period and report where it begins."""
    print("\n=== ciphertext periodicity (grid hunt)")
    for r in recs:
        if r["source"] != "packet" or not r["hex"]:
            continue
        b = r["body"]
        if len(b) < 32:
            continue
        for size in (8, 16):
            if len(b) < 3 * size:
                continue
            tail = b[-3 * size:]
            if tail[:size] == tail[size:2 * size] == tail[2 * size:]:
                print(f"  {r['ts'][11:23]} {r['opcode']:11} body={len(b):<5} "
                      f"period={size} tail_starts_at={len(b) - 3 * size} "
                      f"unit={tail[:size].hex()}")
                break


def ctr_of(r) -> str:
    raw = bytes.fromhex(r["hex"]) if r["hex"] else b""
    if r["direction"] == "C->S" and r["kind"] == "game" and len(raw) >= 13:
        return str(int.from_bytes(raw[11:13], "little"))
    if r["direction"] == "S->C" and r["kind"] == "game" and len(raw) >= 16:
        return str(raw[7])
    return "-"


def report_short(recs, maxlen: int = 32):
    """Every small packet with its wire body -- and the plaintext sitting
    directly below it -- so identical plaintexts at different sequence
    numbers become visible."""
    print(f"\n=== packets with body <= {maxlen}B (wire + the plain= line under it)")
    n = 0
    for i, r in enumerate(recs):
        b = r["body"]
        if not b or len(b) > maxlen:
            continue
        n += 1
        pl = ""
        if (i + 1 < len(recs) and recs[i + 1]["source"] == "unhandled"
                and recs[i + 1]["opcode"] == r["opcode"]):
            pl = "  plain=" + recs[i + 1]["plain"]
        raw = bytes.fromhex(r["hex"])
        a = raw[7:11].hex() if len(raw) >= 11 else "-"
        print(f"  {r['ts'][11:23]} c{r['conn']:3} {r['direction']:5} {r['kind']:7} "
              f"{r['opcode']:11} ctr={ctr_of(r):<4} A={a} len={len(b):<4} {b.hex()}{pl}")
    print(f"  ({n} packets)")


def report_s2c_hdr(recs):
    """S->C game header fields against the body: is [7:11]/[11:15] derived
    from the body, the packet, or nothing at all?"""
    rows = [r for r in recs if r["direction"] == "S->C" and r["kind"] == "game" and r["hex"]]
    print(f"\n=== S->C game headers ({len(rows)} packets)")
    eq = 0
    for r in rows:
        raw = bytes.fromhex(r["hex"])
        if len(raw) >= 16 and raw[7] == raw[11]:
            eq += 1
    print(f"  b[7] == b[11]: {eq}/{len(rows)}")
    for r in rows:
        raw = bytes.fromhex(r["hex"])
        if len(raw) < 16:
            continue
        body = r["body"]
        print(f"  {r['ts'][11:23]} {r['opcode']:11} wire={len(raw):<5} "
              f"A={raw[7:11].hex()} B={raw[11:15].hex()} "
              f"h12={raw[11:13].hex()} decl={int.from_bytes(raw[3:7], 'little'):<6} "
              f"body={body[:32].hex()}{'...' if len(body) > 32 else ''}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", type=Path)
    ap.add_argument("--keys", action="store_true")
    ap.add_argument("--pairs", action="store_true")
    ap.add_argument("--blocks", action="store_true")
    ap.add_argument("--short", action="store_true")
    ap.add_argument("--s2c", action="store_true")
    ap.add_argument("--ecb", action="store_true")
    ap.add_argument("--phase", action="store_true")
    ap.add_argument("--grid", action="store_true")
    args = ap.parse_args()

    recs = load(args.log)
    print(f"{args.log}: {len(recs)} records")

    if args.short:
        report_short(recs)
    if args.s2c:
        report_s2c_hdr(recs)
    if args.ecb:
        report_ecb(recs)
    if args.phase:
        report_phase(recs)
    if args.grid:
        report_grid(recs)
    if args.blocks:
        report_blocks(recs)
    report_legacy(recs)
    if args.pairs:
        report_pairs(recs)
    if args.keys:
        c2s_zero = bytes.fromhex("d8542ae1bbeac96b9ccf9ac12d501244")
        s2c_zero = bytes.fromhex("829bec98e3808b1e704ed8de024a5852")
        key_tests(c2s_zero, s2c_zero)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
