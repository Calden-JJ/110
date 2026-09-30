"""Every `(0,35)` CARD body in the reference logs, laid side by side.

The clear chain's card is a fed input in the rewrite (`clear.Card`); this
script collects the corpus's own cards so a live generator can be fitted:
size (257+29k), the purse fields `clear.card_purse` reads, the gold u32 at
`card.GOLD_AT`, and a byte-level diff of same-size pairs.
"""
import importlib.util
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "src"))

_spec = importlib.util.spec_from_file_location(
    "diff_packets", Path(__file__).parent / "diff_packets.py")
dp = importlib.util.module_from_spec(_spec)
sys.modules["diff_packets"] = dp
_spec.loader.exec_module(dp)

from uslocalserver import logs  # noqa: E402
from uslocalserver.protocol import frame  # noqa: E402

REF_DIR = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\Logs")

cards = {}          # sha -> (body, [sources])
for path in sorted(REF_DIR.glob("server-*.log")):
    for p in logs.iter_packets(path):
        if p.direction != "S->C" or p.link != "game" or p.hex is None:
            continue
        try:
            f = frame.parse(frame.Link.GAME_S2C, p.hex.data, strict=False,
                            expect_size=p.hex.full_size if p.hex.truncated else None)
        except Exception:                              # noqa: BLE001
            continue
        if (f.opcode.main, f.opcode.sub) != (0, 35):
            continue
        body = dp.s2c_content(f, truncated=p.truncated)
        if body is None or p.truncated or len(body) < 258:
            continue
        # The wire payload is padded to the tile block; the content is
        # 257 + 29k, so crop the trailing zeros back off.
        k = round((len(body) - 257) / 29)
        content = body[:257 + 29 * k]
        if content not in cards:
            cards[content] = []
        cards[content].append(f"{path.name}:{p.ts}")

print(f"{len(cards)} distinct card(s)\n")
for body, srcs in sorted(cards.items(), key=len):
    size = len(body)
    k = (size - 257) // 29
    free = body[131]
    gold = int.from_bytes(body[136:140], "little")
    paid = body[-90]
    cost = int.from_bytes(body[-118:-116], "little")
    print(f"len={size} ({257}+29*{k}) free={free} gold={gold} paid={paid} "
          f"cost={cost}  x{len(srcs)}")
    for s in srcs[:3]:
        print(f"    {s}")
    nz = [(i, body[i]) for i in range(size) if body[i]]
    print(f"    nonzero offsets: {nz[:40]}")
    if k:
        recs = body[257:]
        for i in range(k):
            print(f"    rec[{i}]: {recs[i*29:(i+1)*29].hex()}")
    print()

# same-size pairs: which bytes differ between two dungeons' cards
sizes = {}
for body in cards:
    sizes.setdefault(len(body), []).append(body)
for size, bodies in sorted(sizes.items()):
    if len(bodies) < 2:
        continue
    a, b = bodies[0], bodies[1]
    d = [i for i in range(size) if a[i] != b[i]]
    print(f"len={size} pair diff at {len(d)} offset(s):")
    for i in d:
        print(f"    [{i}] a={a[i]:02x} b={b[i]:02x}")
        if len(d) > 60:
            break
