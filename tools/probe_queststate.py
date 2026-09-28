"""Re-validate `queststate.available_ids` against the whole corpus.

Reads every paired `TOWN-QUEST-STATE`/`TOWN-QUESTS` line in the three server
logs -- the independent evidence the rule was fitted to -- re-derives
`available` with the shipped module, and prints OK/XX per state.  At
`finished=814` it also compares the module's id set against the captured
`(0,21)` frame id for id.  `tests/test_queststate.py` pins the rule; this is
where it stands against the raw corpus.

Expected: 37 OK, 0 XX, 17 of them `frame:IDENTICAL`.
"""
import glob
import json
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, r"E:\DFO_2.31.1.117\dfo-server\src")

from uslocalserver.game.town import queststate as qs

STATE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*TOWN-QUEST-STATE conn=(\d+) "
    r"\(0,342\) finished=(\d+) \(0,291\) in-progress=(\d+) \(of (\d+) ever accepted\)"
    r"(?:; finished=([\d,]+))?(?:; in-progress=([\d,]+))?")
QUESTS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*TOWN-QUESTS conn=(\d+) town=(\d+) "
    r"worldmap nodes=(\d+) \(0,21\) available=(\d+) active=\[([\d,]*)\] "
    r"finished=(\d+) level=(\d+)")

# The character each era's states belong to.  09-25/26 morning is LRouDao
# (fighter, 4, 1); every Lv110 state is XRenYing.
IDENT = {"0925": (1, 4, 1), "0926": (1, 4, 1), "0927": (1, 4, 1)}
XRENYING = (11, 5, 3)

states = []
for path in sorted(glob.glob(
        r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server\Logs\server-2026092*.log")):
    last = {}
    day = path[-8:-4]
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "TOWN-QUEST-STATE" in line:
                m = STATE_RE.search(line)
                if m:
                    fin = sorted(int(x) for x in (m.group(6) or "").split(",") if x)
                    inp = sorted(int(x) for x in (m.group(7) or "").split(",") if x)
                    last[int(m.group(2))] = (m.group(1), fin, inp)
            elif "TOWN-QUESTS" in line:
                m = QUESTS_RE.search(line)
                if m and int(m.group(2)) in last:
                    ts, fin, inp = last[int(m.group(2))]
                    states.append((day, ts, int(m.group(5)), int(m.group(8)),
                                   fin, inp))

doc = json.load(open(r"E:\DFO_2.31.1.117\dfo-server\data\game\replies.json",
                     encoding="utf-8"))
run = doc["scripts"][13]["runs"][0]
avail_frame = None
for r in run["replies"]:
    if (r["main"], r["sub"]) == (0, 21):
        body = bytes.fromhex(r["plain_hex"])
        # skip the u32 prefix, then read the varint stream positionally
        vals, pos = [], 4
        while pos < len(body):
            shift = val = 0
            while True:
                b = body[pos]
                pos += 1
                val |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            vals.append(val)
        avail_frame = set(vals[5::2])
        print(f"frame (0,21): count={vals[3]} level={vals[1]} ids={len(avail_frame)}")

print("\n== every paired state ==")
failures = 0
for day, ts, avail_n, level, fin, inp in states:
    clazz, grow, sub = XRENYING if level == 110 else IDENT[day]
    model = set(qs.available_ids(qs.Seeker(level, clazz, grow, sub), fin, inp))
    ok = len(model) == avail_n
    failures += not ok
    extra = ""
    if avail_frame is not None and level == 110 and len(fin) == 814:
        extra = ("  frame:IDENTICAL" if model == avail_frame
                 else f"  frame:diff +{len(model - avail_frame)} "
                      f"-{len(avail_frame - model)}")
    print(f"  {'OK ' if ok else 'XX '}{day} {ts} cls{clazz} lv{level} "
          f"fin={len(fin)} inp={len(inp)} avail={avail_n} "
          f"model={len(model)}{extra}")

print(f"\n{len(states) - failures}/{len(states)} states match")
sys.exit(1 if failures else 0)
