#!/usr/bin/env python3
"""Extract TCP streams from a pktmon capture and search for the frame layout.

Input : .pcapng or .pcap produced by PktMon.exe (see capture_s2c.bat)
Output: per-flow, per-direction raw byte streams + a hypothesis search that
        tries to split the stream into frames of the form
        [header][length field][body].

Usage:
    python extract_streams.py dfo_capture.pcapng
    python extract_streams.py dfo_capture.pcapng --dump 128
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import defaultdict
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SERVER_PORTS = {7001} | set(range(10011, 10022))


# --------------------------------------------------------------------------
# container parsing
# --------------------------------------------------------------------------

def read_pcapng(raw: bytes):
    """Yield (linktype, payload) for every packet in a pcapng file."""
    off = 0
    linktypes: dict[int, int] = {}
    n = len(raw)
    while off + 12 <= n:
        btype, blen = struct.unpack_from("<II", raw, off)
        if blen < 12 or off + blen > n:
            break
        body = raw[off + 8: off + blen - 4]
        if btype == 0x0A0D0D0A:          # section header
            linktypes.clear()
        elif btype == 0x00000001:        # interface description
            if len(body) >= 8:
                linktypes[len(linktypes)] = struct.unpack_from("<H", body, 0)[0]
        elif btype == 0x00000006:        # enhanced packet
            if len(body) >= 20:
                iface, _, _, caplen, _ = struct.unpack_from("<IIIII", body, 0)
                yield linktypes.get(iface, 1), body[20:20 + caplen]
        elif btype == 0x00000003:        # simple packet
            if len(body) >= 4:
                yield linktypes.get(0, 1), body[4:]
        off += blen


def read_pcap(raw: bytes):
    """Yield (linktype, payload) for every packet in a classic pcap file."""
    if len(raw) < 24:
        return
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
    else:
        raise ValueError(f"unknown pcap magic 0x{magic:08x}")
    linktype = struct.unpack_from(endian + "I", raw, 20)[0]
    off = 24
    n = len(raw)
    while off + 16 <= n:
        _, _, caplen, _ = struct.unpack_from(endian + "IIII", raw, off)
        off += 16
        if caplen > n - off:
            break
        yield linktype, raw[off: off + caplen]
        off += caplen


def read_packets(path: Path):
    raw = path.read_bytes()
    if raw[:4] == b"\x0a\x0d\x0d\x0a":
        yield from read_pcapng(raw)
    else:
        yield from read_pcap(raw)


# --------------------------------------------------------------------------
# link / network / transport
# --------------------------------------------------------------------------

def strip_link(linktype: int, pkt: bytes):
    """Return the IPv4 payload, or None."""
    if linktype == 1:                                   # Ethernet
        if len(pkt) < 14:
            return None
        ethertype = struct.unpack_from(">H", pkt, 12)[0]
        off = 14
        if ethertype == 0x8100 and len(pkt) >= 18:      # VLAN
            ethertype = struct.unpack_from(">H", pkt, 16)[0]
            off = 18
        if ethertype != 0x0800:
            return None
        return pkt[off:]
    if linktype == 101:                                 # raw IP
        return pkt
    if linktype == 113:                                 # Linux SLL
        if len(pkt) < 16:
            return None
        return pkt[16:]
    if linktype == 276:                                 # Linux SLL2
        if len(pkt) < 20:
            return None
        return pkt[20:]
    if linktype == 0:                                   # BSD null/loopback
        if len(pkt) < 4:
            return None
        return pkt[4:]
    return None


def parse_tcp(ip: bytes):
    """Return (src, sport, dst, dport, seq, payload) or None."""
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 20 or ip[9] != 6:                # not TCP
        return None
    total = struct.unpack_from(">H", ip, 2)[0]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    t = ip[ihl:]
    sport, dport = struct.unpack_from(">HH", t, 0)
    seq = struct.unpack_from(">I", t, 4)[0]
    doff = (t[12] >> 4) * 4
    payload = t[doff:total - ihl] if total >= ihl else b""
    return src, sport, dst, dport, seq, payload


# --------------------------------------------------------------------------
# reassembly
# --------------------------------------------------------------------------

def flows_from(path: Path):
    """Group packets into bidirectional flows, keeping payload per direction."""
    flows: dict[tuple, dict[str, list[tuple[int, bytes]]]] = defaultdict(
        lambda: {"a": [], "b": []}
    )
    n_pkts = n_bytes = 0
    for linktype, pkt in read_packets(path):
        ip = strip_link(linktype, pkt)
        if not ip:
            continue
        parsed = parse_tcp(ip)
        if not parsed:
            continue
        src, sport, dst, dport, seq, payload = parsed
        n_pkts += 1
        if not payload:
            continue
        n_bytes += len(payload)
        # canonical flow key: sort the two endpoints
        a, b = (src, sport), (dst, dport)
        if a <= b:
            key, side = (a, b), "a"
        else:
            key, side = (b, a), "b"
        flows[key][side].append((seq, payload))
    return flows, n_pkts, n_bytes


def assemble(segments: list[tuple[int, bytes]]) -> bytes:
    if not segments:
        return b""
    segments.sort()
    base = segments[0][0]
    end = base
    out = bytearray()
    for seq, data in segments:
        if seq + len(data) <= end:      # fully duplicate
            continue
        if seq < end:                   # partial overlap: keep the tail
            data = data[end - seq:]
            seq = end
        if seq > end:                   # gap: pad so offsets stay honest
            out.extend(b"\x00" * (seq - end))
        out.extend(data)
        end = seq + len(data)
    return bytes(out)


# --------------------------------------------------------------------------
# frame hypothesis search
# --------------------------------------------------------------------------

def try_split(buf: bytes, header: int, len_off: int, len_size: int, includes_header: bool):
    """Return (frames, leftover) or None if the hypothesis breaks."""
    frames = []
    i, n = 0, len(buf)
    while i + header <= n:
        if i + len_off + len_size > n:
            return None
        ln = int.from_bytes(buf[i + len_off: i + len_off + len_size], "little")
        total = ln if includes_header else header + ln
        if total < header or total > n - i:
            return None
        frames.append(buf[i:i + total])
        i += total
    if i != n:
        return None
    return frames


def search_layout(buf: bytes, label: str, max_frames: int = 4000):
    """Brute-force [header][len@off][body] layouts that split buf cleanly.

    Returns groups keyed by the *load-bearing* knobs.  When the length field
    counts the whole frame (includes_header=True) the frame boundaries depend
    only on (len_off, len_size) -- every header size >= len_off+len_size splits
    identically, so the header length stays under-determined until the opcode
    bytes are matched against the packet log.  The first frames' raw bytes are
    returned so that match can be done by eye.
    """
    if len(buf) < 16:
        print(f"  [{label}] only {len(buf)}B -- too short to search")
        return {}
    groups: dict[tuple, dict] = {}
    for header in (8, 10, 11, 12, 13, 14, 16, 17, 20):
        for len_off in range(0, min(header, 12)):
            for len_size in (2, 4):
                if len_off + len_size > header:
                    continue
                for includes_header in (True, False):
                    frames = try_split(buf, header, len_off, len_size, includes_header)
                    if frames is None or not frames or len(frames) > max_frames:
                        continue
                    if len(frames) == 1 and len(buf) > 64:
                        continue        # degenerate "one giant frame"
                    key = (len_off, len_size, includes_header)
                    g = groups.setdefault(key, {"headers": set(), "n": len(frames),
                                                "lens": [], "sample": frames[:3]})
                    g["headers"].add(header)
                    g["n"] = len(frames)
                    g["lens"] = [len(f) for f in frames]
                    g["sample"] = frames[:3]
    return groups


def hexd(d: bytes, limit: int = 96) -> str:
    s = d[:limit].hex(" ")
    if len(d) > limit:
        s += f" ... (+{len(d) - limit}B)"
    return s


# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", type=Path)
    ap.add_argument("--dump", type=int, default=64,
                    help="hex bytes to show per direction (default 64)")
    ap.add_argument("--outdir", type=Path, default=None,
                    help="write each direction's raw stream here")
    ap.add_argument("--search", action="store_true",
                    help="run the frame-layout hypothesis search")
    args = ap.parse_args()

    if not args.capture.exists():
        print(f"no such file: {args.capture}", file=sys.stderr)
        return 2

    flows, n_pkts, n_bytes = flows_from(args.capture)
    print(f"capture : {args.capture}")
    print(f"packets : {n_pkts} with payload, {n_bytes} payload bytes")
    print(f"flows   : {len(flows)}")
    if args.outdir:
        args.outdir.mkdir(parents=True, exist_ok=True)

    for (ep_a, ep_b), dirs in sorted(flows.items()):
        streams = {side: assemble(segs) for side, segs in dirs.items()}
        total_a, total_b = len(streams["a"]), len(streams["b"])
        if total_a + total_b == 0:
            continue
        # which endpoint is the server?
        if ep_a[1] in SERVER_PORTS:
            srv, cli = ep_a, ep_b
        elif ep_b[1] in SERVER_PORTS:
            srv, cli = ep_b, ep_a
        else:
            srv, cli = (ep_a, ep_b) if total_a < total_b else (ep_b, ep_a)

        srv_side = "a" if ep_a == srv else "b"
        cli_side = "b" if srv_side == "a" else "a"
        to_server = streams[cli_side]     # client -> server
        to_client = streams[srv_side]     # server -> client

        tag = "CHANNEL" if srv[1] == 7001 else "GAME"
        print(f"\n=== {tag}  {cli[0]}:{cli[1]}  <->  {srv[0]}:{srv[1]} ===")
        print(f"  client->server : {len(to_server)} B")
        print(f"  server->client : {len(to_client)} B")
        print(f"  c2s head: {hexd(to_server, args.dump)}")
        print(f"  s2c head: {hexd(to_client, args.dump)}")

        if args.outdir:
            stem = f"{tag}_{srv[1]}_{cli[1]}"
            (args.outdir / f"{stem}_c2s.bin").write_bytes(to_server)
            (args.outdir / f"{stem}_s2c.bin").write_bytes(to_client)

        if args.search:
            for label, buf in (("s2c", to_client), ("c2s", to_server)):
                print(f"  -- layout search [{label}] ({len(buf)}B) --")
                groups = search_layout(buf, label)
                if not groups:
                    print("     no clean split found")
                    continue
                ranked = sorted(groups.items(),
                                key=lambda kv: (-kv[1]["n"], kv[0][0], kv[0][1]))
                for (loff, lsize, incl), g in ranked[:6]:
                    hdrs = sorted(g["headers"])
                    hrange = f"{hdrs[0]}" if len(hdrs) == 1 else f"{hdrs[0]}..{hdrs[-1]}"
                    lens = g["lens"]
                    avg = sum(lens) / len(lens)
                    print(f"     {g['n']:5d} frames  len@{loff} u{lsize * 8}le  "
                          f"includes_header={incl}  header={hrange}{' (under-determined)' if len(hdrs) > 1 else ''}")
                    print(f"            lens={lens[:8]}{' ...' if len(lens) > 8 else ''}  avg={avg:.1f}")
                    for k, f in enumerate(g["sample"]):
                        print(f"            frame{k}: {f[:24].hex(' ')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
