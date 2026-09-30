"""Restart the reference server and dump the ACK block maps of a fresh probe.

    python tools/chan_experiment.py --label short-host

Kills the reference, starts it again with the current `server.json`, waits for
7001, replays the three channel requests, and writes the bodies to
`_chan_exp/<label>/` plus a block map (`inflated -> 16B blocks, grouped by
equality`).  Comparing maps across runs is how the plaintext layout of
CHANNEL_ACK gets pinned: each `server.json` edit changes a known field.

`--no-restart` probes the server that is already up.
"""
from __future__ import annotations

import argparse
import asyncio
import socket
import subprocess
import sys
import time
import zlib
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tools"))

from uslocalserver.protocol import frame                       # noqa: E402

SERVER_DIR = Path(r"E:\DFO_2.31.1.117\DFO110-0.3.6\Server")
EXE = SERVER_DIR / "USLocalServer.Server.exe"
EXE_NAME = EXE.name
OUT_ROOT = REPO / "_chan_exp"

PROBE = (
    ((0, 11), (124, 12), "CONNECT_ACK",
     bytes.fromhex("f2f7f142f7dea0499f6bf6129fe6184fb76651875835f147e7940427c0d0aca3")),
    ((0, 9), (124, 10), "SCRIPT_ACK", b""),
    ((0, 1), (124, 3), "CHANNEL_ACK", b""),
)


def _op(main: int, sub: int) -> frame.Opcode:
    return frame.Opcode(main, sub, frame.OpcodeEncoding.U16BE, False)


def stop_server() -> int:
    return subprocess.run(["taskkill", "/F", "/IM", EXE_NAME],
                          capture_output=True).returncode


def start_server() -> subprocess.Popen:
    return subprocess.Popen(
        [str(EXE)], cwd=str(SERVER_DIR),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.DETACHED_PROCESS
        | subprocess.CREATE_NEW_PROCESS_GROUP)


def wait_port(host: str, port: int, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((host, port)) == 0:
                time.sleep(1.0)          # let it finish the STAGE banner
                return True
        time.sleep(0.5)
    return False


async def probe(host: str, port: int) -> dict[str, bytes]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5.0)
    got: list[frame.Frame] = []
    stream = frame.FrameStream(frame.Link.CHANNEL_S2C)
    try:
        for req, _reply, _name, body in PROBE:
            writer.write(frame.build(frame.Link.CHANNEL_C2S, _op(*req), body))
        await writer.drain()
        while len(got) < len(PROBE):
            chunk = await asyncio.wait_for(reader.read(65536), 5.0)
            if not chunk:
                break
            stream.feed(chunk)
            while (f := stream.next_frame()) is not None:
                got.append(f)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    out: dict[str, bytes] = {}
    for f, (_req, reply, name, _body) in zip(got, PROBE):
        assert f.opcode.key() == reply, f"{name}: got {f.opcode.key()}"
        out[name] = f.body
    return out


def inflated(body: bytes) -> bytes:
    return zlib.decompress(body) if body[:1] == b"\x78" else body


def block_map(data: bytes) -> str:
    lines = []
    blocks = [data[i:i + 16] for i in range(0, len(data) - len(data) % 16, 16)]
    seen: dict[bytes, list[int]] = {}
    for i, b in enumerate(blocks):
        seen.setdefault(b, []).append(i)
    for b, idx in sorted(seen.items(), key=lambda kv: kv[1][0]):
        mark = "CONST" if len(idx) > 1 else "uniq "
        lines.append(f"    {mark} {b.hex()}  at {idx}")
    if len(data) % 16:
        lines.append(f"    tail({len(data) % 16}) {data[len(data) - len(data) % 16:].hex()}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7001)
    ap.add_argument("--no-restart", action="store_true")
    args = ap.parse_args()

    if not args.no_restart:
        print(f"taskkill rc={stop_server()}")
        time.sleep(1.0)
        start_server()
        if not wait_port(args.host, args.port):
            print("!! server did not come up on 7001")
            return 1

    bodies = asyncio.run(probe(args.host, args.port))
    out = OUT_ROOT / args.label
    out.mkdir(parents=True, exist_ok=True)
    for name, body in bodies.items():
        inf = inflated(body)
        (out / f"{name}.wire").write_bytes(body)
        (out / f"{name}.infl").write_bytes(inf)
        print(f"{name}: wire={len(body)} inflated={len(inf)}")
        print(block_map(inf))
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
