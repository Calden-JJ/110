#!/usr/bin/env python3
"""Extract the client patches Dll1.dll installs -- Phase 0.1 of the launcher.

The reference launcher manual-maps `Runtime\\Dll1.dll` into the suspended
client, and Dll1's `ngs_startup_compat` module patches two sites in the
client image (`Dll1.status.log`: `PATCH_RVA=0x0497564A`, "NGS initialization
fast-success and success branch installed").  Dll1 holds the whole patch as
data:

  * a 39-byte code signature of the client around the sites, with the three
    rel32 displacement fields masked out of the comparison -- the version
    guard the module runs before touching anything;
  * the expected original bytes of the second site (`0F 84 E6 00 00 00`);
  * the two payloads (`31 C0 90 90 90` and `E9 E7 00 00 00 90`) plus the
    first site's own call displacement, which doubles as the magic
    `0xFE0E37EE`;
  * the writer's procedure: `VirtualProtect(0x40)` -> write -> read back ->
    `FlushInstructionCache` -> restore, with an "already patched" fast path
    that treats bytes equal to the payload as success.

This tool locates that writer function with capstone, decodes every cell,
checks all of them against the real `DFO.exe`, and emits
`data/launcher/patches-<client version>.json` -- what the rewrite's own
launcher reads, since it must never ship Dll1.

    python tools/extract_launcher_patches.py            # verify + write JSON
    python tools/extract_launcher_patches.py --check    # verify only

Dev-only: needs `capstone` and `pefile` (installed in `.venv`), which the
package itself deliberately does not depend on.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import capstone
import pefile
from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_AL,
                          X86_REG_RCX, X86_REG_RDX, X86_REG_RIP, X86_REG_R8)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver import paths  # noqa: E402

#: The module's own name and result line, verbatim from `Dll1.status.log`.
MODULE_NAME = "ngs_startup_compat"
MODULE_RESULT = "NGS initialization fast-success and success branch installed"

#: A `lea <reg>, [rdx + disp]` disp this large is a client-image RVA (the
#: module's base address lives in rdx); anything smaller is a local write.
RVA_FLOOR = 0x0200_0000


class ExtractError(RuntimeError):
    pass


@dataclass(slots=True)
class Cells:
    """The .rdata cells the writer code reads its expectations from."""
    stub_rva: int
    sig_rva: int
    sig_size: int
    mask: list[tuple[int, int]]
    site_a: int
    site_b: int
    payload_a: bytes
    orig_b: bytes
    payload_b: bytes
    expect_a_first: int
    fingerprint: int


def _mem(ins, i: int):
    if i < len(ins.operands) and ins.operands[i].type == X86_OP_MEM:
        return ins.operands[i].mem
    return None


def _rip_rva(ins) -> int | None:
    """RVA of a `[rip + disp]` memory operand, whichever side it is on."""
    for i in (1, 0):
        m = _mem(ins, i)
        if m is not None and m.base == X86_REG_RIP:
            return ins.address + ins.size + m.disp
    return None


def _read_size(ins) -> int | None:
    for i in (1, 0):
        if i < len(ins.operands) and ins.operands[i].type == X86_OP_MEM:
            return ins.operands[i].size
    return None


def _index_of(instrs, ins) -> int:
    for i, x in enumerate(instrs):
        if x.address == ins.address:
            return i
    raise ExtractError(f"instruction 0x{ins.address:x} not in listing")


def _reads(instrs: list, start: int, stop) -> list[tuple]:
    """The `[rip+d]` loads between `start` (exclusive) and the first
    instruction `stop` accepts (exclusive), as (ins, rva, size)."""
    out = []
    for ins in instrs[start + 1:start + 0x30]:
        if stop(ins):
            break
        rva = _rip_rva(ins)
        size = _read_size(ins)
        if rva is not None and size is not None:
            out.append((ins, rva, size))
    return out


def decode(dll: Path) -> tuple[bytes, pefile.PE, list]:
    pe = pefile.PE(str(dll), fast_load=True)
    data = dll.read_bytes()
    text = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"), None)
    if text is None:
        raise ExtractError(f"{dll.name}: no .text section")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    code = data[text.PointerToRawData:text.PointerToRawData + text.SizeOfRawData]
    return data, pe, list(md.disasm(code, text.VirtualAddress))


def find_signature(instrs: list) -> tuple:
    """The signature loop: `cmp byte ptr [rdx + rcx + rva], al`."""
    for ins in instrs:
        m = _mem(ins, 0)
        if (ins.mnemonic == "cmp" and m is not None and m.base == X86_REG_RDX
                and m.index == X86_REG_RCX and ins.operands[0].size == 1
                and ins.operands[1].type == X86_OP_REG
                and ins.operands[1].reg == X86_REG_AL):
            return ins, m.disp
    raise ExtractError("signature compare instruction not found")


def decode_cells(data: bytes, pe: pefile.PE, instrs: list) -> Cells:
    sig_cmp, sig_rva = find_signature(instrs)
    i = _index_of(instrs, sig_cmp)
    window = instrs[max(0, i - 0x40): i + 0x40]

    stub = next((x for x in reversed(instrs[max(0, i - 0x40):i])
                 if x.mnemonic == "lea" and _mem(x, 1) is not None
                 and _mem(x, 1).base == X86_REG_RIP
                 and x.operands[0].reg == X86_REG_R8), None)
    if stub is None:
        raise ExtractError("signature stub `lea r8, [rip+d]` not found")
    stub_rva = _rip_rva(stub)

    bound = next((x for x in instrs[i + 1:i + 0x30] if x.mnemonic == "cmp"
                  and x.operands[0].type == X86_OP_REG
                  and x.operands[0].reg == X86_REG_RCX
                  and x.operands[1].type == X86_OP_IMM), None)
    if bound is None:
        raise ExtractError("signature length `cmp rcx, size` not found")
    sig_size = bound.operands[1].imm

    # The loop skips the displacement fields: `lea rax, [rcx - k]` /
    # `cmp rax, m` / `jbe`.  Other modules repeat this shape nearby with
    # their own large offsets, so keep only the ranges inside the signature
    # and only triplets close to its compare.
    mask: list[tuple[int, int]] = []
    for k, ins in enumerate(window):
        m = _mem(ins, 1)
        if (ins.mnemonic == "lea" and m is not None and m.base == X86_REG_RCX
                and m.index == 0 and m.disp < 0 and k + 2 < len(window)):
            cmp_, jbe = window[k + 1], window[k + 2]
            if (cmp_.mnemonic == "cmp" and cmp_.operands[1].type == X86_OP_IMM
                    and jbe.mnemonic.startswith("j")
                    and sig_cmp.address - jbe.address < 0x30
                    and -m.disp + cmp_.operands[1].imm < sig_size):
                mask.append((-m.disp, -m.disp + cmp_.operands[1].imm))
    if not mask:
        raise ExtractError("signature mask ranges not found")
    mask.sort()

    sites = []
    for x in window:
        m = _mem(x, 1)
        if (x.mnemonic == "lea" and m is not None and m.base == X86_REG_RDX
                and m.index == 0 and m.disp >= RVA_FLOOR):
            sites.append((x, m.disp, x.operands[0].reg))
    if len(sites) != 2:
        raise ExtractError(f"expected 2 patch-site anchors, found {len(sites)}")

    site_a = site_b = None
    for x, rva, reg in sites:
        j = _index_of(instrs, x)
        stop = next((y for y in instrs[j + 1:j + 0x10]
                     if y.mnemonic == "cmp" and _mem(y, 0) is not None
                     and _mem(y, 0).base == reg
                     and y.operands[0].size == 1), None)
        if stop is not None:
            site_a = (x, rva, stop)
        else:
            site_b = (x, rva)
    if site_a is None or site_b is None:
        raise ExtractError("could not tell the two site anchors apart")

    x, a_rva, expect_cmp = site_a
    reads_a = _reads(instrs, _index_of(instrs, x), stop=lambda y: y is expect_cmp)
    if [s for _, _, s in reads_a] != [4, 1]:
        raise ExtractError(f"site A cells are {[s for _, _, s in reads_a]}, expected [4, 1]")
    payload_a = (data[pe.get_offset_from_rva(reads_a[0][1]):][:4]
                 + data[pe.get_offset_from_rva(reads_a[1][1]):][:1])
    expect_a_first = expect_cmp.operands[1].imm

    j = _index_of(instrs, expect_cmp)
    fp = next((y for y in instrs[j + 1:j + 6] if y.mnemonic == "cmp"
               and (m := _mem(y, 0)) is not None and m.base == X86_REG_RDX
               and y.operands[0].size == 4
               and y.operands[1].type == X86_OP_IMM), None)
    if fp is None or _mem(fp, 0).disp != a_rva + 1:
        raise ExtractError("fingerprint `cmp dword [rdx + siteA+1], imm` not found")
    fingerprint = fp.operands[1].imm

    x, b_rva = site_b
    reads_b = _reads(instrs, _index_of(instrs, x), stop=lambda y: y.mnemonic == "sete")
    if [s for _, _, s in reads_b] != [4, 2, 4, 2]:
        raise ExtractError(f"site B cells are {[s for _, _, s in reads_b]}, expected [4, 2, 4, 2]")

    def rd(rva: int, size: int) -> bytes:
        off = pe.get_offset_from_rva(rva)
        return data[off:off + size]

    orig_b = rd(reads_b[0][1], 4) + rd(reads_b[1][1], 2)
    payload_b = rd(reads_b[2][1], 4) + rd(reads_b[3][1], 2)
    return Cells(stub_rva, sig_rva, sig_size, mask, a_rva, b_rva,
                 payload_a, orig_b, payload_b, expect_a_first, fingerprint)


def read_client(client: pefile.PE, path: Path, rva: int, size: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(client.get_offset_from_rva(rva))
        return fh.read(size)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def client_version(build_info: Path) -> str:
    m = re.search(r"DFO\.exe\s+([0-9][\w.]*)", build_info.read_text(encoding="utf-8"))
    if not m:
        raise ExtractError(f"{build_info.name}: no `DFO.exe <version>` field")
    return m.group(1)


def verify(cells: Cells, data: bytes, pe: pefile.PE,
           client_path: Path) -> list[str]:
    """Check every decoded value against the real client; no silent passes."""
    cpe = pefile.PE(str(client_path), fast_load=True)
    problems: list[str] = []
    stub = data[pe.get_offset_from_rva(cells.stub_rva):][:cells.sig_size]

    skipped: set[int] = set()
    for lo, hi in cells.mask:
        if not 0 <= lo <= hi < cells.sig_size:
            problems.append(f"mask range {lo}..{hi} outside the signature")
        skipped.update(range(lo, hi + 1))
    want = read_client(cpe, client_path, cells.sig_rva, cells.sig_size)
    bad = [i for i in range(cells.sig_size)
           if i not in skipped and want[i] != stub[i]]
    if bad:
        problems.append(f"client differs from the signature at {len(bad)} byte(s): "
                        + ", ".join(f"+0x{i:x}" for i in bad[:8]))

    got_a = read_client(cpe, client_path, cells.site_a, 5)
    if got_a[0] != cells.expect_a_first:
        problems.append(f"site A starts 0x{got_a[0]:02x}, expected "
                        f"0x{cells.expect_a_first:02x}")
    if int.from_bytes(got_a[1:5], "little") != cells.fingerprint:
        problems.append(f"site A magic is 0x{int.from_bytes(got_a[1:5], 'little'):08x}, "
                        f"expected 0x{cells.fingerprint:08x}")

    got_b = read_client(cpe, client_path, cells.site_b, 6)
    if got_b != cells.orig_b:
        problems.append(f"site B is {got_b.hex()}, expected {cells.orig_b.hex()}")

    if cells.payload_a[0:2] != b"\x31\xc0":
        problems.append(f"site A payload {cells.payload_a.hex()} is not `xor eax,eax`")
    if cells.orig_b[0:2] != b"\x0f\x84":
        problems.append(f"site B original {cells.orig_b.hex()} is not `je rel32`")
    if cells.payload_b[0] != 0xE9:
        problems.append(f"site B payload {cells.payload_b.hex()} is not `jmp rel32`")
    else:
        orig_disp = int.from_bytes(cells.orig_b[2:6], "little")
        jmp_disp = int.from_bytes(cells.payload_b[1:5], "little")
        if jmp_disp != orig_disp + 1:
            problems.append(f"site B jmp +0x{jmp_disp:x} does not match je "
                            f"+0x{orig_disp:x} (+1)")
    if cells.site_b - cells.site_a != 13:
        problems.append(f"the two sites are {cells.site_b - cells.site_a} bytes apart, "
                        f"expected 13")
    return problems


def build(cells: Cells, dll: Path, dll_sha: str, stub_hex: str,
          client_path: Path, version: str) -> dict:
    return {
        "format": 1,
        "generated_by": "tools/extract_launcher_patches.py",
        "client_version": version,
        "client": {"size": client_path.stat().st_size, "sha256": sha256(client_path)},
        "source": {
            "dll": dll.name,
            "size": dll.stat().st_size,
            "sha256": dll_sha,
            "status_log": "PATCH_RVA=0x%08X, %s" % (cells.site_b, MODULE_NAME),
        },
        "modules": [{
            "name": MODULE_NAME,
            "result": MODULE_RESULT,
            "signature": {
                "rva": hex(cells.sig_rva),
                "size": cells.sig_size,
                "bytes": stub_hex,
                "mask": [[hex(lo), hex(hi)] for lo, hi in cells.mask],
            },
            "fingerprint": {"rva": hex(cells.site_a + 1),
                            "value": hex(cells.fingerprint)},
            "patches": [
                {
                    "name": "ngs_init_fast_success",
                    "rva": hex(cells.site_a),
                    "size": 5,
                    "expect": (bytes([cells.expect_a_first])
                               + cells.fingerprint.to_bytes(4, "little")).hex(),
                    "bytes": cells.payload_a.hex(),
                    "note": "call -> xor eax,eax + 3 nops (NGS init reports success)",
                },
                {
                    "name": "ngs_success_branch",
                    "rva": hex(cells.site_b),
                    "size": 6,
                    "expect": cells.orig_b.hex(),
                    "bytes": cells.payload_b.hex(),
                    "note": "je +0xE6 -> jmp +0xE7 + nop (always take the success path)",
                },
            ],
        }],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dll", type=Path, default=paths.DLL1)
    ap.add_argument("--client", type=Path, default=paths.CLIENT_EXE)
    ap.add_argument("--build-info", type=Path, default=paths.BUILD_INFO)
    ap.add_argument("--out", type=Path, default=None,
                    help="default: data/launcher/patches-<version>.json")
    ap.add_argument("--check", action="store_true", help="verify only, write nothing")
    args = ap.parse_args(argv)

    data, pe, instrs = decode(args.dll)
    cells = decode_cells(data, pe, instrs)
    dll_sha = sha256(args.dll)
    version = client_version(args.build_info)

    def cell(rva: int, size: int) -> str:
        off = pe.get_offset_from_rva(rva)
        return data[off:off + size].hex()

    stub_hex = cell(cells.stub_rva, cells.sig_size)
    step = "  "
    print(f"{args.dll}")
    print(f"{step}sha256 {dll_sha}")
    print(f"{args.client}  client {args.client.stat().st_size} B  version {version}")
    print(f"signature 0x{cells.sig_rva:08x}+0x{cells.sig_size:x} "
          f"mask {[f'{lo:x}-{hi:x}' for lo, hi in cells.mask]}  {stub_hex}")
    print(f"site A 0x{cells.site_a:08x}  0x{cells.expect_a_first:02x}"
          f"{cells.fingerprint.to_bytes(4, 'little').hex()} -> {cells.payload_a.hex()}"
          f"  (magic 0x{cells.fingerprint:08x} at +1)")
    print(f"site B 0x{cells.site_b:08x}  {cells.orig_b.hex()} -> {cells.payload_b.hex()}")

    problems = verify(cells, data, pe, args.client)
    if problems:
        for p in problems:
            print(f"!! {p}")
        print(f"{len(problems)} problem(s): the client does not match this Dll1")
        return 1

    if args.check:
        print("verified; --check, nothing written")
        return 0
    out = args.out or paths.LAUNCHER_DATA_DIR / f"patches-{version}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = build(cells, args.dll, dll_sha, stub_hex, args.client, version)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(paths.REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
