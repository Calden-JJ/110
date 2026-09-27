#!/usr/bin/env python3
"""Phase 0.3 probe: launch DFO.exe the way the reference launcher does, from Python.

Proves the two facts the rewrite's own launcher will depend on:

1. the endpoint travels in the command line, so a self-written launcher needs no
   endpoint patch -- ``"<client>\\DFO.exe" "99?<ip>?<port>?0?<blob>"``;
2. the two NGS patches in ``data/launcher/patches-*.json`` can be written from the
   outside while the process is suspended (no Dll1.dll, no C compiler), and they
   survive Themida's unpacking.

Pass criterion: the client boots and opens a TCP connection to the listened port.
Everything is verified against the pinned client size/SHA-256 before launch.

    python tools/launch_probe.py --dry-run          # offline check, no launch
    python tools/launch_probe.py                    # listen on 127.0.0.1:7001
    python tools/launch_probe.py --no-patch         # passport only, no NGS patch
    python tools/launch_probe.py --timeout 120 --kill
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from uslocalserver import paths  # noqa: E402

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

CREATE_SUSPENDED = 0x00000004
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
TH32CS_SNAPPROCESS = 0x00000002


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR), ("dwX", wt.DWORD), ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD), ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


kernel32.CreateProcessW.restype = wt.BOOL
kernel32.CreateProcessW.argtypes = [
    wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD,
    ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.WriteProcessMemory.restype = wt.BOOL
kernel32.VirtualProtectEx.restype = wt.BOOL
kernel32.ResumeThread.restype = wt.DWORD
kernel32.OpenProcess.restype = wt.HANDLE


def err(msg: str) -> None:
    raise SystemExit(f"[probe] {msg} (win32 {ctypes.get_last_error()})")


def dfo_pids() -> list[int]:
    """Any running DFO.exe, via a toolhelp snapshot (no psapi/no shell)."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    pids: list[int] = []
    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == "dfo.exe":
                pids.append(entry.th32ProcessID)
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return pids


def load_launch_data(client_dir: Path) -> dict:
    data = json.loads((paths.LAUNCHER_DATA_DIR / "launch-2.31.1.117.json").read_text(encoding="utf-8"))
    data["_patches"] = json.loads(
        (paths.LAUNCHER_DATA_DIR / "patches-2.31.1.117.json").read_text(encoding="utf-8"))
    data["_client_dir"] = client_dir
    return data


def verify_client(exe: Path, client: dict) -> None:
    size = exe.stat().st_size
    if size != client["size"]:
        raise SystemExit(f"[probe] 客户端大小不符：{size} != {client['size']}（需要 2.31.1.117 原版 DFO.exe）")
    digest = hashlib.sha256(exe.read_bytes()).hexdigest().upper()
    if digest != client["sha256"]:
        if digest == load_launch_data(exe.parent)["rebuilt_client"]["sha256"]:
            raise SystemExit("[probe] 这是「固定重建版」客户端（已打过 NGS 补丁），本探针不适用。")
        raise SystemExit(f"[probe] 客户端 SHA-256 不符：\n  {digest}\n  {client['sha256']}")
    print(f"[probe] 客户端校验通过：{size} B / {digest[:16]}…")


def build_passport(template: str, host: str, port: int) -> str:
    socket.inet_aton(host)  # IPv4 literal only, same rule as the reference
    if not 1 <= port <= 65535:
        raise SystemExit(f"[probe] 端口越界：{port}")
    return template.format(address=host, port=port)


def module_base(process: wt.HANDLE) -> int:
    """x64 PEB -> ImageBaseAddress (the client is not ASLR-relocated)."""
    class PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("Reserved1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)]

    ntdll = ctypes.WinDLL("ntdll")
    pbi = PROCESS_BASIC_INFORMATION()
    if ntdll.NtQueryInformationProcess(process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None) != 0:
        err("NtQueryInformationProcess 失败")
    return read_remote(process, pbi.PebBaseAddress + 0x10, 8)  # PEB.ImageBaseAddress


def read_remote(process: wt.HANDLE, addr: int, size: int) -> int:
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(process, ctypes.c_void_p(addr), buf, size, ctypes.byref(read)):
        err(f"ReadProcessMemory 0x{addr:x} 失败")
    return int.from_bytes(bytes(buf[:read.value]), "little")


def read_remote_bytes(process: wt.HANDLE, addr: int, size: int) -> bytes:
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(process, ctypes.c_void_p(addr), buf, size, ctypes.byref(read)):
        err(f"ReadProcessMemory 0x{addr:x} 失败")
    return bytes(buf[:read.value])


def write_remote(process: wt.HANDLE, addr: int, payload: bytes) -> None:
    """VirtualProtect -> write -> flush -> read back -> restore (Dll1's order)."""
    old = wt.DWORD()
    if not kernel32.VirtualProtectEx(process, ctypes.c_void_p(addr), len(payload),
                                     PAGE_EXECUTE_READWRITE, ctypes.byref(old)):
        err(f"VirtualProtectEx 0x{addr:x} 失败")
    written = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(process, ctypes.c_void_p(addr),
                                       ctypes.c_char_p(payload), len(payload), ctypes.byref(written)):
        err(f"WriteProcessMemory 0x{addr:x} 失败")
    kernel32.FlushInstructionCache(process, ctypes.c_void_p(addr), len(payload))
    if read_remote_bytes(process, addr, len(payload)) != payload:
        err(f"回读校验失败 0x{addr:x}")
    kernel32.VirtualProtectEx(process, ctypes.c_void_p(addr), len(payload), old, ctypes.byref(old))


def apply_patches(process: wt.HANDLE, base: int, module: dict) -> list[tuple[str, int, bytes]]:
    """Verify-then-write; returns [(name, addr, payload)] of the sites patched now."""
    done = []
    for patch in module["patches"]:
        addr = base + int(patch["rva"], 16)
        want = bytes.fromhex(patch["expect"])
        got = bytes.fromhex(patch["bytes"])
        live = read_remote_bytes(process, addr, patch["size"])
        if live == got:
            print(f"[probe]   {patch['name']}: 已是补丁后字节，跳过")
            continue
        if live != want:
            err(f"{patch['name']} 现场字节不匹配 0x{addr:x}："
                f"期望 {want.hex()} / 实际 {live.hex()}")
        write_remote(process, addr, got)
        print(f"[probe]   {patch['name']}: 0x{addr:x} {want.hex()} -> {got.hex()}")
        done.append((patch["name"], addr, got))
    return done


class Listener(threading.Thread):
    def __init__(self, host: str, port: int):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(4)
        self.peer: tuple | None = None
        self.first_bytes = b""

    def run(self) -> None:
        self.sock.settimeout(None)
        try:
            conn, addr = self.sock.accept()
        except OSError:
            return
        self.peer = addr
        conn.settimeout(5)
        try:
            self.first_bytes = conn.recv(64)
        except OSError:
            pass
        conn.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="DFO.exe 启动探针（Phase 0.3）")
    ap.add_argument("--client", type=Path, default=paths.CLIENT_DIR, help="客户端目录")
    ap.add_argument("--host", default="127.0.0.1", help="写进通行证的 IPv4")
    ap.add_argument("--port", type=int, default=7001, help="写进通行证 / 监听的端口")
    ap.add_argument("--timeout", type=float, default=60.0, help="等待连接的秒数")
    ap.add_argument("--no-patch", action="store_true", help="只发通行证，不打 NGS 补丁")
    ap.add_argument("--no-listen", action="store_true", help="不监听端口")
    ap.add_argument("--kill", action="store_true", help="探针结束后结束客户端")
    ap.add_argument("--dry-run", action="store_true", help="只做离线校验，不启动")
    args = ap.parse_args(argv)

    client_dir = args.client.resolve()
    exe = client_dir / "DFO.exe"
    data = load_launch_data(client_dir)
    verify_client(exe, data["client"])

    passport = build_passport(data["launch"]["passport"], args.host, args.port)
    cmdline = f'"{exe}" "{passport}"'
    print(f"[probe] 命令行：{cmdline}")

    if args.dry_run:
        print(f"[probe] 补丁数：{len(data['_patches']['modules'][0]['patches'])}，"
              f"签名 RVA {data['_patches']['modules'][0]['signature']['rva']}")
        print("[probe] --dry-run 结束（未启动）。")
        return 0

    pids = dfo_pids()
    if pids:
        raise SystemExit(f"[probe] 已有 DFO.exe 在运行：PID {pids}（参考登录器也会拒绝启动）")
    for port, label in ((args.port, "通行证/频道端口"),):
        probe = socket.socket()
        try:
            probe.bind((args.host if args.host != "0.0.0.0" else "", port))
        except OSError as e:
            raise SystemExit(f"[probe] {label} {port} 被占用：{e}")
        finally:
            probe.close()

    listener = None
    if not args.no_listen:
        listener = Listener(args.host, args.port)
        listener.start()
        print(f"[probe] 正在监听 {args.host}:{args.port}")

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    if not kernel32.CreateProcessW(str(exe), ctypes.create_unicode_buffer(cmdline), None, None,
                                   False, CREATE_SUSPENDED, None, str(client_dir),
                                   ctypes.byref(si), ctypes.byref(pi)):
        err("CreateProcessW 失败")
    print(f"[probe] 已挂起启动：PID {pi.dwProcessId}")

    patched: list[tuple[str, int, bytes]] = []
    try:
        if not args.no_patch:
            handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pi.dwProcessId)
            if not handle:
                err("OpenProcess 失败")
            base = module_base(handle)
            print(f"[probe] 映像基址 0x{base:x}（MZ={read_remote(handle, base, 2):#06x}）")
            patched = apply_patches(handle, base, data["_patches"]["modules"][0])
            kernel32.CloseHandle(handle)

        if kernel32.ResumeThread(pi.hThread) == 0xFFFFFFFF:
            err("ResumeThread 失败")
        print(f"[probe] 已恢复运行，等待最多 {args.timeout:.0f}s ...")

        deadline = time.time() + args.timeout
        while time.time() < deadline and not (listener and listener.peer):
            time.sleep(0.2)

        if listener and listener.peer:
            print(f"[probe] ✅ 收到来自 {listener.peer} 的连接，首 64B：{listener.first_bytes.hex(' ')}")
        elif listener:
            print(f"[probe] ⚠ {args.timeout:.0f}s 内没有连接（客户端是否停在窗口/报错？）")

        exit_code = wt.DWORD()
        kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
        print(f"[probe] 客户端存活：{'是' if exit_code.value == 259 else f'否（退出码 {exit_code.value}）'}")

        if patched:
            handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False,
                                          pi.dwProcessId)
            if handle:
                for name, addr, payload in patched:
                    live = read_remote_bytes(handle, addr, len(payload))
                    kept = live == payload
                    print(f"[probe]   {name} 运行期回读：{live.hex()} "
                          f"（{'补丁保持 ✅' if kept else '已被覆盖/还原 ❌'}）")
                kernel32.CloseHandle(handle)
    finally:
        if args.kill:
            kernel32.TerminateProcess(pi.hProcess, 0)
            print(f"[probe] 已结束 PID {pi.dwProcessId}")
        else:
            print(f"[probe] 客户端保持运行（要关：taskkill /PID {pi.dwProcessId} /F）")
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
