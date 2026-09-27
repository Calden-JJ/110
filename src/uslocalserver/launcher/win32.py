"""Win32 pieces the launcher needs, in ctypes only.

The reference launcher does its work with a native DLL (`Runtime\\Dll1.dll`)
mapped into the game process.  Nothing here needs that: the only writes are two
patches at fixed RVAs, and `WriteProcessMemory` reaches them just as well.  The
call order in `write_remote` (protect -> write -> flush -> read back -> restore)
is the one Dll1 documents in its status log.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import socket
from dataclasses import dataclass
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

CREATE_SUSPENDED = 0x00000004
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PAGE_EXECUTE_READWRITE = 0x40
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
TH32CS_SNAPPROCESS = 0x00000002
STILL_ACTIVE = 259
AF_INET = 2
TCP_TABLE_OWNER_PID_LISTENER = 3


class Win32Error(OSError):
    """A failed call, with the Win32 text appended to the Chinese message."""


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


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD),
                ("dwRemoteAddr", wt.DWORD), ("dwRemotePort", wt.DWORD),
                ("dwOwningPid", wt.DWORD)]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwNumEntries", wt.DWORD), ("table", MIB_TCPROW_OWNER_PID * 1)]


kernel32.CreateProcessW.restype = wt.BOOL
kernel32.CreateProcessW.argtypes = [
    wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD,
    ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.WriteProcessMemory.restype = wt.BOOL
kernel32.VirtualProtectEx.restype = wt.BOOL
kernel32.ResumeThread.restype = wt.DWORD
kernel32.TerminateProcess.restype = wt.BOOL
kernel32.GetExitCodeProcess.restype = wt.BOOL
iphlpapi.GetExtendedTcpTable.restype = wt.DWORD


def _fail(what: str) -> Win32Error:
    code = ctypes.get_last_error()
    text = ctypes.FormatError(code).strip()
    return Win32Error(f"{what} 失败：{text}（错误码 {code}）")


def last_error_text(code: int) -> str:
    return ctypes.FormatError(code).strip()


@dataclass
class Process:
    """A suspended-then-resumed child; close() is safe to call twice."""

    handle: int
    thread: int
    pid: int

    def resume(self) -> None:
        if kernel32.ResumeThread(self.thread) == 0xFFFFFFFF:
            raise _fail("ResumeThread")

    def alive(self) -> bool:
        code = wt.DWORD()
        if not kernel32.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            raise _fail("GetExitCodeProcess")
        return code.value == STILL_ACTIVE

    def terminate(self) -> None:
        kernel32.TerminateProcess(self.handle, 0)

    def close(self) -> None:
        for h in (self.thread, self.handle):
            if h:
                kernel32.CloseHandle(h)
        self.thread = self.handle = 0


def create_suspended(exe: Path, cmdline: str, cwd: Path) -> Process:
    """`CreateProcessW` with the command line the reference builds.

    The buffer is mutable on purpose: the API is allowed to write to
    `lpCommandLine`, and a `str` would hand it read-only memory.
    """
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    if not kernel32.CreateProcessW(str(exe), ctypes.create_unicode_buffer(cmdline), None,
                                   None, False, CREATE_SUSPENDED, None, str(cwd),
                                   ctypes.byref(si), ctypes.byref(pi)):
        raise _fail("CreateProcessW")
    return Process(pi.hProcess, pi.hThread, pi.dwProcessId)


def open_process(pid: int, access: int = PROCESS_ALL_ACCESS) -> int:
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        raise _fail(f"OpenProcess(PID {pid})")
    return handle


def close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(handle)


def image_base(process_handle: int) -> int:
    """PEB -> ImageBaseAddress; works whether or not the exe is ASLR'd."""
    class PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("Reserved1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)]

    pbi = PROCESS_BASIC_INFORMATION()
    if ntdll.NtQueryInformationProcess(process_handle, 0, ctypes.byref(pbi),
                                       ctypes.sizeof(pbi), None) != 0:
        raise _fail("NtQueryInformationProcess")
    return read_u64(process_handle, pbi.PebBaseAddress + 0x10)


def read_bytes(process_handle: int, addr: int, size: int) -> bytes:
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(addr), buf, size,
                                      ctypes.byref(read)) or read.value != size:
        raise _fail(f"ReadProcessMemory 0x{addr:x}")
    return bytes(buf)


def read_u64(process_handle: int, addr: int) -> int:
    return int.from_bytes(read_bytes(process_handle, addr, 8), "little")


def write_remote(process_handle: int, addr: int, payload: bytes) -> None:
    """VirtualProtect -> write -> flush -> read back -> restore protection."""
    old = wt.DWORD()
    if not kernel32.VirtualProtectEx(process_handle, ctypes.c_void_p(addr), len(payload),
                                     PAGE_EXECUTE_READWRITE, ctypes.byref(old)):
        raise _fail(f"VirtualProtectEx 0x{addr:x}")
    written = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(process_handle, ctypes.c_void_p(addr),
                                       ctypes.c_char_p(payload), len(payload),
                                       ctypes.byref(written)):
        raise _fail(f"WriteProcessMemory 0x{addr:x}")
    kernel32.FlushInstructionCache(process_handle, ctypes.c_void_p(addr), len(payload))
    back = read_bytes(process_handle, addr, len(payload))
    kernel32.VirtualProtectEx(process_handle, ctypes.c_void_p(addr), len(payload), old,
                              ctypes.byref(old))
    if back != payload:
        raise Win32Error(f"回读校验失败 0x{addr:x}：写入 {payload.hex()}，读回 {back.hex()}")


def process_ids_by_name(exe_name: str) -> list[int]:
    """Toolhelp snapshot, so no shell and no psapi dependency."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    pids: list[int] = []
    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if str(entry.szExeFile).lower() == exe_name.lower():
                pids.append(entry.th32ProcessID)
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return pids


def process_name(pid: int) -> str:
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return "?"
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.th32ProcessID == pid:
                return str(entry.szExeFile)
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return "?"


def tcp_listener_pids(port: int) -> list[int]:
    """PIDs owning a listening socket on `port` (IPv4)."""
    size = wt.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET,
                                 TCP_TABLE_OWNER_PID_LISTENER, 0)
    buf = (ctypes.c_char * size.value)()
    if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET,
                                    TCP_TABLE_OWNER_PID_LISTENER, 0) != 0:
        return []
    table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
    rows = ctypes.cast(ctypes.byref(table.table),
                       ctypes.POINTER(MIB_TCPROW_OWNER_PID * table.dwNumEntries)).contents
    want = socket.htons(port)  # dwLocalPort keeps the port in network order
    return [row.dwOwningPid for row in rows if row.dwLocalPort & 0xFFFF == want]
