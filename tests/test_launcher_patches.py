"""The launcher's patch layer: the JSON it reads, and verify-then-write for real.

`apply()`/`verify_still_applied()` are exercised against a suspended child of
`sys.executable` -- the same Win32 path a launch takes (CreateProcessW ->
OpenProcess -> VirtualProtectEx -> WriteProcessMemory -> read back), without
needing the 212 MB client.  The planted site is read out of the live image
first, so nothing here depends on any particular build of the target.
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import _bootstrap  # noqa: F401

from uslocalserver.launcher import client, patches, win32

#: The golden site, as `tools/extract_launcher_patches.py` read it out of
#: `Dll1.dll`.  The probe of 2026-09-27 wrote exactly these bytes in a live
#: client (PID 27700), so pinning the literals guards the JSON against edits.
GOLDEN_SITES = {
    "ngs_init_fast_success": (0x497563D, "e8ee370efe", "31c0909090"),
    "ngs_success_branch": (0x497564A, "0f84e6000000", "e9e700000090"),
}


class TestPatchData(unittest.TestCase):
    def test_reads_the_two_sites(self):
        ps = patches.load()
        self.assertEqual(ps.version, "2.31.1.117")
        self.assertEqual([m.name for m in ps.modules], ["ngs_startup_compat"])
        self.assertEqual(len(ps.sites), 2)
        for site in ps.sites:
            rva, expect, payload = GOLDEN_SITES[site.name]
            self.assertEqual(site.rva, rva)
            self.assertEqual(site.expect.hex(), expect)
            self.assertEqual(site.payload.hex(), payload)
            self.assertEqual(site.size, len(site.payload))

    def test_client_fingerprint_agrees_with_the_launch_data(self):
        ps = patches.load()
        data = client.launch_data()
        self.assertEqual(ps.client_size, data.client_size)
        self.assertEqual(ps.client_sha256.upper(), data.client_sha256)

    def test_missing_version_file(self):
        with self.assertRaises(patches.PatchError) as ctx:
            patches.load("0.0.0.000")
        self.assertIn("缺少补丁数据文件", str(ctx.exception))

    def test_default_path_is_versioned(self):
        self.assertEqual(patches.default_path("1.2.3").name, "patches-1.2.3.json")

    def test_self_contradictory_file_is_refused(self):
        raw = json.loads(patches.default_path("2.31.1.117").read_text(encoding="utf-8"))
        raw["modules"][0]["patches"][0]["size"] = 4  # payload is 5 bytes long
        with _temp_patch_file(raw) as path:
            with self.assertRaises(patches.PatchError) as ctx:
                patches.load()
            self.assertIn("自相矛盾", str(ctx.exception))
            self.assertEqual(path.name, "patches-2.31.1.117.json")


class _temp_patch_file:
    """Serve one patched JSON as if it were `data/launcher/patches-<v>.json`."""

    def __init__(self, raw: dict):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "patches-2.31.1.117.json"
        self.path.write_text(json.dumps(raw), encoding="utf-8")

    def __enter__(self) -> Path:
        self._patcher = mock.patch.object(patches, "default_path", return_value=self.path)
        self._patcher.start()
        return self.path

    def __exit__(self, *exc) -> None:
        self._patcher.stop()
        self._tmp.cleanup()


def _size_of_image(handle: int, base: int) -> int:
    """NT headers: e_lfanew at +0x3C, SizeOfImage at +0x50 past the signature."""
    e_lfanew = int.from_bytes(win32.read_bytes(handle, base + 0x3C, 4), "little")
    return int.from_bytes(win32.read_bytes(handle, base + e_lfanew + 0x50, 4), "little")


@unittest.skipUnless(sys.platform == "win32", "Win32 process writes are Windows-only")
class TestRemoteWrite(unittest.TestCase):
    #: Inside the first section of any normal image, and far below SizeOfImage.
    RVA = 0x2000

    def setUp(self):
        exe = Path(sys.executable)
        self.proc = win32.create_suspended(
            exe, f'"{exe}" -c "import time; time.sleep(60)"', exe.parent)
        self.addCleanup(self.proc.close)
        self.addCleanup(self.proc.terminate)
        self.handle = win32.open_process(self.proc.pid)
        self.addCleanup(win32.close_handle, self.handle)

    def _one_site_set(self, site: patches.Site) -> patches.PatchSet:
        return patches.PatchSet("test", 0, "", (patches.Module("test", (site,)),))

    def test_apply_verify_and_refuse(self):
        base = win32.image_base(self.handle)
        self.assertEqual(win32.read_bytes(self.handle, base, 2), b"MZ")
        self.assertLess(self.RVA, _size_of_image(self.handle, base))
        self.assertTrue(self.proc.alive())

        original = win32.read_bytes(self.handle, base + self.RVA, 6)
        payload = bytes(b ^ 0xFF for b in original)
        ps = self._one_site_set(patches.Site("smoke", self.RVA, original, payload))

        applied = patches.apply(self.handle, base, ps)
        self.assertEqual([a.address for a in applied], [base + self.RVA])
        self.assertEqual(win32.read_bytes(self.handle, base + self.RVA, 6), payload)
        self.assertEqual(patches.verify_still_applied(self.handle, applied), [])
        self.assertEqual(patches.apply(self.handle, base, ps), [],
                         "already-patched sites must be a no-op, not an error")

        wrong = bytes(b ^ 0x5A for b in original)
        bad = self._one_site_set(patches.Site(
            "bad", self.RVA, wrong, bytes(b ^ 0x33 for b in payload)))
        with self.assertRaises(patches.PatchError) as ctx:
            patches.apply(self.handle, base, bad)
        self.assertIn("版本不匹配", str(ctx.exception))
        self.assertEqual(win32.read_bytes(self.handle, base + self.RVA, 6), payload,
                         "a refused patch must not have written anything")

    def test_toolhelp_lookup_and_terminate(self):
        name = Path(sys.executable).name
        self.assertIn(self.proc.pid, win32.process_ids_by_name(name))
        self.assertEqual(win32.process_name(self.proc.pid).lower(), name.lower())

        self.proc.terminate()
        deadline = time.monotonic() + 5
        while self.proc.alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(self.proc.alive())
        self.proc.close()
        self.proc.close()  # documented as safe to call twice


if __name__ == "__main__":
    unittest.main()
