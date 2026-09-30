"""Does the 0.4.4 release accept the client that is actually installed here?

The launcher fingerprints `DFO.exe` before it will start anything, and the
0.4.4 `ClientPatch\\manifest.json` lists two `compatibleExeSha256` values.  The
rewrite's own launcher has to reproduce that gate, so this records which client
this host has and whether it is on the list -- plus what the 0.4.4 package
expects for the two injected DLLs.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from uslocalserver import paths                                     # noqa: E402

CLIENT = paths.CLIENT_EXE


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest().upper()


def main() -> int:
    print(f"root       {paths.DFO_ROOT}")
    print(f"client exe {CLIENT}  exists={CLIENT.exists()}")
    if CLIENT.exists():
        digest = sha256(CLIENT)
        print(f"  size     {CLIENT.stat().st_size:,} bytes")
        print(f"  sha256   {digest}")

    for version in ("0.3.6", "0.4.4"):
        layout = paths.for_version(version)
        print(f"\n=== {version}  {layout.root}  exists={layout.root.exists()} ===")
        for label, path in (("build-info", layout.build_info),
                            ("manifest", layout.client_patch_manifest)):
            if not path.exists():
                print(f"  {label}: absent")
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            if label == "build-info":
                print(f"  {label}: version={data.get('version')} "
                      f"built={data.get('builtUtc')}")
            else:
                allowed = [h.upper() for h in data.get("compatibleExeSha256", [])]
                print(f"  {label}: clientBuild={data.get('clientBuild')} "
                      f"version={data.get('version')}")
                for h in allowed:
                    mark = "  <-- INSTALLED CLIENT" if \
                        CLIENT.exists() and h == sha256(CLIENT) else ""
                    print(f"    allows {h}{mark}")
                for entry in data.get("files", []):
                    target = paths.CLIENT_DIR / entry["target"]
                    here = sha256(target) if target.exists() else None
                    state = "absent" if here is None else (
                        "match" if here == entry["sha256"].upper() else "DIFFERENT")
                    print(f"    file {entry['target']:<14} bytes={entry['bytes']:<8} "
                          f"installed={state}")

    # The injected DLLs sitting next to the client right now.
    print("\n=== installed client-side DLLs ===")
    for name in ("dinput8.dll", "110us.dll", "NGClient64.aes", "BlackCipher"):
        p = paths.CLIENT_DIR / name
        if p.is_file():
            print(f"  {name:<18} {p.stat().st_size:>9,} B  {sha256(p)[:16]}...")
        elif p.is_dir():
            n = sum(1 for _ in p.rglob("*") if _.is_file())
            print(f"  {name:<18} <dir, {n} files>")
        else:
            print(f"  {name:<18} absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
