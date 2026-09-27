"""Shim: the suite moved into the package as `uslocalserver.protocol.crypto`.

Kept so the probes in this directory (`verify_gold.py`, `*_probe.py`,
`*_trace.py`, `aes_bcrypt_check.py`) keep importing `dfo_ciphers` by name with
no edit -- those unchanged imports *are* the regression test for the move.
The tables under `data/crypto/` did not move; they are data, not code.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uslocalserver.protocol import crypto as _crypto  # noqa: E402

globals().update({k: v for k, v in vars(_crypto).items() if not k.startswith("__")})

if __name__ == "__main__":
    raise SystemExit(_crypto.selftest())
