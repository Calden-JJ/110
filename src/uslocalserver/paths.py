"""Filesystem layout of the rewrite workspace and the reference server.

Single source of truth for every path used by the package and the tools.
Overridable for machines where the game is installed elsewhere:

    DFO_ROOT        <- E:\\DFO_2.31.1.117
    DFO_SERVER_DIR  <- <DFO_ROOT>/DFO110-0.3.6/Server
    DFO_LOGS_DIR    <- <DFO_SERVER_DIR>/Logs
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
TOOLS_DIR = REPO_ROOT / "tools"
TESTS_DIR = REPO_ROOT / "tests"

DATA_DIR = REPO_ROOT / "data"
TABLES_DIR = DATA_DIR / "tables"
TABLES_INDEX = TABLES_DIR / "_index.json"
TABLES_NAMES = TABLES_DIR / "_names.json"
TABLE_MAP = TABLES_DIR / "_table_map.json"
GEN_MODELS_SKIPPED = TABLES_DIR / "_gen_models_skipped.json"
GAME_DATA_DIR = SRC_DIR / "uslocalserver" / "game" / "data"
CRYPTO_TABLES = DATA_DIR / "crypto"
PROTOCOL_DIR = DATA_DIR / "protocol"
OPCODES_JSON = PROTOCOL_DIR / "opcodes.json"
BOOTSTRAP_SQL = DATA_DIR / "BootstrapSchema.sql"

DFO_ROOT = Path(os.environ.get("DFO_ROOT", REPO_ROOT.parent))
SERVER_DIR = Path(os.environ.get("DFO_SERVER_DIR", DFO_ROOT / "DFO110-0.3.6" / "Server"))

#: Game client.  DFO.exe and Script.pvf sit in the repo's parent directory;
#: `Runtime\Dll1.dll` is the reference launcher's native hook, which carries
#: the client-side patches the rewrite's own launcher has to reproduce.
CLIENT_DIR = Path(os.environ.get("DFO_CLIENT_DIR", DFO_ROOT))
CLIENT_EXE = CLIENT_DIR / "DFO.exe"
BUILD_INFO = DFO_ROOT / "DFO110-0.3.6" / "build-info.json"
DLL1 = Path(os.environ.get("DFO_DLL1", DFO_ROOT / "DFO110-0.3.6" / "Runtime" / "Dll1.dll"))
LAUNCHER_DATA_DIR = DATA_DIR / "launcher"
EXE = SERVER_DIR / "USLocalServer.Server.exe"
SERVER_JSON = SERVER_DIR / "server.json"
SAVE_DB = SERVER_DIR / "uslocalserver.db"
LOGS_DIR = Path(os.environ.get("DFO_LOGS_DIR", SERVER_DIR / "Logs"))

# Separate 500k-row item catalogue, delivered outside the 69 embedded tables.
ITEM_CONTENT_DB = Path(os.environ.get(
    "DFO_ITEM_CONTENT_DB",
    Path(os.environ.get("LOCALAPPDATA", "")) / "USLocalServer" / "Tester" / "Content" / "item_content_110us.db",
))

# Executable file offsets holding the ordered ASCII resource manifest
# (`[u8 2*len][name]` records): 69 names whose order is data/tables/_index.json's
# `i`, verified against 15 content anchors by tools/map_tables.py.  A scan
# window, not a record span -- the walk ends at the first `USLocalServer.Protocol.`
# name, and the previous end (0x58f3572) cut off the 69th record.
MANIFEST_REGION = (0x58F1050, 0x58F4000)


#: The reference logs the rewrite's data files were generated from: the
#: capture, the opcode registry and the game script, one consistent set.
#: Later reference runs are deliberately not swept in -- widening the scan to
#: `server-20260927.log` was measured to add zero opcodes and only churn every
#: pinned count.  Widening the evidence base is a regenerate-and-re-pin.
CORPUS_LOGS = ("server-20260919.log", "server-20260925.log", "server-20260926.log")


def server_logs() -> list[Path]:
    return sorted(LOGS_DIR.glob("server-*.log"))


def corpus_logs() -> list[Path]:
    return [LOGS_DIR / name for name in CORPUS_LOGS]


def launcher_logs() -> list[Path]:
    return sorted(LOGS_DIR.glob("launcher-*.log"))


def latest_server_log() -> Path:
    logs = server_logs()
    if not logs:
        raise FileNotFoundError(f"no server-*.log under {LOGS_DIR}")
    return logs[-1]
