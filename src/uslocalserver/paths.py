"""Filesystem layout of the rewrite workspace and the reference servers.

Single source of truth for every path used by the package and the tools.

Two reference trees matter and they play different roles:

* **0.3.6** (`DFO110-0.3.6\\Server`, released 2026-09) is the *oracle*.  Every
  packet-level fact in `references/protocol.md` was measured against it, and
  `data/` (crypto tables, opcode registry, `game/replies.json`, ...) was
  extracted from its exe and its `server-202609{19,25,26}.log` corpus.  The
  save fixtures -- `XRenYing Lv110`, four characters, 235 item rows -- are
  pinned to its `uslocalserver.db`.  It is kept so the measurements stay
  reproducible; nothing new is extracted from it.
* **0.4.4** (`DFO110-0.4.4\\Server`, released 2026-09-30) is the *target*.  It
  is the version the rewrite ships against: 13 channels instead of 8, five
  special-dungeon ports, a 95-table save, and an 883 MB SQLite mirror of
  `Script.pvf` under `Data\\pvf-cache\\`.  Our AOT layout notes for it live in
  `references/` and the generated assets in `data/0.4.4/`.

`LAYOUT` resolves the whole tree by version name, and `ACTIVE` selects what the
top-level constants below point at.  Overriding is therefore one variable:

    DFO_REF           <- "0.4.4" | "0.3.6", default "0.3.6"
    DFO_ROOT          <- E:\\DFO_2.31.1.117
    DFO_SERVER_DIR    <- <DFO_ROOT>/DFO110-<version>/Server      (wins over LAYOUT)
    DFO_LOGS_DIR      <- <DFO_SERVER_DIR>/Logs                   (wins over LAYOUT)
    DFO_CLIENT_DIR    <- <DFO_ROOT>
    DFO_ITEM_CONTENT_DB <- <...>/item_content_110us.db
    DFO_PVF_CACHE_DB  <- <server>/Data/pvf-cache/<sha>.db
    DFO_CORPUS_LOG    <- one capture log, replacing `CORPUS_LOGS` outright

The reference trees are read-only.  A run of the rewrite must not write into
`DFO110-*\\`; `tools/drift_save.py` is the audit that proves it did not.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
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

#: The 0.3.6 bootstrap script, bundled so a clone with no reference tree can
#: still build a database.  `BOOTSTRAP_SQL` below prefers the active release's
#: own copy when there is one -- 0.4.4's script has 95 tables to 0.3.6's 55, and
#: `migrations.py` cannot reconstruct the newer save from the older script.
BUNDLED_BOOTSTRAP_SQL = DATA_DIR / "BootstrapSchema.sql"

DFO_ROOT = Path(os.environ.get("DFO_ROOT", REPO_ROOT.parent))

#: Game client.  DFO.exe and Script.pvf sit in the repo's parent directory.
CLIENT_DIR = Path(os.environ.get("DFO_CLIENT_DIR", DFO_ROOT))
CLIENT_EXE = CLIENT_DIR / "DFO.exe"


@dataclass(frozen=True, slots=True)
class Layout:
    """One reference server release and where its pieces live.

    `dfolder` is the release folder name; `build_info` and `runtime` may be
    absent on a trimmed copy, so every accessor that needs them tolerates a
    missing file rather than raising at import time.
    """
    version: str
    dfolder: str

    @property
    def root(self) -> Path:
        return DFO_ROOT / self.dfolder

    @property
    def build_info(self) -> Path:
        return self.root / "build-info.json"

    @property
    def runtime(self) -> Path:
        return self.root / "Runtime"

    @property
    def dll1(self) -> Path:
        """The reference launcher's native hook (0.3.6 layout, kept for docs)."""
        return self.runtime / "Dll1.dll"

    @property
    def client_patch(self) -> Path:
        """0.4.4 only: the managed client-patch bundle the launcher installs."""
        return self.runtime / "ClientPatch"

    @property
    def client_patch_manifest(self) -> Path:
        return self.client_patch / "manifest.json"

    @property
    def server_dir(self) -> Path:
        return self.root / "Server"

    @property
    def exe(self) -> Path:
        return self.server_dir / "USLocalServer.Server.exe"

    @property
    def server_json(self) -> Path:
        return self.server_dir / "server.json"

    @property
    def save_db(self) -> Path:
        return self.server_dir / "uslocalserver.db"

    @property
    def bootstrap_sql(self) -> Path:
        return self.server_dir / "Schema" / "BootstrapSchema.sql"

    @property
    def logs_dir(self) -> Path:
        return self.server_dir / "Logs"

    @property
    def data_dir(self) -> Path:
        return self.server_dir / "Data"

    @property
    def item_content_db(self) -> Path:
        """The 500k-row item catalogue.  Extracted per release; not in the exe."""
        return self.data_dir / "item_content_110us.db"

    @property
    def drop_rates_json(self) -> Path:
        """0.4.4 only: a per-item drop-rate side file the GM tool rewrites."""
        return self.server_dir / "uslocalserver.db.drop-rates.json"

    def pvf_cache_db(self) -> Path | None:
        """The whole `Script.pvf` tree, as an SQLite mirror the server writes.

        0.4.4 keeps it under `Server\\Data\\pvf-cache\\<sha256>.db`; the hash is
        the PVF's own digest, so it changes when the PVF does.  Newest first --
        an older cache is left behind, not deleted.  `DFO_PVF_CACHE_DB`
        overrides.  None when the release has no cache.
        """
        override = os.environ.get("DFO_PVF_CACHE_DB")
        if override:
            return Path(override)
        cache = self.data_dir / "pvf-cache"
        if not cache.is_dir():
            return None
        files = sorted(cache.glob("*.db"),
                       key=lambda p: (p.stat().st_mtime, p.name), reverse=True)
        return files[0] if files else None

    def assets_dir(self, *, name: str | None = None) -> Path:
        """Where this release's extracted assets live under `data/`.

        The 0.3.6 assets predate the version split and stay at the top level of
        `data/` (`legacy`), because they were extracted from that exe.  0.4.4 is
        the shipped target and gets its own directory once its assets exist.
        """
        return DATA_DIR if name == "legacy" or self.version == "0.3.6" \
            else DATA_DIR / self.version


LAYOUTS: dict[str, Layout] = {
    "0.3.6": Layout("0.3.6", "DFO110-0.3.6"),
    "0.4.4": Layout("0.4.4", "DFO110-0.4.4"),
}

#: The reference the package's paths point at.
#:
#: **0.4.4 is the target.**  It is the release the rewrite ships against: 13
#: channels instead of 8, five special-dungeon ports, the 95-table save, and
#: the `pvf-cache` that replaced the exe's embedded data tables.  Its crypto is
#: byte-identical to 0.3.6's (`tools/probe_tables044.py`, `_probe_newblob.py`),
#: so the protocol layer carries over untouched.
#:
#: 0.3.6 is *retired*: the tree was deleted and only backup copies in
#: `_saveaudit/` survive.  `DFO_REF=0.3.6` still resolves the layout for
#: archaeology, but nothing defaults to it and its corpus logs are not on disk.
REFERENCE = os.environ.get("DFO_REF", "0.4.4")
if REFERENCE not in LAYOUTS:
    raise ValueError(f"DFO_REF={REFERENCE!r}; known: {sorted(LAYOUTS)}")
ACTIVE = LAYOUTS[REFERENCE]

SERVER_DIR = Path(os.environ.get("DFO_SERVER_DIR", ACTIVE.server_dir))
BUILD_INFO = ACTIVE.build_info
DLL1 = Path(os.environ.get("DFO_DLL1", ACTIVE.dll1))
LAUNCHER_DATA_DIR = DATA_DIR / "launcher"
EXE = SERVER_DIR / "USLocalServer.Server.exe"
SERVER_JSON = SERVER_DIR / "server.json"
SAVE_DB = SERVER_DIR / "uslocalserver.db"
LOGS_DIR = Path(os.environ.get("DFO_LOGS_DIR", SERVER_DIR / "Logs"))

# Separate 500k-row item catalogue, delivered outside the 69 embedded tables.
# Resolved against the *active* layout, then the historical LocalAppData spot.
ITEM_CONTENT_DB = Path(os.environ.get(
    "DFO_ITEM_CONTENT_DB",
    ACTIVE.item_content_db,
))
if not ITEM_CONTENT_DB.exists():
    _fallback = (Path(os.environ.get("LOCALAPPDATA", "")) / "USLocalServer"
                 / "Tester" / "Content" / "item_content_110us.db")
    if _fallback.exists():
        ITEM_CONTENT_DB = _fallback


def for_version(version: str) -> Layout:
    try:
        return LAYOUTS[version]
    except KeyError:
        raise KeyError(f"no layout for {version!r}; have {sorted(LAYOUTS)}") from None


# Executable file offsets holding the ordered ASCII resource manifest
# (`[u8 2*len][name]` records): names whose order is data/tables/_index.json's
# `i`, verified against 15 content anchors by tools/map_tables.py.  A scan
# window, not a record span -- the walk ends at the first `USLocalServer.Protocol.`
# name, and the previous end (0x58f3572) cut off the 69th record.
#
# 0.3.6 ONLY.  The 0.4.4 image is a different build and this offset does not
# carry over; re-locate it before running tools/map_tables.py against 0.4.4.
MANIFEST_REGION = (0x58F1050, 0x58F4000)


#: The reference logs the rewrite's data files were generated from: the
#: capture, the opcode registry and the game script, one consistent set.
#: Later reference runs are deliberately not swept in -- widening the scan to
#: `server-20260927.log` was measured to add zero opcodes and only churn every
#: pinned count.  Widening the evidence base is a regenerate-and-re-pin.
#:
#: These are 0.3.6 files.  That tree has been retired, so on a 0.4.4-only host
#: `corpus_logs()` comes back empty and anything that counts on it has to say
#: so rather than read zeroes (`tests/_bootstrap.require_corpus`).
CORPUS_LOGS = ("server-20260919.log", "server-20260925.log", "server-20260926.log")

#: Names the corpus when the tree that held it is gone, the way `DFO_LOGS_DIR`
#: names a whole directory.  Single file, because that is the unit the suite was
#: measured in (`tests/_bootstrap`).
CORPUS_LOG_ENV = "DFO_CORPUS_LOG"


def corpus_override() -> Path | None:
    """`DFO_CORPUS_LOG`, when it names a file that is actually there."""
    raw = os.environ.get(CORPUS_LOG_ENV)
    if not raw:
        return None
    path = Path(raw)
    return path if path.exists() else None


def server_logs() -> list[Path]:
    return sorted(LOGS_DIR.glob("server-*.log"))


def corpus_logs() -> list[Path]:
    """The corpus logs that actually exist here, in declared order.

    `DFO_CORPUS_LOG` replaces the set outright rather than adding to it: it is
    how a host with no 0.3.6 tree (every host, now) points the corpus-dependent
    tests at whatever capture it does have.
    """
    override = corpus_override()
    if override:
        return [override]
    return [LOGS_DIR / name for name in CORPUS_LOGS if (LOGS_DIR / name).exists()]


def missing_corpus_logs() -> list[Path]:
    """The declared corpus files this host does not have."""
    if corpus_override():
        return []
    return [LOGS_DIR / name for name in CORPUS_LOGS if not (LOGS_DIR / name).exists()]


def launcher_logs() -> list[Path]:
    return sorted(LOGS_DIR.glob("launcher-*.log"))


def latest_server_log() -> Path:
    logs = server_logs()
    if not logs:
        raise FileNotFoundError(f"no server-*.log under {LOGS_DIR}")
    return logs[-1]


def bootstrap_sql() -> Path:
    """The active tree's `BootstrapSchema.sql`, falling back to the bundled copy.

    `data/BootstrapSchema.sql` is the 0.3.6 script and stays bundled so a clone
    with no reference tree can still build a database; a 0.4.4 run prefers the
    release's own schema.
    """
    candidate = SERVER_DIR / "Schema" / "BootstrapSchema.sql"
    return candidate if candidate.exists() else BUNDLED_BOOTSTRAP_SQL


#: Resolved once at import, the way `EXE`/`SAVE_DB` are.
BOOTSTRAP_SQL = bootstrap_sql()


def missing_reference() -> list[str]:
    """What is absent from the active reference tree, for a doctor command.

    Returns human-readable lines; empty means the tree is complete enough for
    the test suite.  Kept here so a fresh clone can say what it needs instead
    of failing 200 tests with `no such table`.
    """
    out = []
    for label, path in (
        ("server exe", EXE),
        ("server.json", SERVER_JSON),
        ("save database", SAVE_DB),
        ("BootstrapSchema.sql", BOOTSTRAP_SQL),
        ("item catalogue", ITEM_CONTENT_DB),
    ):
        if not path.exists():
            out.append(f"{label}: {path}")
    for name in CORPUS_LOGS:
        if not (LOGS_DIR / name).exists():
            out.append(f"corpus log: {LOGS_DIR / name}")
    return out
