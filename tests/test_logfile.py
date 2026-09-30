"""A new session must not destroy the previous session's log.

The 2026-09-29 client session that reported `赛利亚房间下方出不去` was the only
record of it, and the 09-30 start truncated the file away.  Rotation is the
fix; these tests pin it -- including the half-fix where the rename itself
fails because the previous session's writer still holds the file open.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _bootstrap  # noqa: F401

from uslocalserver.server.logfile import Log


class RotationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "server-rewrite.log"

    def test_the_previous_session_is_renamed_not_truncated(self) -> None:
        self.path.write_text("old session\n", encoding="utf-8")
        with Log(self.path) as log:
            log.info("TEST", "new session")
        rotated = list(self.path.parent.glob("server-rewrite-*.log"))
        self.assertEqual(1, len(rotated))
        self.assertEqual("old session\n", rotated[0].read_text(encoding="utf-8"))
        self.assertIn("new session", self.path.read_text(encoding="utf-8"))

    def test_an_absent_or_empty_log_rotates_nothing(self) -> None:
        with Log(self.path):
            pass
        self.assertEqual([], list(self.path.parent.glob("server-rewrite-*.log")))
        self.path.write_text("", encoding="utf-8")
        with Log(self.path):
            pass
        self.assertEqual([], list(self.path.parent.glob("server-rewrite-*.log")))

    def test_a_rename_that_fails_leaves_the_held_log_alone(self) -> None:
        """The rename fails exactly while a writer still holds the file, so
        the fallback is the case that matters: the new session takes a `+`
        name and the old file keeps every line."""
        self.path.write_text("held session\n", encoding="utf-8")
        real = Path.rename

        def held(self2: Path, target: Path) -> Path:
            if self2 == self.path:
                raise OSError(13, "held open")
            return real(self2, target)

        with mock.patch.object(Path, "rename", held):
            with Log(self.path) as log:
                log.info("TEST", "new session")
        self.assertEqual("held session\n", self.path.read_text(encoding="utf-8"))
        self.assertEqual([], list(self.path.parent.glob("server-rewrite-*.log")))
        live = list(self.path.parent.glob("server-rewrite+*.log"))
        self.assertEqual(1, len(live))
        self.assertIn("new session", live[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
