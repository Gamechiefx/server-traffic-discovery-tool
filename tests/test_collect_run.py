#!/usr/bin/env python3
"""Tests for persistent collection windows."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from collect import load_run, resolve_deadline  # noqa: E402


class RunWindowTests(unittest.TestCase):
    def test_creates_and_keeps_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            first = resolve_deadline(out, days=14, interval=60, force=False)
            again = resolve_deadline(out, days=1, interval=30, force=False)
            self.assertEqual(first, again)
            run = load_run(out)
            self.assertEqual(run["interval"], 60)
            self.assertGreater(first, datetime.now(timezone.utc) + timedelta(days=13))

    def test_force_replaces_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            first = resolve_deadline(out, days=14, interval=60, force=False)
            second = resolve_deadline(out, days=1, interval=60, force=True)
            self.assertLess(second, first)


if __name__ == "__main__":
    unittest.main()
