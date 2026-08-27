#!/usr/bin/env python3
"""Tests for daily ship path layout (no network)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from ship import remote_layout, split_ssh_dest, stage_files, utc_day  # noqa: E402


class ShipTests(unittest.TestCase):
    def test_remote_layout(self):
        latest, daily = remote_layout("sql-03", "20260826")
        self.assertEqual(latest, "sql-03/flows.csv")
        self.assertEqual(daily, "sql-03/daily/20260826.csv")

    def test_split_ssh_dest(self):
        host, path = split_ssh_dest("fwship@central.example.com:/data/fw-baseline")
        self.assertEqual(host, "fwship@central.example.com")
        self.assertEqual(path, "/data/fw-baseline")

    def test_stage_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            stage = Path(tmp) / "stage"
            data.mkdir()
            (data / "flows.csv").write_text("source,destination,port\n")
            (data / "run.json").write_text("{}\n")
            host_dir = stage_files(data, stage, "sql-03", "20260826")
            self.assertTrue((host_dir / "flows.csv").exists())
            self.assertTrue((host_dir / "daily" / "20260826.csv").exists())
            self.assertTrue((host_dir / "run.json").exists())

    def test_utc_day_format(self):
        self.assertRegex(utc_day(), r"^\d{8}$")


if __name__ == "__main__":
    unittest.main()
