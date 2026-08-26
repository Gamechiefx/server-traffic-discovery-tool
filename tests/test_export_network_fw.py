#!/usr/bin/env python3
"""Tests for FTD / NSX candidate export."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from export_network_fw import (  # noqa: E402
    build_candidates,
    load_groups,
    write_ftd,
    write_nsx,
)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.networks, self.services = load_groups(HERE / "groups.example.json")

    def test_east_west_goes_to_nsx(self):
        rows = [
            {
                "source": "10.70.40.9",
                "destination": "10.70.12.20",
                "port": "1433",
                "protocol": "tcp",
                "direction": "outbound",
                "process": "app",
                "count": "20",
                "host": "app-01",
                "first_seen": "2026-08-01T00:00:00Z",
                "last_seen": "2026-08-14T00:00:00Z",
            }
        ]
        cands = build_candidates(rows, self.networks, self.services, min_count=3)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0].source_object, "net-app")
        self.assertEqual(cands[0].dest_object, "net-sql")
        self.assertEqual(cands[0].service, "svc-mssql")
        self.assertEqual(cands[0].platform, "nsx")

    def test_user_to_ad_goes_to_ftd(self):
        rows = [
            {
                "source": "10.80.4.10",
                "destination": "10.70.1.10",
                "port": "389",
                "protocol": "tcp",
                "direction": "outbound",
                "count": "50",
                "host": "dc-01",
            }
        ]
        cands = build_candidates(rows, self.networks, self.services, min_count=3)
        self.assertEqual(cands[0].platform, "ftd")
        self.assertEqual(cands[0].service, "svc-ldap")
        self.assertEqual(cands[0].src_zone, "USERS")
        self.assertEqual(cands[0].dst_zone, "INSIDE")

    def test_listen_rows_skipped(self):
        rows = [
            {
                "source": "*",
                "destination": "0.0.0.0",
                "port": "22",
                "protocol": "tcp",
                "direction": "listen",
                "count": "100",
            }
        ]
        self.assertEqual(
            build_candidates(rows, self.networks, self.services, min_count=1), []
        )

    def test_min_count_drops_one_offs(self):
        rows = [
            {
                "source": "10.70.40.9",
                "destination": "10.70.12.20",
                "port": "1433",
                "protocol": "tcp",
                "direction": "outbound",
                "count": "2",
            }
        ]
        self.assertEqual(
            build_candidates(rows, self.networks, self.services, min_count=3), []
        )

    def test_writers(self):
        rows = [
            {
                "source": "10.70.40.9",
                "destination": "10.70.12.20",
                "port": "1433",
                "protocol": "tcp",
                "direction": "outbound",
                "count": "20",
                "host": "app-01",
            },
            {
                "source": "10.80.4.10",
                "destination": "10.70.1.10",
                "port": "389",
                "protocol": "tcp",
                "direction": "outbound",
                "count": "50",
            },
        ]
        cands = build_candidates(rows, self.networks, self.services, min_count=3)
        out = Path("/tmp/fw-export-test")
        out.mkdir(exist_ok=True)
        write_ftd(cands, out / "ftd.csv")
        write_nsx(cands, out / "nsx.json")
        ftd = (out / "ftd.csv").read_text()
        self.assertIn("svc-ldap", ftd)
        self.assertIn("net-users", ftd)
        policy = json.loads((out / "nsx.json").read_text())
        self.assertEqual(policy["resource_type"], "SecurityPolicy")
        self.assertTrue(policy["rules"])
        self.assertIn("svc-mssql", policy["rules"][0]["services"][0])


if __name__ == "__main__":
    unittest.main()
