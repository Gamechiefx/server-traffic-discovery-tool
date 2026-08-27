#!/usr/bin/env python3
"""Parser tests for source/destination/port conversion."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from convert import convert_text, detect_format, ephemeral_floor, split_endpoint  # noqa: E402


SS_SAMPLE = """
Netid State Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*         users:(("sshd",pid=1,fd=3))
tcp   ESTAB  0      0      10.70.12.20:22      10.70.1.50:51234  users:(("sshd",pid=88,fd=4))
tcp   ESTAB  0      0      10.70.12.20:54321   10.70.1.10:389    users:(("sssd",pid=9,fd=5))
tcp   ESTAB  0      0      127.0.0.1:54322     127.0.0.1:54323   users:(("python3",pid=2,fd=6))
"""

NETSTAT_SAMPLE = """
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      1/smbd
tcp        0      0 10.70.12.20:445         10.70.8.12:49876        ESTABLISHED 1/smbd
"""

TCPDUMP_SAMPLE = """
12:00:01.123456 IP 10.70.12.20.54321 > 10.70.1.10.389: Flags [P.], seq 1:20, ack 1, win 64, length 19
12:00:01.223456 IP 10.70.1.10.389 > 10.70.12.20.54321: Flags [.], ack 20, win 64, length 0
"""

PFW_SAMPLE = """
#Version: 1.5
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
2026-08-26 17:00:01 ALLOW TCP 10.70.12.20 10.70.1.10 54321 389 0 - 0 0 0 - - - SEND
2026-08-26 17:00:02 ALLOW TCP 10.70.1.50 10.70.12.20 51234 22 0 - 0 0 0 - - - RECEIVE
"""

WIN_CSV = """CreationTime,State,LocalAddress,LocalPort,RemoteAddress,RemotePort,PID,Process
2026-08-26T17:00:00,Listen,0.0.0.0,1433,0.0.0.0,0,100,sqlservr
2026-08-26T17:00:01,Established,10.70.12.20,1433,10.70.40.9,60001,100,sqlservr
"""

CONNTRACK_SAMPLE = """
tcp      6 431999 ESTABLISHED src=10.70.12.20 dst=10.70.1.10 sport=54321 dport=389 packets=10 bytes=800
"""


class SplitEndpointTests(unittest.TestCase):
    def test_ipv4_colon(self):
        self.assertEqual(split_endpoint("10.70.12.20:445"), ("10.70.12.20", "445"))

    def test_ipv6_brackets(self):
        self.assertEqual(split_endpoint("[fe80::1]:22"), ("fe80::1", "22"))

    def test_tcpdump_dot_port(self):
        self.assertEqual(split_endpoint("10.70.1.10.389"), ("10.70.1.10", "389"))

    def test_star(self):
        self.assertEqual(split_endpoint("*"), ("*", "*"))

    def test_ipv4_mapped_ipv6(self):
        self.assertEqual(split_endpoint("[::ffff:10.70.70.86]:22"), ("10.70.70.86", "22"))

    def test_bare_wildcard_ipv6_listen(self):
        self.assertEqual(split_endpoint(":::22"), ("::", "22"))

    def test_ipv6_loopback_not_split(self):
        self.assertEqual(split_endpoint("::1"), ("::1", "*"))


class ConvertTests(unittest.TestCase):
    def _rows(self, text, **kwargs):
        store = convert_text(text, **kwargs)
        return {(f.source, f.destination, f.port, f.protocol, f.direction): f for f in store.rows()}

    def test_detect_ss(self):
        self.assertEqual(detect_format(SS_SAMPLE), "ss")

    def test_udp_unconn_listen_and_connected_outbound(self):
        text = (
            "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n"
            "udp ESTAB 0 0 10.70.70.86:51000 10.70.70.77:123\n"
            "udp UNCONN 0 0 10.70.70.86:51001 10.70.70.77:123\n"
        )
        rows = self._rows(text, host_ips={"10.70.70.86"})
        self.assertIn(("*", "0.0.0.0", "53", "udp", "listen"), rows)
        self.assertIn(("10.70.70.86", "10.70.70.77", "123", "udp", "outbound"), rows)

    def test_estab_only_uses_ephemeral_heuristic(self):
        text = "tcp ESTAB 0 0 10.70.12.20:22 10.70.1.50:51234\n"
        rows = self._rows(text, host_ips={"10.70.12.20"})
        self.assertIn(("10.70.1.50", "10.70.12.20", "22", "tcp", "inbound"), rows)

    def test_linux_ephemeral_range_outbound_not_flipped(self):
        floor = ephemeral_floor()
        text = f"tcp ESTAB 0 0 10.70.12.20:{floor + 1} 10.70.1.10:50000\n"
        rows = self._rows(text, host_ips={"10.70.12.20"})
        self.assertIn(("10.70.12.20", "10.70.1.10", "50000", "tcp", "outbound"), rows)

    def test_ephemeral_floor_reads_proc_range(self):
        with mock.patch("convert._ephemeral_floor", None), mock.patch(
            "convert.Path"
        ) as path_cls:
            path_cls.return_value.read_text.return_value = "  32768   60999 \n"
            self.assertEqual(ephemeral_floor(), 32768)
        with mock.patch("convert._ephemeral_floor", None):
            self.assertGreaterEqual(ephemeral_floor(), 1024)

    def test_ss_listen_and_directions(self):
        rows = self._rows(SS_SAMPLE, host_ips={"10.70.12.20"})
        self.assertIn(("*", "0.0.0.0", "22", "tcp", "listen"), rows)
        inbound = rows[("10.70.1.50", "10.70.12.20", "22", "tcp", "inbound")]
        self.assertEqual(inbound.process, "sshd")
        outbound = rows[("10.70.12.20", "10.70.1.10", "389", "tcp", "outbound")]
        self.assertEqual(outbound.process, "sssd")
        loopbacks = [r for r in rows if "127.0.0.1" in (r[0], r[1])]
        self.assertEqual(loopbacks, [])

    def test_ss_dedupes_counts(self):
        store = convert_text(SS_SAMPLE, host_ips={"10.70.12.20"})
        convert_text(SS_SAMPLE, host_ips={"10.70.12.20"}, store=store)
        outbound = [
            f for f in store.rows() if f.destination == "10.70.1.10" and f.port == "389"
        ][0]
        self.assertEqual(outbound.count, 2)

    def test_netstat(self):
        rows = self._rows(NETSTAT_SAMPLE)
        self.assertIn(("*", "0.0.0.0", "445", "tcp", "listen"), rows)
        self.assertIn(("10.70.8.12", "10.70.12.20", "445", "tcp", "inbound"), rows)

    def test_netstat_tcp6_listen(self):
        text = "tcp6       0      0 :::22                   :::*                    LISTEN      1234/sshd\n"
        rows = self._rows(text)
        self.assertIn(("*", "::", "22", "tcp", "listen"), rows)

    def test_netstat_bsd_tcp4_dotted_endpoints(self):
        text = "tcp4       0      0 10.0.0.5.22             10.0.0.9.51000          ESTABLISHED\n"
        rows = self._rows(text, host_ips={"10.0.0.5"})
        self.assertIn(("10.0.0.9", "10.0.0.5", "22", "tcp", "inbound"), rows)

    def test_tcpdump_uses_packet_dst_port(self):
        rows = self._rows(TCPDUMP_SAMPLE, host_ips={"10.70.12.20"})
        self.assertIn(("10.70.12.20", "10.70.1.10", "389", "tcp", "outbound"), rows)
        self.assertIn(("10.70.1.10", "10.70.12.20", "54321", "tcp", "inbound"), rows)

    def test_pfirewall(self):
        self.assertEqual(detect_format(PFW_SAMPLE), "pfirewall")
        rows = self._rows(PFW_SAMPLE, host_ips={"10.70.12.20"})
        self.assertIn(("10.70.12.20", "10.70.1.10", "389", "tcp", "outbound"), rows)
        self.assertIn(("10.70.1.50", "10.70.12.20", "22", "tcp", "inbound"), rows)

    def test_win_csv(self):
        self.assertEqual(detect_format(WIN_CSV), "win_csv")
        rows = self._rows(WIN_CSV)
        self.assertIn(("*", "0.0.0.0", "1433", "tcp", "listen"), rows)
        inbound = rows[("10.70.40.9", "10.70.12.20", "1433", "tcp", "inbound")]
        self.assertEqual(inbound.process, "sqlservr")

    def test_conntrack(self):
        self.assertEqual(detect_format(CONNTRACK_SAMPLE), "conntrack")
        rows = self._rows(CONNTRACK_SAMPLE, host_ips={"10.70.12.20"})
        self.assertIn(("10.70.12.20", "10.70.1.10", "389", "tcp", "outbound"), rows)

    def test_flows_csv_strips_ipv4_mapped(self):
        text = (
            "source,destination,port,protocol,direction,count\n"
            "::ffff:10.30.30.111,::ffff:10.70.70.86,22,tcp,inbound,3\n"
        )
        rows = self._rows(text, fmt="flows")
        self.assertIn(("10.30.30.111", "10.70.70.86", "22", "tcp", "inbound"), rows)

    def test_flows_merge(self):
        first = convert_text(SS_SAMPLE, host_ips={"10.70.12.20"})
        from convert import CSV_FIELDS
        import io, csv
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
        writer.writeheader()
        from dataclasses import asdict
        for flow in first.rows():
            writer.writerow(asdict(flow))
        merged = convert_text(buf.getvalue(), fmt="flows")
        convert_text(buf.getvalue(), fmt="flows", store=merged)
        outbound = [f for f in merged.rows() if f.port == "389"][0]
        self.assertEqual(outbound.count, 2)


if __name__ == "__main__":
    unittest.main()
