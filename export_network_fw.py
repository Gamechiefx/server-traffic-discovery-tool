#!/usr/bin/env python3
"""Collapse host flows into candidate FTD and NSX firewall rules.

Reads the source/destination/port CSV from the collectors. Maps IPs to
network objects and ports to service objects. East-west pairs (both sides
in NSX-scoped networks) become NSX DFW candidates. North-south or
FTD-scoped pairs become FTD access-control candidates.

This writes review files only. It does not push policy to FMC or NSX.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


SKIP_SOURCES = {"*", ""}
SKIP_DESTS = {"*", "", "0.0.0.0", "::"}


@dataclass
class NetworkObj:
    name: str
    cidrs: list
    platform: str = "both"
    ftd_zone: str = ""

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.cidrs)


@dataclass
class ServiceObj:
    name: str
    protocol: str
    port: str


@dataclass
class Candidate:
    source_object: str
    dest_object: str
    service: str
    protocol: str
    port: str
    platform: str
    src_zone: str = ""
    dst_zone: str = ""
    count: int = 0
    hosts: set = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    processes: set = field(default_factory=set)


def load_groups(path: Optional[Path]) -> tuple[list[NetworkObj], dict[tuple[str, str], ServiceObj]]:
    networks: list[NetworkObj] = []
    services: dict[tuple[str, str], ServiceObj] = {}
    if path is None:
        return networks, services
    data = json.loads(path.read_text())
    for row in data.get("networks", []):
        networks.append(
            NetworkObj(
                name=row["name"],
                cidrs=[ipaddress.ip_network(c, strict=False) for c in row.get("cidrs", [])],
                platform=(row.get("platform") or "both").lower(),
                ftd_zone=row.get("ftd_zone") or "",
            )
        )
    for row in data.get("services", []):
        proto = (row.get("protocol") or "tcp").lower()
        port = str(row.get("port"))
        services[(proto, port)] = ServiceObj(name=row["name"], protocol=proto, port=port)
    return networks, services


def _safe_name(prefix: str, value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return f"{prefix}-{cleaned}"[:64]


def resolve_network(ip: str, networks: list[NetworkObj]) -> tuple[str, Optional[NetworkObj]]:
    if ip in SKIP_SOURCES or ip in SKIP_DESTS:
        return ip, None
    for net in networks:
        if net.contains(ip):
            return net.name, net
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _safe_name("host", ip), None
    if addr.is_loopback:
        return _safe_name("host", ip), None
    if addr.version == 4 and not addr.is_private:
        return "net-internet", None
    if addr.version == 4:
        slash24 = ipaddress.ip_network(f"{ip}/24", strict=False)
        return _safe_name("net", str(slash24).replace("/", "-")), None
    return _safe_name("host", ip), None


def resolve_service(
    proto: str, port: str, catalog: dict[tuple[str, str], ServiceObj]
) -> str:
    proto = proto.lower()
    known = catalog.get((proto, port))
    if known:
        return known.name
    if proto == "icmp":
        return "svc-icmp"
    return _safe_name("svc", f"{proto}-{port}")


def classify_platform(
    src_obj: Optional[NetworkObj],
    dst_obj: Optional[NetworkObj],
    src_name: str,
    dst_name: str,
) -> str:
    src_plat = (src_obj.platform if src_obj else "") or ""
    dst_plat = (dst_obj.platform if dst_obj else "") or ""
    if src_name == "net-internet" or dst_name == "net-internet":
        return "ftd"
    if src_plat == "ftd" or dst_plat == "ftd":
        return "ftd"
    if src_obj and dst_obj and src_plat in {"nsx", "both"} and dst_plat in {"nsx", "both"}:
        return "nsx"
    if src_obj and dst_obj:
        return "both"
    return "ftd"


def read_flows(path: Path) -> list[dict]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def build_candidates(
    rows: list[dict],
    networks: list[NetworkObj],
    services: dict[tuple[str, str], ServiceObj],
    min_count: int,
) -> list[Candidate]:
    bucket: dict[tuple, Candidate] = {}
    for row in rows:
        source = (row.get("source") or "").strip()
        dest = (row.get("destination") or "").strip()
        port = (row.get("port") or "").strip()
        proto = (row.get("protocol") or "tcp").strip().lower()
        direction = (row.get("direction") or "").strip().lower()
        if direction == "listen":
            continue
        if source in SKIP_SOURCES or dest in SKIP_DESTS:
            continue
        if port in {"", "*"}:
            continue
        count = int(row.get("count") or 1)
        src_name, src_obj = resolve_network(source, networks)
        dst_name, dst_obj = resolve_network(dest, networks)
        if src_name == dst_name:
            continue
        service = resolve_service(proto, port, services)
        platform = classify_platform(src_obj, dst_obj, src_name, dst_name)
        key = (src_name, dst_name, service, proto, port, platform)
        item = bucket.get(key)
        if item is None:
            item = Candidate(
                source_object=src_name,
                dest_object=dst_name,
                service=service,
                protocol=proto,
                port=port,
                platform=platform,
                src_zone=src_obj.ftd_zone if src_obj else "",
                dst_zone=dst_obj.ftd_zone if dst_obj else "",
            )
            bucket[key] = item
        item.count += count
        if row.get("host"):
            item.hosts.add(row["host"])
        if row.get("process"):
            item.processes.add(row["process"])
        first = row.get("first_seen") or ""
        last = row.get("last_seen") or ""
        if first and (not item.first_seen or first < item.first_seen):
            item.first_seen = first
        if last and last > item.last_seen:
            item.last_seen = last
    return [c for c in bucket.values() if c.count >= min_count]


def write_ftd(candidates: list[Candidate], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "name",
        "action",
        "source_zone",
        "dest_zone",
        "source_network",
        "dest_network",
        "service",
        "protocol",
        "port",
        "logging",
        "count",
        "comment",
    ]
    rows = []
    for idx, cand in enumerate(sorted(candidates, key=lambda c: (-c.count, c.source_object)), start=1):
        if cand.platform not in {"ftd", "both"}:
            continue
        comment_bits = []
        if cand.hosts:
            comment_bits.append("hosts=" + ",".join(sorted(cand.hosts)[:8]))
        if cand.processes:
            comment_bits.append("proc=" + ",".join(sorted(cand.processes)[:6]))
        rows.append(
            {
                "name": f"allow-{idx:04d}-{cand.service}",
                "action": "ALLOW",
                "source_zone": cand.src_zone,
                "dest_zone": cand.dst_zone,
                "source_network": cand.source_object,
                "dest_network": cand.dest_object,
                "service": cand.service,
                "protocol": cand.protocol,
                "port": cand.port,
                "logging": "True",
                "count": cand.count,
                "comment": "; ".join(comment_bits),
            }
        )
    with dest.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_nsx(candidates: list[Candidate], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    rules = []
    for idx, cand in enumerate(sorted(candidates, key=lambda c: (-c.count, c.source_object)), start=1):
        if cand.platform not in {"nsx", "both"}:
            continue
        notes = []
        if cand.hosts:
            notes.append("hosts=" + ",".join(sorted(cand.hosts)[:8]))
        if cand.processes:
            notes.append("proc=" + ",".join(sorted(cand.processes)[:6]))
        rules.append(
            {
                "display_name": f"allow-{idx:04d}-{cand.service}",
                "description": "; ".join(notes),
                "action": "ALLOW",
                "logged": True,
                "direction": "IN_OUT",
                "source_groups": [f"/infra/domains/default/groups/{cand.source_object}"],
                "destination_groups": [f"/infra/domains/default/groups/{cand.dest_object}"],
                "services": [f"/infra/services/{cand.service}"],
                "scope": ["ANY"],
                "tag": f"count={cand.count}",
            }
        )
    policy = {
        "resource_type": "SecurityPolicy",
        "display_name": "lanit-fw-baseline-candidates",
        "category": "Application",
        "stateful": True,
        "rules": rules,
    }
    dest.write_text(json.dumps(policy, indent=2) + "\n")


def write_objects(candidates: list[Candidate], groups_path: Optional[Path], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    nets = set()
    svcs = set()
    for cand in candidates:
        nets.add(cand.source_object)
        nets.add(cand.dest_object)
        svcs.add((cand.service, cand.protocol, cand.port))
    named = {}
    if groups_path:
        data = json.loads(groups_path.read_text())
        for row in data.get("networks", []):
            named[row["name"]] = ",".join(row.get("cidrs", []))
    rows = []
    for name in sorted(nets):
        rows.append(
            {
                "type": "network",
                "name": name,
                "value": named.get(name, "REVIEW-unmapped-or-slash24"),
            }
        )
    for name, proto, port in sorted(svcs):
        rows.append({"type": "service", "name": name, "value": f"{proto}/{port}"})
    with dest.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["type", "name", "value"])
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export candidate FTD and NSX rules from flows.csv"
    )
    parser.add_argument("flows", type=Path, help="Merged source/destination/port CSV")
    parser.add_argument(
        "--groups",
        type=Path,
        default=None,
        help="JSON map of CIDRs and known services (see groups.example.json)",
    )
    parser.add_argument("--out", type=Path, required=True, help="Output directory")
    parser.add_argument(
        "--min-count",
        type=int,
        default=3,
        help="Drop triples seen fewer times than this (default 3)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.flows.exists():
        print(f"missing {args.flows}", file=sys.stderr)
        return 2
    networks, services = load_groups(args.groups)
    rows = read_flows(args.flows)
    candidates = build_candidates(rows, networks, services, args.min_count)
    args.out.mkdir(parents=True, exist_ok=True)
    write_objects(candidates, args.groups, args.out / "objects.csv")
    write_ftd(candidates, args.out / "ftd-candidate-rules.csv")
    write_nsx(candidates, args.out / "nsx-candidate-policy.json")
    ftd_n = sum(1 for c in candidates if c.platform in {"ftd", "both"})
    nsx_n = sum(1 for c in candidates if c.platform in {"nsx", "both"})
    print(
        f"{len(candidates)} object-level rules "
        f"(FTD {ftd_n}, NSX {nsx_n}) -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
