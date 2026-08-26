#!/usr/bin/env python3
"""Convert collector text into source, destination, and service port.

Reads ss, netstat, tcpdump -nn, Windows firewall log, Get-NetTCPConnection CSV,
conntrack, or an already-normalized CSV. Writes one row per unique
source/destination/port/protocol with hit counts and first/last seen.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


ISO = "%Y-%m-%dT%H:%M:%SZ"

LOOPBACK_V4 = re.compile(r"^127\.")
LOOPBACK_V6 = re.compile(r"^(::1|::ffff:127\.)", re.I)
SS_HEADER = re.compile(r"^(Netid|State)\b", re.I)
TCPDUMP_LINE = re.compile(
    r"^(?P<ts>\S+\s+\S+|\S+)\s+"
    r"(?P<fam>IP6?)\s+"
    r"(?P<src>\S+)\s+>\s+(?P<dst>\S+?):",
)
CONNTRACK = re.compile(
    r"^(?P<proto>tcp|udp|icmp)\b.*?\bsrc=(?P<src>\S+)\s+dst=(?P<dst>\S+)"
    r"(?:\s+sport=(?P<sport>\d+))?(?:\s+dport=(?P<dport>\d+))?",
    re.I,
)
PROCESS_SS = re.compile(r'users:\(\("([^"]+)"')
PROCESS_NETSTAT = re.compile(r"(\d+)/(\S+)")
EPHEMERAL_MIN = 49152


@dataclass
class Flow:
    source: str
    destination: str
    port: str
    protocol: str
    source_port: str = ""
    direction: str = ""
    process: str = ""
    count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    host: str = ""

    def key(self) -> tuple:
        return (
            self.source,
            self.destination,
            self.port,
            self.protocol.lower(),
            self.direction,
        )


@dataclass
class RawConn:
    proto: str
    local_ip: str
    local_port: str
    remote_ip: str
    remote_port: str
    state: str = ""
    process: str = ""
    ts: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: str = ""
    dst_port: str = ""


@dataclass
class Store:
    flows: dict[tuple, Flow] = field(default_factory=dict)
    listeners: set[tuple[str, str]] = field(default_factory=set)

    def add(self, flow: Flow) -> None:
        if not flow.first_seen:
            flow.first_seen = flow.last_seen or _now()
        if not flow.last_seen:
            flow.last_seen = flow.first_seen
        key = flow.key()
        existing = self.flows.get(key)
        if existing is None:
            self.flows[key] = flow
            return
        existing.count += flow.count
        existing.last_seen = max(existing.last_seen, flow.last_seen)
        if flow.first_seen and (
            not existing.first_seen or flow.first_seen < existing.first_seen
        ):
            existing.first_seen = flow.first_seen
        if flow.process and not existing.process:
            existing.process = flow.process
        if flow.source_port and not existing.source_port:
            existing.source_port = flow.source_port
        if flow.host and not existing.host:
            existing.host = flow.host

    def rows(self) -> list[Flow]:
        return sorted(
            self.flows.values(),
            key=lambda f: (-f.count, f.destination, f.port, f.source),
        )


def _now() -> str:
    return datetime.now(timezone.utc).strftime(ISO)


def _clean_ip(value: str) -> str:
    value = value.strip().strip("[]")
    if value.endswith("%"):
        value = value.split("%", 1)[0]
    if "%" in value:
        value = value.split("%", 1)[0]
    return value


def split_endpoint(token: str) -> tuple[str, str]:
    """Split ip:port, [ipv6]:port, or tcpdump ip.port into (ip, port)."""
    token = token.strip().rstrip(":")
    if not token or token in {"*", "0.0.0.0:*", "[::]:*", ":::*"}:
        return "*", "*"
    if token.startswith("["):
        end = token.find("]")
        if end != -1:
            ip = _clean_ip(token[1:end])
            rest = token[end + 1 :]
            port = rest[1:] if rest.startswith(":") else rest.lstrip(".")
            return ip, port or "*"
    if token.count(":") == 1 and not token.startswith(":"):
        ip, port = token.rsplit(":", 1)
        return _clean_ip(ip), port or "*"
    if token.count(":") > 1:
        if token.endswith(":*"):
            return _clean_ip(token[:-2]), "*"
        if "]." in token:
            ip, port = token.rsplit("].", 1)
            return _clean_ip(ip), port
        if "]:" in token:
            ip, port = token.rsplit("]:", 1)
            return _clean_ip(ip), port
        last_colon = token.rfind(":")
        last_dot = token.rfind(".")
        if last_dot > last_colon and token[last_dot + 1 :].isdigit():
            return _clean_ip(token[:last_dot]), token[last_dot + 1 :]
        return _clean_ip(token), "*"
    if "." in token:
        ip, port = token.rsplit(".", 1)
        if port.isdigit() or port == "*":
            return _clean_ip(ip), port
    return _clean_ip(token), "*"


def is_loopback(ip: str) -> bool:
    ip = ip.lower()
    return bool(LOOPBACK_V4.match(ip) or LOOPBACK_V6.match(ip) or ip in {"::1", "localhost"})


def normalize_conn(
    conn: RawConn,
    host_ips: Optional[set[str]] = None,
    listeners: Optional[set[tuple[str, str]]] = None,
    include_loopback: bool = False,
    host: str = "",
) -> Optional[Flow]:
    proto = (conn.proto or "tcp").lower()
    if proto.startswith("tcp"):
        proto = "tcp"
    elif proto.startswith("udp"):
        proto = "udp"
    elif proto.startswith("icmp"):
        proto = "icmp"

    local_ip, local_port = conn.local_ip, conn.local_port
    remote_ip, remote_port = conn.remote_ip, conn.remote_port
    if conn.src_ip:
        # Packet-oriented record (tcpdump / pfirewall): src → dst:dport
        source, destination, port = conn.src_ip, conn.dst_ip, conn.dst_port or remote_port
        source_port = conn.src_port or local_port
        direction = ""
        if host_ips:
            if destination in host_ips:
                direction = "inbound"
            elif source in host_ips:
                direction = "outbound"
        if not include_loopback and (is_loopback(source) or is_loopback(destination)):
            return None
        if destination in {"*", ""} or port in {"", "*"}:
            return None
        return Flow(
            source=source,
            destination=destination,
            port=port,
            protocol=proto,
            source_port=source_port,
            direction=direction,
            process=conn.process,
            first_seen=conn.ts,
            last_seen=conn.ts,
            host=host,
        )

    if not include_loopback and (
        is_loopback(local_ip) or is_loopback(remote_ip)
    ):
        return None

    state = (conn.state or "").upper()
    listening = state in {"LISTEN", "LISTENING", "UNCONN"} or (
        listeners is not None and (local_ip, local_port) in listeners
    ) or (
        listeners is not None and ("*", local_port) in listeners
    ) or (
        listeners is not None and ("0.0.0.0", local_port) in listeners
    )
    if (
        not listening
        and local_port.isdigit()
        and remote_port.isdigit()
        and int(local_port) < EPHEMERAL_MIN
        and int(remote_port) >= EPHEMERAL_MIN
    ):
        listening = True

    if state in {"LISTEN", "LISTENING"}:
        if local_port in {"", "*"}:
            return None
        return Flow(
            source="*",
            destination=local_ip if local_ip not in {"", "*"} else "0.0.0.0",
            port=local_port,
            protocol=proto,
            source_port="*",
            direction="listen",
            process=conn.process,
            first_seen=conn.ts,
            last_seen=conn.ts,
            host=host,
        )

    if remote_ip in {"", "*", "0.0.0.0", "::"} or remote_port in {"", "*"}:
        return None

    if listening:
        source, destination, port = remote_ip, local_ip, local_port
        source_port = remote_port
        direction = "inbound"
    else:
        source, destination, port = local_ip, remote_ip, remote_port
        source_port = local_port
        direction = "outbound"
        if host_ips:
            if local_ip in host_ips and remote_ip not in host_ips:
                direction = "outbound"
            elif remote_ip in host_ips and local_ip not in host_ips:
                source, destination, port = remote_ip, local_ip, local_port
                source_port = remote_port
                direction = "inbound"

    if destination in {"", "*"} or port in {"", "*"}:
        return None

    return Flow(
        source=source,
        destination=destination,
        port=port,
        protocol=proto,
        source_port=source_port,
        direction=direction,
        process=conn.process,
        first_seen=conn.ts,
        last_seen=conn.ts,
        host=host,
    )


def detect_format(text: str) -> str:
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#Fields:") or line.startswith("#Version:"):
            return "pfirewall"
        if line.lower().startswith("source,destination,port"):
            return "flows"
        lowered = line.lower()
        if "localaddress" in lowered and "localport" in lowered:
            return "win_csv"
        if "local address" in lowered and "foreign address" in lowered:
            return "netstat"
        if SS_HEADER.match(line) or line.startswith("Netid"):
            return "ss"
        if line.startswith("Active Connections"):
            return "netstat"
        if CONNTRACK.match(line):
            return "conntrack"
        if TCPDUMP_LINE.search(line) or re.search(r"\sIP6?\s+\S+\s+>\s+\S+", line):
            return "tcpdump"
        if re.match(r"^(tcp|udp|icmp)\s", line, re.I) and "src=" in line:
            return "conntrack"
        if re.match(r"^(tcp|udp|u_str|u_dgr|icmp6?)\s", line, re.I):
            return "ss"
        if re.match(r"^(TCP|UDP)\s+", line):
            return "netstat"
        if "," in line and line.lower().startswith("creationtime"):
            return "win_csv"
    return "ss"


def parse_ss(text: str) -> list[RawConn]:
    conns: list[RawConn] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or SS_HEADER.match(line) or line.startswith("Netid"):
            continue
        process = ""
        match = PROCESS_SS.search(line)
        if match:
            process = match.group(1)
            line = line[: match.start()].rstrip()
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        # ss: Netid State Recv-Q Send-Q Local Peer
        if parts[1].isdigit() and len(parts) >= 5:
            # netstat-like slipped through: proto recv send local foreign
            local = parts[3]
            remote = parts[4]
            state = parts[5] if len(parts) > 5 and not parts[5][0].isdigit() else ""
        else:
            state = parts[1]
            if len(parts) < 6:
                continue
            local = parts[4]
            remote = parts[5]
        local_ip, local_port = split_endpoint(local)
        remote_ip, remote_port = split_endpoint(remote)
        conns.append(
            RawConn(
                proto=proto,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                process=process,
            )
        )
    return conns


def parse_netstat(text: str) -> list[RawConn]:
    conns: list[RawConn] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("Active") or line.lower().startswith("proto"):
            continue
        if line.lower().startswith("local address"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        proto = parts[0]
        if proto.upper() not in {"TCP", "UDP", "TCPv6", "UDPv6"}:
            continue
        if parts[1].isdigit() and len(parts) >= 5:
            local, remote, state = parts[3], parts[4], parts[5] if len(parts) > 5 else ""
            rest = parts[6] if len(parts) > 6 else ""
        else:
            local, remote = parts[1], parts[2]
            state = parts[3] if len(parts) > 3 else ""
            rest = parts[4] if len(parts) > 4 else ""
        process = ""
        proc = PROCESS_NETSTAT.search(rest) or PROCESS_NETSTAT.search(line)
        if proc:
            process = proc.group(2)
        local_ip, local_port = split_endpoint(local)
        remote_ip, remote_port = split_endpoint(remote)
        conns.append(
            RawConn(
                proto=proto,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                process=process,
            )
        )
    return conns


def parse_tcpdump(text: str) -> list[RawConn]:
    conns: list[RawConn] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = TCPDUMP_LINE.search(line)
        if not match:
            alt = re.search(r"\sIP6?\s+(\S+)\s+>\s+(\S+?):", line)
            if not alt:
                continue
            src_tok, dst_tok = alt.group(1), alt.group(2)
            ts = line.split()[0]
            fam = "IP6" if " IP6 " in line else "IP"
        else:
            src_tok, dst_tok = match.group("src"), match.group("dst")
            ts = match.group("ts")
            fam = match.group("fam")
        src_ip, src_port = split_endpoint(src_tok)
        dst_ip, dst_port = split_endpoint(dst_tok)
        proto = "icmp" if " ICMP" in line or " icmp" in line else ("udp" if " UDP" in line else "tcp")
        conns.append(
            RawConn(
                proto=proto,
                local_ip="",
                local_port="",
                remote_ip="",
                remote_port="",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                ts=_coerce_ts(ts),
            )
        )
        _ = fam
    return conns


def parse_pfirewall(text: str) -> list[RawConn]:
    conns: list[RawConn] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 8:
            continue
        date, time, _action, proto, src_ip, dst_ip, src_port, dst_port = parts[:8]
        conns.append(
            RawConn(
                proto=proto,
                local_ip="",
                local_port="",
                remote_ip="",
                remote_port="",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                ts=_coerce_ts(f"{date} {time}"),
            )
        )
    return conns


def parse_conntrack(text: str) -> list[RawConn]:
    conns: list[RawConn] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = CONNTRACK.search(line)
        if not match:
            continue
        conns.append(
            RawConn(
                proto=match.group("proto"),
                local_ip=match.group("src"),
                local_port=match.group("sport") or "*",
                remote_ip=match.group("dst"),
                remote_port=match.group("dport") or "*",
                state="ESTABLISHED" if "ESTABLISHED" in line else "",
            )
        )
    return conns


def parse_win_csv(text: str) -> list[RawConn]:
    sample = text.lstrip()
    reader = csv.DictReader(io.StringIO(sample))
    if not reader.fieldnames:
        return []
    fields = {name.lower().strip(): name for name in reader.fieldnames}
    conns: list[RawConn] = []
    for row in reader:
        def g(*names: str) -> str:
            for name in names:
                key = fields.get(name.lower())
                if key and row.get(key) not in (None, ""):
                    return str(row[key]).strip()
            return ""

        conns.append(
            RawConn(
                proto=g("protocol", "proto") or "tcp",
                local_ip=g("localaddress", "local_ip", "local"),
                local_port=g("localport", "local_port"),
                remote_ip=g("remoteaddress", "remote_ip", "remote"),
                remote_port=g("remoteport", "remote_port"),
                state=g("state"),
                process=g("process", "processname", "owningprocess"),
                ts=_coerce_ts(g("creationtime", "timestamp", "time")),
            )
        )
    return conns


def parse_flows_csv(text: str) -> list[Flow]:
    reader = csv.DictReader(io.StringIO(text.lstrip()))
    flows: list[Flow] = []
    for row in reader:
        if not row.get("source") or not row.get("destination") or not row.get("port"):
            continue
        flows.append(
            Flow(
                source=row["source"].strip(),
                destination=row["destination"].strip(),
                port=row["port"].strip(),
                protocol=(row.get("protocol") or "tcp").strip().lower(),
                source_port=(row.get("source_port") or "").strip(),
                direction=(row.get("direction") or "").strip(),
                process=(row.get("process") or "").strip(),
                count=int(row.get("count") or 1),
                first_seen=(row.get("first_seen") or "").strip(),
                last_seen=(row.get("last_seen") or "").strip(),
                host=(row.get("host") or "").strip(),
            )
        )
    return flows


def _coerce_ts(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return _now()
    if re.match(r"^\d{4}-\d{2}-\d{2}T", value):
        return value if value.endswith("Z") else value + "Z"
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%H:%M:%S.%f",
        "%H:%M:%S",
    ):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.year == 1900:
                today = datetime.now(timezone.utc)
                parsed = parsed.replace(
                    year=today.year, month=today.month, day=today.day, tzinfo=timezone.utc
                )
            elif parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.strftime(ISO)
        except ValueError:
            continue
    return _now()


PARSERS = {
    "ss": parse_ss,
    "netstat": parse_netstat,
    "tcpdump": parse_tcpdump,
    "pfirewall": parse_pfirewall,
    "conntrack": parse_conntrack,
    "win_csv": parse_win_csv,
}


def collect_listeners(conns: Iterable[RawConn]) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for conn in conns:
        state = (conn.state or "").upper()
        if state in {"LISTEN", "LISTENING"} and conn.local_port not in {"", "*"}:
            found.add((conn.local_ip or "*", conn.local_port))
            found.add(("*", conn.local_port))
    return found


def convert_text(
    text: str,
    fmt: str = "auto",
    host_ips: Optional[set[str]] = None,
    include_loopback: bool = False,
    host: str = "",
    store: Optional[Store] = None,
) -> Store:
    store = store or Store()
    if not text.strip():
        return store
    if fmt == "auto":
        fmt = detect_format(text)
    if fmt == "flows":
        for flow in parse_flows_csv(text):
            if host and not flow.host:
                flow.host = host
            store.add(flow)
        return store

    parser = PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"unknown format: {fmt}")
    conns = parser(text)
    listeners = collect_listeners(conns)
    store.listeners.update(listeners)
    for conn in conns:
        flow = normalize_conn(
            conn,
            host_ips=host_ips,
            listeners=store.listeners,
            include_loopback=include_loopback,
            host=host,
        )
        if flow:
            store.add(flow)
    return store


def convert_files(
    paths: Iterable[Path],
    fmt: str = "auto",
    host_ips: Optional[set[str]] = None,
    include_loopback: bool = False,
    host: str = "",
) -> Store:
    store = Store()
    for path in paths:
        text = path.read_text(errors="replace")
        inferred_host = host or _host_from_name(path)
        file_fmt = fmt
        if fmt == "auto":
            file_fmt = detect_format(text)
        convert_text(
            text,
            fmt=file_fmt,
            host_ips=host_ips,
            include_loopback=include_loopback,
            host=inferred_host,
            store=store,
        )
    return store


def _host_from_name(path: Path) -> str:
    name = path.name
    for prefix in ("ss-", "netstat-", "tcpdump-", "pfirewall-", "flows-"):
        if name.startswith(prefix):
            return ""
    if path.parent.name and path.parent.name not in {".", "fw-baseline", "raw"}:
        return path.parent.name
    return ""


CSV_FIELDS = [
    "source",
    "destination",
    "port",
    "protocol",
    "source_port",
    "direction",
    "process",
    "count",
    "first_seen",
    "last_seen",
    "host",
]


def write_csv(store: Store, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for flow in store.rows():
            writer.writerow(asdict(flow))


def write_json(store: Store, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps([asdict(f) for f in store.rows()], indent=2) + "\n")


def load_store(path: Path) -> Store:
    store = Store()
    if not path.exists():
        return store
    convert_text(path.read_text(errors="replace"), fmt="flows", store=store)
    return store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert collector text to source, destination, port."
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="Raw or CSV files")
    parser.add_argument("-o", "--output", type=Path, required=True, help="Output CSV")
    parser.add_argument(
        "--format",
        default="auto",
        choices=["auto", *PARSERS, "flows"],
        help="Input format (default: auto-detect per file)",
    )
    parser.add_argument(
        "--host-ip",
        action="append",
        default=[],
        help="This host's IP (repeatable). Improves inbound vs outbound.",
    )
    parser.add_argument("--host", default="", help="Hostname written on each row")
    parser.add_argument(
        "--include-loopback",
        action="store_true",
        help="Keep 127.0.0.1 / ::1 flows",
    )
    parser.add_argument("--json", type=Path, help="Also write JSON")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    missing = [p for p in args.inputs if not p.exists()]
    if missing:
        print(f"missing files: {', '.join(str(p) for p in missing)}", file=sys.stderr)
        return 2
    store = convert_files(
        args.inputs,
        fmt=args.format,
        host_ips=set(args.host_ip) or None,
        include_loopback=args.include_loopback,
        host=args.host,
    )
    write_csv(store, args.output)
    if args.json:
        write_json(store, args.json)
    print(f"{len(store.flows)} unique source/destination/port rows -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
