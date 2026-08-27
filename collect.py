#!/usr/bin/env python3
"""Long-running flow collector for Linux (and macOS for local tests).

Every --interval seconds it snapshots sockets, converts them to
source/destination/port, and merges into a running unique set. State is
flushed to disk so a multi-day run survives reboot or crash.
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from convert import Store, convert_text, detect_format, load_store, write_csv, write_json


def local_ips() -> set[str]:
    found: set[str] = set()
    for cmd in (
        ["ip", "-o", "addr", "show"],
        ["ifconfig", "-a"],
    ):
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError):
            continue
        found.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out))
        found.update(
            re.findall(r"\binet6\s+([0-9a-fA-F:]+)", out)
        )
        break
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("1.1.1.1", 80))
        found.add(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    found.discard("127.0.0.1")
    found.discard("0.0.0.0")
    found.discard("::1")
    found.discard("::")
    return found


def snapshot_text() -> tuple[str, str]:
    for cmd, fmt in (
        (["ss", "-tunap"], "ss"),
        (["netstat", "-antup"], "netstat"),
        (["netstat", "-an"], "netstat"),
    ):
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            return out, fmt
        except (OSError, subprocess.CalledProcessError):
            continue
    raise RuntimeError("ss and netstat are both unavailable")


def hostname() -> str:
    return socket.gethostname().split(".")[0]


def parse_deadline(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_run(out: Path) -> dict:
    path = out / "run.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_run(out: Path, data: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "run.json").write_text(json.dumps(data, indent=2) + "\n")


def resolve_deadline(out: Path, days: float, interval: int, force: bool = False) -> datetime:
    existing = load_run(out)
    if not force and existing.get("deadline"):
        deadline = parse_deadline(existing["deadline"])
        if deadline > datetime.now(timezone.utc):
            return deadline
    started = datetime.now(timezone.utc).replace(microsecond=0)
    deadline = started + timedelta(days=days)
    save_run(
        out,
        {
            "started": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "deadline": deadline.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days": days,
            "interval": interval,
        },
    )
    return deadline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sample sockets for days and write source,destination,port."
    )
    parser.add_argument("--days", type=float, default=14, help="How long to run (default 14)")
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Seconds between snapshots (default 5)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("/var/lib/lanit/fw-baseline"),
        help="Output directory",
    )
    parser.add_argument(
        "--keep-raw",
        action="store_true",
        help="Append each snapshot to raw/YYYYMMDD.log (large on long runs)",
    )
    parser.add_argument("--include-loopback", action="store_true")
    parser.add_argument(
        "--flush-every",
        type=int,
        default=5,
        help="Flush CSV every N snapshots (default 5)",
    )
    parser.add_argument(
        "--force-new-window",
        action="store_true",
        help="Ignore an existing run.json deadline and start a new window",
    )
    return parser


class Collector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.out: Path = args.out
        self.out.mkdir(parents=True, exist_ok=True)
        self.csv_path = self.out / "flows.csv"
        self.json_path = self.out / "flows.json"
        self.store: Store = load_store(self.csv_path)
        self.host = hostname()
        self.host_ips = local_ips()
        self._stop = False
        self.snapshots = 0
        run = load_run(self.out)
        if run.get("interval"):
            self.args.interval = int(run["interval"])
        self.deadline = resolve_deadline(
            self.out, args.days, self.args.interval, force=args.force_new_window
        )

    def request_stop(self, *_args) -> None:
        self._stop = True

    def flush(self) -> None:
        write_csv(self.store, self.csv_path)
        write_json(self.store, self.json_path)

    def sample(self) -> int:
        text, fmt = snapshot_text()
        if self.args.keep_raw:
            raw_dir = self.out / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            day = datetime.now(timezone.utc).strftime("%Y%m%d")
            with (raw_dir / f"{fmt}-{day}.log").open("a") as handle:
                handle.write(f"# {datetime.now(timezone.utc).isoformat()}\n")
                handle.write(text)
                if not text.endswith("\n"):
                    handle.write("\n")
        before = len(self.store.flows)
        convert_text(
            text,
            fmt=fmt if fmt != "auto" else detect_format(text),
            host_ips=self.host_ips or None,
            include_loopback=self.args.include_loopback,
            host=self.host,
            store=self.store,
        )
        self.snapshots += 1
        return len(self.store.flows) - before

    def run(self) -> int:
        now = datetime.now(timezone.utc)
        if now >= self.deadline:
            print(
                f"collection window already ended at "
                f"{self.deadline.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                flush=True,
            )
            self.flush()
            return 0
        print(
            f"collecting on {self.host} until "
            f"{self.deadline.strftime('%Y-%m-%dT%H:%M:%SZ')}, "
            f"every {self.args.interval}s",
            flush=True,
        )
        print(f"host IPs: {', '.join(sorted(self.host_ips)) or '(none detected)'}", flush=True)
        print(f"output: {self.csv_path}", flush=True)
        try:
            while not self._stop and datetime.now(timezone.utc) < self.deadline:
                started = time.monotonic()
                try:
                    new_rows = self.sample()
                except Exception as exc:
                    print(f"snapshot failed: {exc}", file=sys.stderr, flush=True)
                    new_rows = 0
                if self.snapshots % max(1, self.args.flush_every) == 0:
                    self.flush()
                    print(
                        f"{datetime.now(timezone.utc).strftime('%H:%M:%S')}Z "
                        f"snapshots={self.snapshots} unique={len(self.store.flows)} "
                        f"new={new_rows}",
                        flush=True,
                    )
                elapsed = time.monotonic() - started
                sleep_for = max(0.0, self.args.interval - elapsed)
                end = time.monotonic() + sleep_for
                while not self._stop and time.monotonic() < end:
                    time.sleep(min(1.0, end - time.monotonic()))
        finally:
            self.flush()
            print(
                f"stopped. {len(self.store.flows)} unique source/destination/port rows "
                f"in {self.csv_path}",
                flush=True,
            )
        return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.days <= 0:
        print("--days must be > 0", file=sys.stderr)
        return 2
    if args.interval < 5:
        print("--interval must be >= 5", file=sys.stderr)
        return 2
    collector = Collector(args)
    signal.signal(signal.SIGINT, collector.request_stop)
    signal.signal(signal.SIGTERM, collector.request_stop)
    return collector.run()


if __name__ == "__main__":
    sys.exit(main())
