#!/usr/bin/env python3
"""Ship the day's flows.csv to a central server via scp, rsync, or rclone.

The collector keeps one running unique set locally. This copies that file
once per day to:

  <dest>/<hostname>/flows.csv
  <dest>/<hostname>/daily/YYYYMMDD.csv

The dated file is a point-in-time snapshot. The latest file is what
bootstrap export reads. No passwords: SSH key or rclone remote config.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def hostname() -> str:
    return socket.gethostname().split(".")[0]


def utc_day(now: Optional[datetime] = None) -> str:
    stamp = now or datetime.now(timezone.utc)
    return stamp.strftime("%Y%m%d")


def remote_layout(host: str, day: str) -> tuple[str, str]:
    return f"{host}/flows.csv", f"{host}/daily/{day}.csv"


def split_ssh_dest(dest: str) -> tuple[str, str]:
    if ":" not in dest:
        raise ValueError("SSH dest must be user@host:/path")
    hostpart, path = dest.rsplit(":", 1)
    if not hostpart or not path:
        raise ValueError("SSH dest must be user@host:/path")
    return hostpart, path


def load_env(path: Optional[Path]) -> dict[str, str]:
    data: dict[str, str] = {}
    if path is None or not path.exists():
        return data
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip("'").strip('"')
    return data


def stage_files(data_dir: Path, stage_root: Path, host: str, day: str) -> Path:
    src = data_dir / "flows.csv"
    if not src.exists():
        raise FileNotFoundError(f"no {src} yet")
    host_dir = stage_root / host
    daily_dir = host_dir / "daily"
    daily_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, host_dir / "flows.csv")
    shutil.copy2(src, daily_dir / f"{day}.csv")
    run = data_dir / "run.json"
    if run.exists():
        shutil.copy2(run, host_dir / "run.json")
    return host_dir


def ssh_opts(key: str, port: str) -> list[str]:
    opts = [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    if key:
        opts.extend(["-i", key])
    if port:
        opts.extend(["-p", port])
    return opts


def run(cmd: list[str]) -> None:
    print(" ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def ship_scp(host_dir: Path, dest: str, key: str, port: str) -> None:
    hostpart, base = split_ssh_dest(dest)
    host = host_dir.name
    ssh = ["ssh", *ssh_opts(key, port), hostpart, f"mkdir -p {base}/{host}/daily"]
    run(ssh)
    scp_base = ["scp", "-q"]
    if key:
        scp_base.extend(["-i", key])
    if port:
        scp_base.extend(["-P", port])
    scp_base.extend(["-o", "BatchMode=yes"])
    run([*scp_base, str(host_dir / "flows.csv"), f"{hostpart}:{base}/{host}/flows.csv"])
    day_file = next((host_dir / "daily").glob("*.csv"))
    run([*scp_base, str(day_file), f"{hostpart}:{base}/{host}/daily/{day_file.name}"])
    run_json = host_dir / "run.json"
    if run_json.exists():
        run([*scp_base, str(run_json), f"{hostpart}:{base}/{host}/run.json"])


def ship_rsync(host_dir: Path, dest: str, key: str, port: str) -> None:
    hostpart, base = split_ssh_dest(dest)
    ssh_cmd = "ssh " + " ".join(ssh_opts(key, port))
    remote = f"{hostpart}:{base}/{host_dir.name}/"
    run(
        [
            "rsync",
            "-az",
            "-e",
            ssh_cmd,
            "--rsync-path",
            f"mkdir -p {base}/{host_dir.name}/daily && rsync",
            f"{host_dir}/",
            remote,
        ]
    )


def ship_rclone(host_dir: Path, dest: str) -> None:
    remote = dest.rstrip("/") + "/" + host_dir.name
    run(["rclone", "copy", str(host_dir), remote, "--create-empty-src-dirs"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Copy the day's flows.csv to a central server."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("/var/lib/fw-baseline"),
    )
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--method", choices=["scp", "rsync", "rclone"], default=None)
    parser.add_argument("--dest", default=None, help="user@host:/path or rclone remote:path")
    parser.add_argument("--ssh-key", default="")
    parser.add_argument("--ssh-port", default="")
    parser.add_argument("--host", default="")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    env = load_env(args.config)
    method = (args.method or env.get("SHIP_METHOD") or "scp").lower()
    dest = args.dest or env.get("SHIP_DEST") or ""
    key = args.ssh_key or env.get("SHIP_SSH_KEY") or ""
    port = args.ssh_port or env.get("SHIP_SSH_PORT") or ""
    if not dest:
        print("ship disabled: no SHIP_DEST", flush=True)
        return 0
    host = args.host or hostname()
    day = utc_day()
    stage_root = args.data_dir / "stage"
    if stage_root.exists():
        shutil.rmtree(stage_root)
    try:
        host_dir = stage_files(args.data_dir, stage_root, host, day)
    except FileNotFoundError as exc:
        print(str(exc), flush=True)
        return 0
    latest, daily = remote_layout(host, day)
    print(f"shipping {latest} and {daily} via {method}", flush=True)
    try:
        if method == "scp":
            ship_scp(host_dir, dest, key, port)
        elif method == "rsync":
            ship_rsync(host_dir, dest, key, port)
        elif method == "rclone":
            ship_rclone(host_dir, dest)
        else:
            print(f"unknown method {method}", file=sys.stderr)
            return 2
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)
    print("ship complete", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
