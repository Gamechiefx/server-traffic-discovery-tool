#!/usr/bin/env python3
"""Hold TCP connections for known durations so we can see what a snapshot collector catches.

  # On the peer (inbound target / outbound destination):
  python3 stress_flows.py serve --port 19001

  # On the collector host:
  python3 stress_flows.py client --host 10.70.70.77 --port 19001 --hold 0.2,1,3,5,8,15
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from datetime import datetime, timezone


def iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def serve(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    print(f"{iso()} listening 0.0.0.0:{port}", flush=True)

    def handle(conn: socket.socket, addr) -> None:
        try:
            print(f"{iso()} accept {addr[0]}:{addr[1]}", flush=True)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
        except OSError:
            pass
        finally:
            conn.close()
            print(f"{iso()} close {addr[0]}:{addr[1]}", flush=True)

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def hold_one(host: str, port: int, seconds: float) -> str:
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        sock.sendall(b"x")
        time.sleep(seconds)
        return "ok"
    except OSError as exc:
        return f"fail:{exc}"
    finally:
        sock.close()
        elapsed = time.monotonic() - started
        print(f"{iso()} hold {seconds}s -> {host}:{port} elapsed={elapsed:.2f}s", flush=True)


def client(host: str, port: int, holds: list[float], burst: int, burst_hold: float) -> None:
    print(f"{iso()} client start host={host} port={port} holds={holds} burst={burst}", flush=True)
    for seconds in holds:
        status = hold_one(host, port, seconds)
        if status != "ok":
            print(f"{iso()} {status}", flush=True)
        time.sleep(0.3)
    for i in range(burst):
        hold_one(host, port, burst_hold)
    print(f"{iso()} client done", flush=True)


def parse_holds(raw: str) -> list[float]:
    return [float(part) for part in raw.split(",") if part.strip()]


def udp_serve(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"{iso()} udp listen 0.0.0.0:{port}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            sock.sendto(b"y", addr)
        except OSError:
            pass


def udp_hold(host: str, port: int, seconds: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    started = time.monotonic()
    try:
        sock.connect((host, port))
        sock.send(b"x")
        time.sleep(seconds)
    except OSError as exc:
        print(f"{iso()} udp-hold fail {exc}", flush=True)
    finally:
        sock.close()
        print(
            f"{iso()} udp-hold {seconds}s -> {host}:{port} "
            f"elapsed={time.monotonic() - started:.2f}s",
            flush=True,
        )


def udp_oneshot(host: str, port: int, n: int = 1) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _ in range(n):
            sock.sendto(b"x", (host, port))
    finally:
        sock.close()
        print(f"{iso()} udp-oneshot n={n} -> {host}:{port}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Timed TCP holds for snapshot-collector tests")
    sub = parser.add_subparsers(dest="cmd", required=True)
    srv = sub.add_parser("serve")
    srv.add_argument("--port", type=int, required=True)
    cli = sub.add_parser("client")
    cli.add_argument("--host", required=True)
    cli.add_argument("--port", type=int, required=True)
    cli.add_argument("--hold", default="0.2,1,3,5,8,15")
    cli.add_argument("--burst", type=int, default=20)
    cli.add_argument("--burst-hold", type=float, default=0.1)
    many = sub.add_parser("serve-many")
    many.add_argument("--start", type=int, required=True)
    many.add_argument("--end", type=int, required=True)
    cmap = sub.add_parser("client-map")
    cmap.add_argument("--host", required=True)
    cmap.add_argument("--map", required=True, help="hold:port,hold:port")
    userve = sub.add_parser("udp-serve-many")
    userve.add_argument("--start", type=int, required=True)
    userve.add_argument("--end", type=int, required=True)
    umap = sub.add_parser("udp-client-map")
    umap.add_argument("--host", required=True)
    umap.add_argument("--map", required=True, help="hold:port or oneshot:port")
    umap.add_argument("--burst", type=int, default=20)
    args = parser.parse_args(argv)
    if args.cmd == "serve":
        serve(args.port)
        return 0
    if args.cmd == "serve-many":
        for port in range(args.start, args.end + 1):
            threading.Thread(target=serve, args=(port,), daemon=True).start()
        print(f"{iso()} listening {args.start}-{args.end}", flush=True)
        while True:
            time.sleep(60)
    if args.cmd == "client-map":
        pairs = []
        for item in args.map.split(","):
            hold, port = item.split(":")
            pairs.append((float(hold), int(port)))
        print(f"{iso()} client-map start host={args.host} pairs={pairs}", flush=True)
        for hold, port in pairs:
            hold_one(args.host, port, hold)
            time.sleep(0.2)
        print(f"{iso()} client-map done", flush=True)
        return 0
    if args.cmd == "udp-serve-many":
        for port in range(args.start, args.end + 1):
            threading.Thread(target=udp_serve, args=(port,), daemon=True).start()
        print(f"{iso()} udp listening {args.start}-{args.end}", flush=True)
        while True:
            time.sleep(60)
    if args.cmd == "udp-client-map":
        print(f"{iso()} udp-client-map start host={args.host}", flush=True)
        for item in args.map.split(","):
            kind, port_s = item.split(":")
            port = int(port_s)
            if kind == "oneshot":
                udp_oneshot(args.host, port, 1)
            elif kind == "burst":
                udp_oneshot(args.host, port, args.burst)
            else:
                udp_hold(args.host, port, float(kind))
            time.sleep(0.2)
        print(f"{iso()} udp-client-map done", flush=True)
        return 0
    client(args.host, args.port, parse_holds(args.hold), args.burst, args.burst_hold)
    return 0


if __name__ == "__main__":
    sys.exit(main())
