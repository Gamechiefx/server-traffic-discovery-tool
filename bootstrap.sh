#!/usr/bin/env bash
# Single Linux entry point: install the collector, keep it running across
# reboots for the configured window, or export merged FTD/NSX candidates.
#
# Deploy on a server:
#   sudo ./bootstrap.sh
#   sudo ./bootstrap.sh --days 14 --interval 5
#   sudo ./bootstrap.sh --ship-dest fwship@central:/data/fw-baseline --ship-key /etc/fw-baseline_id_ed25519
#
# After the window, on an analysis host (or the central tree):
#   ./bootstrap.sh export --flows-dir /data/fw-baseline --groups groups.json --out ./policy
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ACTION="install"
DAYS=14
INTERVAL=5
FORCE=0
INSTALL_DIR="${FW_BASELINE_INSTALL_DIR:-/opt/fw-baseline}"
DATA_DIR="${FW_BASELINE_DATA_DIR:-/var/lib/fw-baseline}"
SERVICE_NAME="fw-baseline"
SHIP_SERVICE_NAME="fw-baseline-ship"
SHIP_ENV="/etc/fw-baseline-ship.env"
SHIP_METHOD="scp"
SHIP_DEST=""
SHIP_KEY=""
SHIP_PORT="22"
SHIP_HOUR="0"
SHIP_NOW=0
FLOWS_DIR=""
GROUPS=""
EXPORT_OUT=""
MIN_COUNT=3

usage() {
  cat <<'EOF'
Usage:
  sudo ./bootstrap.sh [--days N] [--interval SEC] [--force]
  sudo ./bootstrap.sh --ship-dest user@host:/path [--ship-method scp|rsync|rclone] [--ship-key FILE]
  sudo ./bootstrap.sh status|stop|uninstall|ship
  ./bootstrap.sh export --flows-dir DIR --out DIR [--groups groups.json]

Default action installs the toolkit and starts a multi-day collector.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|status|stop|uninstall|export|ship)
      ACTION="$1"
      shift
      ;;
    --days)
      DAYS="$2"
      shift 2
      ;;
    --interval)
      INTERVAL="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --data-dir)
      DATA_DIR="$2"
      shift 2
      ;;
    --flows-dir)
      FLOWS_DIR="$2"
      shift 2
      ;;
    --groups)
      GROUPS="$2"
      shift 2
      ;;
    --out)
      EXPORT_OUT="$2"
      shift 2
      ;;
    --min-count)
      MIN_COUNT="$2"
      shift 2
      ;;
    --ship-method)
      SHIP_METHOD="$2"
      shift 2
      ;;
    --ship-dest)
      SHIP_DEST="$2"
      shift 2
      ;;
    --ship-key)
      SHIP_KEY="$2"
      shift 2
      ;;
    --ship-port)
      SHIP_PORT="$2"
      shift 2
      ;;
    --ship-hour)
      SHIP_HOUR="$2"
      shift 2
      ;;
    --ship-now)
      SHIP_NOW=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "run as root: sudo $0 $ACTION" >&2
    exit 1
  fi
}

python_bin() {
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return
  fi
  echo "python3 is required" >&2
  exit 1
}

copy_toolkit() {
  mkdir -p "$INSTALL_DIR" "$DATA_DIR"
  local f
  for f in convert.py collect.py export_network_fw.py groups.example.json bootstrap.sh ship.py ship.example.env; do
    if [[ -f "$HERE/$f" ]]; then
      cp -f "$HERE/$f" "$INSTALL_DIR/$f"
    fi
  done
  chmod 755 "$INSTALL_DIR/collect.py" "$INSTALL_DIR/convert.py" "$INSTALL_DIR/export_network_fw.py" "$INSTALL_DIR/bootstrap.sh"
  if [[ -f "$INSTALL_DIR/ship.py" ]]; then
    chmod 755 "$INSTALL_DIR/ship.py"
  fi
}

write_unit() {
  local py
  py="$(python_bin)"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Firewall baseline collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${py} ${INSTALL_DIR}/collect.py --days ${DAYS} --interval ${INTERVAL} --out ${DATA_DIR}
Restart=on-failure
RestartSec=30
WorkingDirectory=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
}

write_ship_env() {
  if [[ -z "$SHIP_DEST" ]]; then
    return 1
  fi
  mkdir -p "$(dirname "$SHIP_ENV")"
  cat > "$SHIP_ENV" <<EOF
SHIP_METHOD=${SHIP_METHOD}
SHIP_DEST=${SHIP_DEST}
SHIP_SSH_KEY=${SHIP_KEY}
SHIP_SSH_PORT=${SHIP_PORT}
EOF
  chmod 600 "$SHIP_ENV"
}

write_ship_units() {
  local py
  py="$(python_bin)"
  cat > "/etc/systemd/system/${SHIP_SERVICE_NAME}.service" <<EOF
[Unit]
Description=Firewall baseline daily ship
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${py} ${INSTALL_DIR}/ship.py --config ${SHIP_ENV} --data-dir ${DATA_DIR}
WorkingDirectory=${INSTALL_DIR}
EOF
  cat > "/etc/systemd/system/${SHIP_SERVICE_NAME}.timer" <<EOF
[Unit]
Description=Ship flows.csv once per day (UTC)

[Timer]
OnCalendar=*-*-* ${SHIP_HOUR}:15:00
Persistent=true
Unit=${SHIP_SERVICE_NAME}.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${SHIP_SERVICE_NAME}.timer"
}

do_install() {
  need_root
  python_bin >/dev/null
  if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
    echo "ss or netstat is required (iproute2)" >&2
    exit 1
  fi
  copy_toolkit
  write_unit
  FW_DATA_DIR="$DATA_DIR" FW_DAYS="$DAYS" FW_INTERVAL="$INTERVAL" FW_FORCE="$FORCE" \
    PYTHONPATH="$INSTALL_DIR" "$(python_bin)" - <<'PY'
import os
from pathlib import Path
from collect import resolve_deadline
resolve_deadline(
    Path(os.environ["FW_DATA_DIR"]),
    float(os.environ["FW_DAYS"]),
    int(os.environ["FW_INTERVAL"]),
    force=os.environ.get("FW_FORCE") == "1",
)
print("run window ready")
PY
  systemctl restart "$SERVICE_NAME"
  echo "installed ${SERVICE_NAME}"
  echo "data: ${DATA_DIR}/flows.csv"
  if write_ship_env; then
    write_ship_units
    echo "daily ship: ${SHIP_METHOD} -> ${SHIP_DEST} at ${SHIP_HOUR}:15 UTC"
    if [[ "$SHIP_NOW" -eq 1 ]]; then
      systemctl start "$SHIP_SERVICE_NAME" || true
    fi
  fi
  systemctl --no-pager --full status "$SERVICE_NAME" | head -n 12 || true
}

do_status() {
  need_root
  systemctl --no-pager --full status "$SERVICE_NAME" || true
  if [[ -f "$DATA_DIR/run.json" ]]; then
    echo "run.json:"
    cat "$DATA_DIR/run.json"
  fi
  if [[ -f "$DATA_DIR/flows.csv" ]]; then
    echo "flows: $DATA_DIR/flows.csv ($(wc -l < "$DATA_DIR/flows.csv") lines)"
  fi
  if [[ -f "$SHIP_ENV" ]]; then
    echo "ship.env:"
    grep -E '^(SHIP_METHOD|SHIP_DEST)=' "$SHIP_ENV" || true
    systemctl --no-pager --full status "${SHIP_SERVICE_NAME}.timer" || true
  fi
}

do_stop() {
  need_root
  systemctl stop "$SERVICE_NAME"
  echo "stopped ${SERVICE_NAME}"
}

do_uninstall() {
  need_root
  systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  systemctl stop "${SHIP_SERVICE_NAME}.timer" >/dev/null 2>&1 || true
  systemctl disable "${SHIP_SERVICE_NAME}.timer" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SHIP_SERVICE_NAME}.service" "/etc/systemd/system/${SHIP_SERVICE_NAME}.timer"
  systemctl daemon-reload
  echo "removed ${SERVICE_NAME} (data kept in ${DATA_DIR})"
}

do_ship() {
  need_root
  if [[ ! -f "$SHIP_ENV" && -z "$SHIP_DEST" ]]; then
    echo "no ship dest. pass --ship-dest or install with --ship-dest" >&2
    exit 2
  fi
  if [[ -n "$SHIP_DEST" ]]; then
    write_ship_env || true
  fi
  local ship_py="$INSTALL_DIR/ship.py"
  if [[ ! -f "$ship_py" ]]; then
    ship_py="$HERE/ship.py"
  fi
  PYTHONPATH="$(dirname "$ship_py")" "$(python_bin)" "$ship_py" --config "$SHIP_ENV" --data-dir "$DATA_DIR"
}

do_export() {
  local py
  py="$(python_bin)"
  if [[ -z "$FLOWS_DIR" || -z "$EXPORT_OUT" ]]; then
    echo "export requires --flows-dir and --out" >&2
    exit 2
  fi
  mkdir -p "$EXPORT_OUT"
  local inputs=()
  while IFS= read -r -d '' f; do
    inputs+=("$f")
  done < <(find "$FLOWS_DIR" -type f -name 'flows.csv' -print0)
  if [[ ${#inputs[@]} -eq 0 ]]; then
    echo "no flows.csv under $FLOWS_DIR" >&2
    exit 1
  fi
  "$py" "$HERE/convert.py" --format flows "${inputs[@]}" -o "$EXPORT_OUT/fleet-flows.csv"
  local extra=()
  if [[ -n "$GROUPS" ]]; then
    extra+=(--groups "$GROUPS")
  elif [[ -f "$HERE/groups.json" ]]; then
    extra+=(--groups "$HERE/groups.json")
  elif [[ -f "$HERE/groups.example.json" ]]; then
    extra+=(--groups "$HERE/groups.example.json")
    echo "using groups.example.json; replace with your CIDRs before import" >&2
  fi
  "$py" "$HERE/export_network_fw.py" "$EXPORT_OUT/fleet-flows.csv" --out "$EXPORT_OUT" --min-count "$MIN_COUNT" "${extra[@]}"
  echo "export complete: $EXPORT_OUT"
}

case "$ACTION" in
  install) do_install ;;
  status) do_status ;;
  stop) do_stop ;;
  uninstall) do_uninstall ;;
  export) do_export ;;
  ship) do_ship ;;
esac
