# Server Traffic Discovery Tool

This toolkit records **observed host network connections** over a defined window and produces **candidate firewall policy** for Cisco Secure Firewall (FTD) and VMware NSX Distributed Firewall. The intended use is a controlled, time-bounded baseline of production traffic so policy can be written from evidence instead of tribal knowledge or overly broad allow rules.

It is a **read-only observation and reporting tool**. It does not change host firewalls, and it does not publish rules to FMC, FTD, or NSX Manager. Every candidate file is for human review.

---

## 1. Purpose

Organizations replacing implicit trust or “any/any” rules need a defensible picture of what servers actually talk to. This toolkit answers that question at the host:

- Which destinations and ports does this system use?
- Which local ports accept inbound connections?
- Which process owns the socket, when the OS reports it?
- Which flows are east-west (candidates for NSX DFW) versus north-south (candidates for FTD)?

The output is a review package: network and service objects, FTD access-control candidates (CSV), and an NSX Security Policy JSON. Operators import nothing until security and network owners approve it.

---

## 2. Security posture

### In scope

| Capability | Behavior |
|---|---|
| Collection | Periodic snapshot of the local socket table (Linux `ss`/`netstat`, Windows `Get-NetTCPConnection` / `Get-NetUDPEndpoint`) |
| Storage | Unique source / destination / port / protocol rows with counts and first/last seen times |
| Transfer (optional) | Copy of CSV metadata to a designated internal host using SSH public-key authentication or a preconfigured rclone remote |
| Export | Offline collapse of fleet CSVs into review-only FTD and NSX candidate files |

### Out of scope

| This toolkit does not | Why it matters |
|---|---|
| Capture packets or payloads | No application content, credentials, or file data are recorded |
| Inspect TLS or HTTP bodies | Metadata only: addresses, ports, protocol, process name |
| Modify iptables, Windows Firewall, FTD, FMC, or NSX | Observation and reporting only |
| Push or activate policy | Export files are candidates. Import is a separate, approved change |
| Phone home or use vendor cloud | No telemetry leaves the host unless shipping is explicitly configured |
| Store passwords | Ship uses SSH keys or rclone remote config. Config files are mode `600` on Linux |
| Require third-party Python packages | Runtime is Python 3 standard library plus OS socket utilities |

### Privileges

- **Linux install / uninstall / status:** root. The collector runs as a systemd service (`fw-baseline`).
- **Windows install / uninstall / status:** elevated PowerShell. The collector runs as a scheduled task under `SYSTEM` (`FwBaseline`).
- **Export:** any operator with read access to collected CSVs and Python 3. Does not require root.

Collection needs enough privilege to read the socket table and, on Windows, process names. It does not install kernel modules, packet filters, or TAP/TUN devices.

### Data classification

Treat collected files as **internal network telemetry**. Typical fields include RFC1918 addresses, destination ports, hostnames, and process names. That combination can reveal application topology. Restrict access to the data directories and any central ship destination the same way you restrict other network-operations artifacts.

Default storage:

| Platform | Toolkit | Data | Ship config |
|---|---|---|---|
| Linux | `/opt/fw-baseline` | `/var/lib/fw-baseline` | `/etc/fw-baseline-ship.env` |
| Windows | `C:\Program Files\fw-baseline` | `C:\ProgramData\fw-baseline` | `C:\ProgramData\fw-baseline\ship.env` |

Uninstall removes the service or scheduled task. **It keeps collected data** so a completed window is not lost. Delete those directories only after the review package is archived according to your retention policy.

---

## 3. How it works

```text
  Linux / Windows hosts                 Optional central host              Analysis host
  ----------------------                ---------------------              --------------
  Socket snapshot every N seconds  -->  SCP / rsync / rclone  -->  Merge fleet CSVs
  Unique flows.csv + run.json           per-host / daily copies     Map CIDRs to objects
  (survives reboot / crash)                                         Write FTD + NSX candidates
                                                                    Human review before any change
```

1. **Collect.** For a configured window (default 14 days), the host records unique connections. State is flushed to disk so a reboot does not restart the clock.
2. **Ship (optional).** Once per day, `flows.csv` and `run.json` are copied to `<dest>/<hostname>/`. A dated snapshot is also written under `daily/YYYYMMDD.csv`.
3. **Export.** After the window, an analysis host merges every `flows.csv`, maps IPs to named networks, and writes candidate policy.
4. **Review.** Security and network owners approve, edit, or reject candidates. Implementation is a separate change on FMC / NSX.

East-west pairs (both sides in NSX-scoped networks) become NSX DFW candidates. North-south or FTD-scoped pairs become FTD access-control candidates. Listen-only rows are kept in the host CSV for inventory and are **not** turned into allow rules.

---

## 4. Data recorded

Each unique flow is one CSV row:

| Field | Description |
|---|---|
| `source` | Source IP, or `*` for a listen socket |
| `destination` | Destination IP |
| `port` | Service port (not the ephemeral client port, except as `source_port`) |
| `protocol` | `tcp` or `udp` |
| `source_port` | Client port when known |
| `direction` | `inbound`, `outbound`, or `listen` |
| `process` | Process name when the OS reports it |
| `count` | How many snapshots observed this tuple |
| `first_seen` / `last_seen` | UTC timestamps |
| `host` | Short hostname |

Loopback (`127.0.0.1`, `::1`) is excluded unless explicitly enabled. Raw socket dumps are **not** kept by default. Linux `--keep-raw` is an operator opt-in and grows quickly on a multi-day run.

The live collectors do not run `tcpdump`. `convert.py` can ingest existing `ss`, `netstat`, `tcpdump -nn`, Windows firewall log, `Get-NetTCPConnection` CSV, or `conntrack` text if those files are already produced by another approved process.

Platform caveats:

- **Windows UDP endpoints carry no state or remote address**, so every UDP endpoint is recorded as a `listen` row and outbound UDP flows (for example DNS) are not captured on Windows collectors. TCP direction on Windows is state-based and complete.
- UDP listener rows require `ss` (Linux). The `netstat` fallback cannot distinguish UDP listeners from short-lived client sockets, so those rows are dropped.
- Rows without a service port (for example ICMP from `conntrack` or `tcpdump`) stay in the host CSV for inventory but are excluded from candidate rules.
- Direction from an established socket with no LISTEN row in the same snapshot uses the local ephemeral port range (`ip_local_port_range` on Linux, 49152 elsewhere) as the client-port floor.

---

## 5. Deployment

### Prerequisites

**Linux**

- Python 3
- `ss` (iproute2) or `netstat`
- systemd (for the supported install path)
- Root for install
- For shipping: `scp` (default), or `rsync`, or `rclone`, plus an SSH key with write access to the destination only

**Windows**

- PowerShell with `Get-NetTCPConnection` / `Get-NetUDPEndpoint` (current Windows Server / Windows 10+)
- Administrator rights for install
- Python 3 is required only on the analysis host that runs export, not on every collected server
- For shipping: OpenSSH `scp` or `rclone`, plus an SSH key

### Linux collector

```bash
sudo ./bootstrap.sh
sudo ./bootstrap.sh --days 14 --interval 5
sudo ./bootstrap.sh --ship-dest fwship@central:/data/fw-baseline \
  --ship-key /etc/fw-baseline_id_ed25519
```

Default interval is 5 seconds (minimum 5). Increase it if CPU or socket-table cost is a concern on a busy host.

```bash
sudo ./bootstrap.sh status
sudo ./bootstrap.sh stop
sudo ./bootstrap.sh uninstall
```

### Windows collector

Elevated PowerShell, from the toolkit directory:

```powershell
.\bootstrap.ps1
.\bootstrap.ps1 -Days 14 -IntervalSeconds 60
.\bootstrap.ps1 -ShipDest "fwship@central:/data/fw-baseline" -ShipKey "C:\ProgramData\fw-baseline_id_ed25519"
.\bootstrap.ps1 -Action status
.\bootstrap.ps1 -Action stop
.\bootstrap.ps1 -Action uninstall
```

### Central shipping

Shipping is off until a destination is set. Authentication is SSH public key or rclone remote config. No password prompts (`BatchMode=yes`).

Copy `ship.example.env` to the platform path above, or let bootstrap write it from `--ship-dest` / `-ShipDest`. Linux ship config is created mode `600`.

Remote layout:

```text
<dest>/<hostname>/flows.csv          # latest unique set
<dest>/<hostname>/run.json           # window start / deadline
<dest>/<hostname>/daily/YYYYMMDD.csv # point-in-time copy for that UTC day
```

Shipping uses `StrictHostKeyChecking=accept-new`: the first connection trusts whichever key the destination presents (TOFU). Pre-stage the destination host key in `known_hosts` before first ship so even that first copy is verified.

---

## 6. Policy export (review files only)

Run on an analysis host after the collection window, against the central tree or a directory of per-host CSVs.

**Linux**

```bash
./bootstrap.sh export \
  --flows-dir /data/fw-baseline \
  --groups groups.json \
  --out ./policy
```

**Windows** (Python 3 required here)

```powershell
.\bootstrap.ps1 -Action export -FlowsDir .\hosts -OutExport .\policy -Groups groups.json
```

`--min-count` (default 3) drops tuples seen fewer times than the threshold so one-off probes do not become allow rules.

### Network and service map

Copy `groups.example.json` to `groups.json` and replace the example CIDRs and service names with your environment. Each network object has:

- `name` — object name used in candidate rules
- `cidrs` — prefixes that belong to that object
- `platform` — `nsx`, `ftd`, or `both`
- `ftd_zone` — FTD zone when the pair is classified as FTD

Unmapped private IPv4 addresses are grouped as a `/24`; `objects.csv` lists the derived CIDR as the object value (unmapped IPv6 hosts list their exact address). Public IPv4 destinations collapse to `net-internet` (`0.0.0.0/0`) and are classified as FTD.

### Export artifacts

| File | Use |
|---|---|
| `fleet-flows.csv` | Merged unique flows across hosts |
| `objects.csv` | Network and service objects referenced by candidates |
| `ftd-candidate-rules.csv` | FTD access-control candidates (ALLOW, logging on) |
| `nsx-candidate-policy.json` | NSX Security Policy JSON (`fw-baseline-candidates`) |

Worked examples from a lab run are under `sample-output/`.

### Review checklist

Before any production import:

1. Confirm every network object in `objects.csv` matches an approved CIDR.
2. Reject or rewrite rules whose `count` is too low for the window, or whose process list is unexpected.
3. Confirm FTD zone pairs and NSX group paths exist in the target managers.
4. Treat `net-internet` and any object whose `objects.csv` value is `REVIEW-unmapped` as incomplete until named.
5. Implement through the standard FMC / NSX change process. Do not apply these files blindly.

---

## 7. Operating model

| Role | Responsibility |
|---|---|
| Infrastructure / server owners | Approve host list, install window, and uninstall after collection |
| Network operations | Operate the central ship destination and run export |
| Information security | Review data handling, approve the host list, and approve candidate policy before import |
| Change management | Ticket the FTD / NSX implementation separately from collection |

Recommended sequence:

1. Agree the host list, window length, and whether shipping is required.
2. Stage SSH keys and the central destination (if used). Restrict the key to that path.
3. Install collectors. Confirm `status` shows a deadline and a growing `flows.csv`.
4. Leave the window running. Reboots resume the same deadline.
5. Export, review, and archive. Uninstall services. Delete or retain data per policy.

---

## 8. Tests

Python unit tests cover conversion, shipping layout, collector run-window behavior, and FTD/NSX classification:

```bash
python3 -m unittest discover -s tests -v
```

Windows collector smoke test: `test_windows.ps1`.

---

## 9. Component reference

| Path | Role |
|---|---|
| `bootstrap.sh` / `bootstrap.ps1` | Supported install, status, stop, uninstall, ship, and export entry points |
| `collect.py` | Linux / macOS long-running collector |
| `collect_windows.ps1` | Windows long-running collector |
| `convert.py` | Normalize socket or log text into unique-flow CSV |
| `ship.py` / `ship.ps1` | Daily copy to the central host |
| `export_network_fw.py` | Build FTD CSV and NSX JSON candidates |
| `groups.example.json` | Template for CIDR and service mapping |
| `ship.example.env` | Template for ship destination and key path |
