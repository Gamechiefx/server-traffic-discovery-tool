# Server traffic discovery tool

Collect source, destination, and service port from Windows Server and Linux hosts for days, then turn that into candidate **Cisco FTD** and **VMware NSX** firewall rules.

Does not use Wireshark or tshark. Linux uses `ss` (or `netstat`). Windows uses `Get-NetTCPConnection`.

## Deploy on each server

Copy this folder to the host, then run one command.

**Linux**

```bash
sudo ./bootstrap.sh
```

**Windows** (elevated PowerShell)

```powershell
.\bootstrap.ps1
```

Default window: 14 days, snapshot every 60 seconds. The end time is stored in `run.json` so a reboot continues the same window.

| OS | Service | Output |
|---|---|---|
| Linux | systemd `lanit-fw-baseline` | `/var/lib/lanit/fw-baseline/flows.csv` |
| Windows | scheduled task `LanIT-FwBaseline` | `C:\ProgramData\LanIT\fw-baseline\flows.csv` |

```bash
sudo ./bootstrap.sh --days 14 --interval 60
sudo ./bootstrap.sh status
sudo ./bootstrap.sh stop
sudo ./bootstrap.sh uninstall
```

```powershell
.\bootstrap.ps1 -Days 14 -IntervalSeconds 60
.\bootstrap.ps1 -Action status
.\bootstrap.ps1 -Action stop
.\bootstrap.ps1 -Action uninstall
```

Running bootstrap again inside an active window does not reset the clock. Use `--force` / `-Force` only to start a new window.

## What each row means

`flows.csv` keeps one unique triple per host:

| source | destination | port | meaning |
|---|---|---|---|
| `*` | `0.0.0.0` | `22` | this host listens on 22 |
| `10.70.1.50` | `10.70.12.20` | `22` | inbound SSH |
| `10.70.12.20` | `10.70.1.10` | `389` | outbound LDAP |

`port` is the service port, not the client ephemeral port. Repeat sightings increment `count`.

## Export to FTD and NSX

After the window, copy every host `flows.csv` into `hosts/<hostname>/flows.csv`. Edit `groups.example.json` into `groups.json` with your CIDRs and FTD zones. Then:

```bash
./bootstrap.sh export --flows-dir ./hosts --groups groups.json --out ./policy
```

Writes:

- `policy/objects.csv` — network and service objects
- `policy/ftd-candidate-rules.csv` — FTD access-control candidates
- `policy/nsx-candidate-policy.json` — NSX DFW SecurityPolicy candidates

East-west pairs inside NSX-scoped networks go to NSX. North-south or FTD-scoped pairs go to FTD. Listen rows are dropped. `--min-count 3` drops one-off triples. Review and create objects in FMC/NSX before import. This tool does not push policy.

## Convert leftover text

If you already have `ss`, `netstat`, `tcpdump -nn`, Windows `pfirewall.log`, or `Get-NetTCPConnection` CSV:

```bash
python3 convert.py ss.log pfirewall.log -o flows.csv --host-ip 10.70.12.20 --host sql-03
```

## Requirements

- Linux: Python 3, `ss` or `netstat` (`iproute2`)
- Windows: PowerShell, NetTCPIP (`Get-NetTCPConnection`)
- Analysis host: Python 3 for `export`

## Tests

```bash
python3 tests/test_convert.py
python3 tests/test_export_network_fw.py
python3 tests/test_collect_run.py
```
