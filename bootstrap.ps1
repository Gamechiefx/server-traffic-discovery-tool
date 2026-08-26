# Single Windows entry point: install the collector as a startup task and
# start the multi-day window. Same folder as the Linux bootstrap.sh.
#
# Deploy on a server (elevated PowerShell):
#   .\bootstrap.ps1
#   .\bootstrap.ps1 -Days 14 -IntervalSeconds 60
#   .\bootstrap.ps1 -Action status|stop|uninstall
#
# After the window, on an analysis host with Python:
#   .\bootstrap.ps1 -Action export -FlowsDir .\hosts -OutDir .\policy -Groups groups.json

[CmdletBinding()]
param(
    [ValidateSet("install", "status", "stop", "uninstall", "export")]
    [string]$Action = "install",
    [double]$Days = 14,
    [int]$IntervalSeconds = 60,
    [switch]$Force,
    [string]$InstallDir = "C:\Program Files\LanIT\fw-baseline",
    [string]$OutDir = "C:\ProgramData\LanIT\fw-baseline",
    [string]$FlowsDir = "",
    [string]$Groups = "",
    [string]$OutExport = "",
    [int]$MinCount = 3
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$TaskName = "LanIT-FwBaseline"

function Test-Admin {
    $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object Security.Principal.WindowsPrincipal($ident)
    return $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Copy-Toolkit {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    foreach ($name in @(
        "collect_windows.ps1",
        "bootstrap.ps1",
        "convert.py",
        "export_network_fw.py",
        "groups.example.json"
    )) {
        $src = Join-Path $Here $name
        if (Test-Path $src) {
            Copy-Item -Force $src (Join-Path $InstallDir $name)
        }
    }
}

function Write-RunWindow {
    $runPath = Join-Path $OutDir "run.json"
    $now = (Get-Date).ToUniversalTime()
    if (-not $Force -and (Test-Path $runPath)) {
        try {
            $existing = Get-Content -Path $runPath -Raw | ConvertFrom-Json
            $parsed = [datetime]::Parse($existing.deadline, $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            if ($parsed -gt $now) {
                Write-Host "keeping existing window until $($parsed.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
                return
            }
        } catch { }
    }
    $deadline = $now.AddDays($Days)
    $runObj = [ordered]@{
        started  = $now.ToString("yyyy-MM-ddTHH:mm:ssZ")
        deadline = $deadline.ToString("yyyy-MM-ddTHH:mm:ssZ")
        days     = $Days
        interval = $IntervalSeconds
    }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    ($runObj | ConvertTo-Json) | Set-Content -Path $runPath -Encoding UTF8
    Write-Host "run window until $($deadline.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
}

function Install-Collector {
    if (-not (Test-Admin)) { throw "Run elevated: .\bootstrap.ps1" }
    Copy-Toolkit
    Write-RunWindow
    $collector = Join-Path $InstallDir "collect_windows.ps1"
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$collector`" -Days $Days -IntervalSeconds $IntervalSeconds -OutDir `"$OutDir`""
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "installed $TaskName"
    Write-Host "data: $(Join-Path $OutDir 'flows.csv')"
    Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo | Format-List
}

function Show-Status {
    if (-not (Test-Admin)) { throw "Run elevated: .\bootstrap.ps1 -Action status" }
    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Format-List
    Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue | Format-List
    $run = Join-Path $OutDir "run.json"
    if (Test-Path $run) {
        Write-Host "run.json:"
        Get-Content $run
    }
    $csv = Join-Path $OutDir "flows.csv"
    if (Test-Path $csv) {
        Write-Host "flows: $csv ($((Get-Content $csv).Count) lines)"
    }
}

function Stop-Collector {
    if (-not (Test-Admin)) { throw "Run elevated: .\bootstrap.ps1 -Action stop" }
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine -like "*collect_windows.ps1*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Host "stopped $TaskName"
}

function Uninstall-Collector {
    Stop-Collector
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "removed $TaskName (data kept in $OutDir)"
}

function Export-Candidates {
    $py = Get-Command python3 -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python -ErrorAction SilentlyContinue }
    if (-not $py) { throw "export needs Python 3. Collect host CSVs and run bootstrap.sh export on a Linux analysis host." }
    if (-not $FlowsDir -or -not $OutExport) { throw "export requires -FlowsDir and -OutExport" }
    New-Item -ItemType Directory -Force -Path $OutExport | Out-Null
    $inputs = Get-ChildItem -Path $FlowsDir -Recurse -Filter flows.csv | ForEach-Object { $_.FullName }
    if (-not $inputs) { throw "no flows.csv under $FlowsDir" }
    $fleet = Join-Path $OutExport "fleet-flows.csv"
    & $py.Source (Join-Path $Here "convert.py") --format flows @inputs -o $fleet
    $groupArg = @()
    if ($Groups) { $groupArg = @("--groups", $Groups) }
    elseif (Test-Path (Join-Path $Here "groups.json")) { $groupArg = @("--groups", (Join-Path $Here "groups.json")) }
    elseif (Test-Path (Join-Path $Here "groups.example.json")) {
        $groupArg = @("--groups", (Join-Path $Here "groups.example.json"))
        Write-Warning "using groups.example.json; replace with your CIDRs before import"
    }
    & $py.Source (Join-Path $Here "export_network_fw.py") $fleet --out $OutExport --min-count $MinCount @groupArg
    Write-Host "export complete: $OutExport"
}

switch ($Action) {
    "install" { Install-Collector }
    "status" { Show-Status }
    "stop" { Stop-Collector }
    "uninstall" { Uninstall-Collector }
    "export" { Export-Candidates }
}
