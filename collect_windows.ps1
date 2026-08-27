# Long-running Windows flow collector.
# Samples TCP/UDP endpoints, converts to source/destination/port, and
# merges into a running unique set that survives a multi-day run.
#
# Example:
#   powershell -ExecutionPolicy Bypass -File collect_windows.ps1 -Days 14 -IntervalSeconds 60

[CmdletBinding()]
param(
    [double]$Days = 14,
    [double]$Minutes = 0,
    [int]$IntervalSeconds = 5,
    [string]$OutDir = "C:\ProgramData\LanIT\fw-baseline",
    [switch]$IncludeLoopback,
    [switch]$ForceNewWindow
)

$ErrorActionPreference = "Continue"
$CsvPath = Join-Path $OutDir "flows.csv"
$script:Store = @{}
$script:StopRequested = $false

function Get-IsoNow {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Test-Loopback([string]$Ip) {
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $false }
    return $Ip.StartsWith("127.") -or $Ip -eq "::1" -or $Ip -eq "localhost"
}

function Get-HostIps {
    $ips = New-Object 'System.Collections.Generic.HashSet[string]'
    Get-NetIPAddress -AddressFamily IPv4, IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -and $_.IPAddress -notmatch "^(127\.|::1$|fe80:)" } |
        ForEach-Object { [void]$ips.Add($_.IPAddress) }
    return $ips
}

function Import-ExistingStore {
    if (-not (Test-Path $CsvPath)) { return }
    Import-Csv -Path $CsvPath | ForEach-Object {
        $key = "{0}|{1}|{2}|{3}|{4}" -f $_.source, $_.destination, $_.port, $_.protocol, $_.direction
        $script:Store[$key] = $_
    }
}

function Merge-Flow {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$Port,
        [string]$Protocol,
        [string]$SourcePort,
        [string]$Direction,
        [string]$ProcessName,
        [string]$HostName
    )
    if ([string]::IsNullOrWhiteSpace($Destination) -or $Destination -eq "*" ) { return }
    if ([string]::IsNullOrWhiteSpace($Port) -or $Port -eq "*") { return }
    if (-not $IncludeLoopback -and ((Test-Loopback $Source) -or (Test-Loopback $Destination))) { return }

    $now = Get-IsoNow
    $key = "{0}|{1}|{2}|{3}|{4}" -f $Source, $Destination, $Port, $Protocol, $Direction
    if ($script:Store.ContainsKey($key)) {
        $row = $script:Store[$key]
        $row.count = [int]$row.count + 1
        $row.last_seen = $now
        if (-not $row.process -and $ProcessName) { $row.process = $ProcessName }
        if (-not $row.source_port -and $SourcePort) { $row.source_port = $SourcePort }
    } else {
        $script:Store[$key] = [pscustomobject]@{
            source      = $Source
            destination = $Destination
            port        = $Port
            protocol    = $Protocol
            source_port = $SourcePort
            direction   = $Direction
            process     = $ProcessName
            count       = 1
            first_seen  = $now
            last_seen   = $now
            host        = $HostName
        }
    }
}

function Write-Store {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $script:Store.Values |
        Sort-Object { -[int]$_.count }, destination, port, source |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
}

function Get-ProcessNameByPid([int]$ProcId) {
    if ($ProcId -le 0) { return "" }
    $proc = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    if ($proc) { return $proc.ProcessName }
    return ""
}

function Invoke-Snapshot {
    $hostName = $env:COMPUTERNAME
    $hostIps = Get-HostIps
    $listenPorts = New-Object 'System.Collections.Generic.HashSet[string]'

    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($row in $tcp) {
        if ($row.State -eq "Listen") {
            [void]$listenPorts.Add([string]$row.LocalPort)
        }
    }

    foreach ($row in $tcp) {
        $localIp = [string]$row.LocalAddress
        $localPort = [string]$row.LocalPort
        $remoteIp = [string]$row.RemoteAddress
        $remotePort = [string]$row.RemotePort
        $procName = Get-ProcessNameByPid ([int]$row.OwningProcess)

        if ($row.State -eq "Listen") {
            $dest = if ($localIp -and $localIp -ne "::") { $localIp } else { "0.0.0.0" }
            Merge-Flow -Source "*" -Destination $dest -Port $localPort -Protocol "tcp" `
                -SourcePort "*" -Direction "listen" -ProcessName $procName -HostName $hostName
            continue
        }
        if (-not $remoteIp -or $remoteIp -in @("0.0.0.0", "::", "*")) { continue }

        if ($listenPorts.Contains($localPort)) {
            Merge-Flow -Source $remoteIp -Destination $localIp -Port $localPort -Protocol "tcp" `
                -SourcePort $remotePort -Direction "inbound" -ProcessName $procName -HostName $hostName
        } else {
            Merge-Flow -Source $localIp -Destination $remoteIp -Port $remotePort -Protocol "tcp" `
                -SourcePort $localPort -Direction "outbound" -ProcessName $procName -HostName $hostName
        }
    }

    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    foreach ($row in $udp) {
        $localIp = [string]$row.LocalAddress
        $localPort = [string]$row.LocalPort
        $procName = Get-ProcessNameByPid ([int]$row.OwningProcess)
        if ($localIp -in @("127.0.0.1", "::1") -and -not $IncludeLoopback) { continue }
        $dest = if ($localIp -and $localIp -notin @("::", "")) { $localIp } else { "0.0.0.0" }
        Merge-Flow -Source "*" -Destination $dest -Port $localPort -Protocol "udp" `
            -SourcePort "*" -Direction "listen" -ProcessName $procName -HostName $hostName
    }
}

if ($Minutes -gt 0) { $Days = $Minutes / 1440.0 }
if ($Days -le 0) { throw "-Days must be > 0" }
if ($IntervalSeconds -lt 5) { throw "-IntervalSeconds must be >= 5" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Import-ExistingStore

$RunPath = Join-Path $OutDir "run.json"
$deadline = $null
if (-not $ForceNewWindow -and (Test-Path $RunPath)) {
    try {
        $run = Get-Content -Path $RunPath -Raw | ConvertFrom-Json
        if ($run.deadline) {
            $parsed = [datetime]::Parse($run.deadline, $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            if ($parsed -gt (Get-Date).ToUniversalTime()) {
                $deadline = $parsed
            }
            if ($run.interval) { $IntervalSeconds = [int]$run.interval }
        }
    } catch {
        Write-Warning "could not read $RunPath"
    }
}
if (-not $deadline) {
    $started = (Get-Date).ToUniversalTime()
    $deadline = $started.AddDays($Days)
    $runObj = [ordered]@{
        started  = $started.ToString("yyyy-MM-ddTHH:mm:ssZ")
        deadline = $deadline.ToString("yyyy-MM-ddTHH:mm:ssZ")
        days     = $Days
        interval = $IntervalSeconds
    }
    ($runObj | ConvertTo-Json) | Set-Content -Path $RunPath -Encoding UTF8
}

if ((Get-Date).ToUniversalTime() -ge $deadline) {
    Write-Host "collection window already ended at $($deadline.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Write-Store
    exit 0
}

Write-Host "collecting on $env:COMPUTERNAME until $($deadline.ToString('yyyy-MM-ddTHH:mm:ssZ')), every ${IntervalSeconds}s"
Write-Host "output: $CsvPath"

$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    $script:StopRequested = $true
}

$snapshots = 0
try {
    while (-not $script:StopRequested -and (Get-Date).ToUniversalTime() -lt $deadline) {
        $started = Get-Date
        try {
            Invoke-Snapshot
        } catch {
            Write-Warning "snapshot failed: $_"
        }
        $snapshots++
        if ($snapshots % 5 -eq 0) {
            Write-Store
            Write-Host ("{0}Z snapshots={1} unique={2}" -f ((Get-Date).ToUniversalTime().ToString("HH:mm:ss")), $snapshots, $script:Store.Count)
        }
        $elapsed = ((Get-Date) - $started).TotalSeconds
        $sleepFor = [Math]::Max(0, $IntervalSeconds - $elapsed)
        Start-Sleep -Seconds $sleepFor
    }
} finally {
    Write-Store
    Write-Host "stopped. $($script:Store.Count) unique source/destination/port rows in $CsvPath"
}
