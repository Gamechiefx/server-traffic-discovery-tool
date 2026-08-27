# Daily ship of flows.csv via scp or rclone.
# Writes <dest>/<hostname>/flows.csv and <dest>/<hostname>/daily/YYYYMMDD.csv

[CmdletBinding()]
param(
    [string]$OutDir = "C:\ProgramData\fw-baseline",
    [string]$Config = "C:\ProgramData\fw-baseline\ship.env",
    [ValidateSet("scp", "rclone")]
    [string]$Method = "",
    [string]$Dest = "",
    [string]$SshKey = "",
    [string]$SshPort = ""
)

$ErrorActionPreference = "Stop"

function Read-Env([string]$Path) {
    $map = @{}
    if (-not (Test-Path $Path)) { return $map }
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) { return }
        $idx = $line.IndexOf("=")
        $map[$line.Substring(0, $idx).Trim()] = $line.Substring($idx + 1).Trim().Trim("'").Trim('"')
    }
    return $map
}

$envMap = Read-Env $Config
if (-not $Method) { $Method = if ($envMap.SHIP_METHOD) { $envMap.SHIP_METHOD } else { "scp" } }
if (-not $Dest) { $Dest = $envMap.SHIP_DEST }
if (-not $SshKey) { $SshKey = $envMap.SHIP_SSH_KEY }
if (-not $SshPort) { $SshPort = $envMap.SHIP_SSH_PORT }

if (-not $Dest) {
    Write-Host "ship disabled: no SHIP_DEST"
    exit 0
}

$csv = Join-Path $OutDir "flows.csv"
if (-not (Test-Path $csv)) {
    Write-Host "no $csv yet"
    exit 0
}

$hostName = $env:COMPUTERNAME
$day = (Get-Date).ToUniversalTime().ToString("yyyyMMdd")
$stage = Join-Path $OutDir "stage"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
$dailyDir = Join-Path $stage "$hostName\daily"
New-Item -ItemType Directory -Force -Path $dailyDir | Out-Null
Copy-Item $csv (Join-Path $stage "$hostName\flows.csv")
Copy-Item $csv (Join-Path $dailyDir "$day.csv")
$run = Join-Path $OutDir "run.json"
if (Test-Path $run) { Copy-Item $run (Join-Path $stage "$hostName\run.json") }

try {
    if ($Method -eq "rclone") {
        $remote = "$Dest/$hostName"
        Write-Host "rclone copy $stage\$hostName $remote"
        & rclone copy (Join-Path $stage $hostName) $remote --create-empty-src-dirs
        if ($LASTEXITCODE -ne 0) { throw "rclone failed" }
    } else {
        if ($Dest -notmatch ":") { throw "SSH dest must be user@host:/path" }
        $hostPart = $Dest.Substring(0, $Dest.LastIndexOf(":"))
        $base = $Dest.Substring($Dest.LastIndexOf(":") + 1)
        $sshArgs = @("-o", "BatchMode=yes")
        $scpArgs = @("-q", "-o", "BatchMode=yes")
        if ($SshKey) {
            $sshArgs += @("-i", $SshKey)
            $scpArgs += @("-i", $SshKey)
        }
        if ($SshPort) {
            $sshArgs += @("-p", $SshPort)
            $scpArgs += @("-P", $SshPort)
        }
        & ssh @sshArgs $hostPart "mkdir -p $base/$hostName/daily"
        if ($LASTEXITCODE -ne 0) { throw "ssh mkdir failed" }
        & scp @scpArgs (Join-Path $stage "$hostName\flows.csv") "${hostPart}:${base}/${hostName}/flows.csv"
        if ($LASTEXITCODE -ne 0) { throw "scp flows.csv failed" }
        & scp @scpArgs (Join-Path $dailyDir "$day.csv") "${hostPart}:${base}/${hostName}/daily/${day}.csv"
        if ($LASTEXITCODE -ne 0) { throw "scp daily csv failed" }
        $stagedRun = Join-Path $stage "$hostName\run.json"
        if (Test-Path $stagedRun) {
            & scp @scpArgs $stagedRun "${hostPart}:${base}/${hostName}/run.json"
        }
    }
    Write-Host "ship complete"
} finally {
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
}
