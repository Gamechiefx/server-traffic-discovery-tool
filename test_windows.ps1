# Smoke-test the Windows collector on a real Windows host.
# Does not install the startup task. Writes to a temp folder and removes it.
#
# Elevated optional. Get-NetTCPConnection works for the current user.
#   powershell -ExecutionPolicy Bypass -File test_windows.ps1

[CmdletBinding()]
param(
    [int]$Minutes = 1,
    [int]$IntervalSeconds = 5,
    [switch]$KeepOutput
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutDir = Join-Path $env:TEMP ("fw-baseline-test-" + [guid]::NewGuid().ToString("N"))
$failed = 0

function Assert-True($cond, $msg) {
    if ($cond) { Write-Host "PASS $msg" }
    else { Write-Host "FAIL $msg"; $script:failed++ }
}

Write-Host "Windows smoke test on $env:COMPUTERNAME"
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Write-Host "out: $OutDir"

Assert-True (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) "Get-NetTCPConnection is available"
Assert-True (Test-Path (Join-Path $Here "collect_windows.ps1")) "collect_windows.ps1 present"
Assert-True (Test-Path (Join-Path $Here "ship.ps1")) "ship.ps1 present"
Assert-True (Test-Path (Join-Path $Here "bootstrap.ps1")) "bootstrap.ps1 present"

$collector = Join-Path $Here "collect_windows.ps1"
& $collector -Minutes $Minutes -IntervalSeconds $IntervalSeconds -OutDir $OutDir -ForceNewWindow
$csv = Join-Path $OutDir "flows.csv"
Assert-True (Test-Path $csv) "flows.csv written"
if (Test-Path $csv) {
    $rows = Import-Csv $csv
    Assert-True ($rows.Count -ge 1) "at least one unique flow row ($($rows.Count))"
    $cols = $rows[0].PSObject.Properties.Name
    foreach ($c in @("source", "destination", "port", "protocol")) {
        Assert-True ($cols -contains $c) "column $c"
    }
    $sample = $rows | Select-Object -First 5
    $sample | Format-Table source, destination, port, protocol, direction, process, count -AutoSize
}

$ship = Join-Path $Here "ship.ps1"
& $ship -OutDir $OutDir -Config (Join-Path $OutDir "missing-ship.env")
Assert-True ($LASTEXITCODE -eq 0) "ship with no dest exits 0"

$run = Join-Path $OutDir "run.json"
Assert-True (Test-Path $run) "run.json written"

if (-not $KeepOutput) {
    Remove-Item -Recurse -Force $OutDir
} else {
    Write-Host "kept $OutDir"
}

if ($failed -gt 0) {
    Write-Host "RESULT FAIL ($failed check(s))"
    exit 1
}
Write-Host "RESULT PASS"
exit 0
