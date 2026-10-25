# run_review2.ps1 - One-command pipeline for the ARP Threat Detection demo.
# Generates the labelled dataset, runs the detector + evaluation, builds the
# dashboard, and opens it. Run from the arp_toolkit folder:
#     powershell -ExecutionPolicy Bypass -File run_review2.ps1

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# --- locate a real Python (not the Microsoft Store stub) ---
function Resolve-Python {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { return "py" }
    $p = Get-Command python -ErrorAction SilentlyContinue
    if ($p -and $p.Source -notlike "*WindowsApps*") { return $p.Source }
    throw "No real Python found. Install Python 3.12 from python.org."
}
$PY = Resolve-Python
Write-Host "Using Python: $PY`n" -ForegroundColor Cyan

Write-Host "[1/3] Generating labelled dataset..." -ForegroundColor Yellow
& $PY make_captures.py --out test_data

Write-Host "`n[2/3] Running detector + evaluation..." -ForegroundColor Yellow
& $PY evaluate.py --data test_data --out reports

Write-Host "`n[3/3] Building dashboard..." -ForegroundColor Yellow
& $PY dashboard.py --reports reports --data test_data --out dashboard.html

Write-Host "`nDone. Opening dashboard..." -ForegroundColor Green
Start-Process (Resolve-Path dashboard.html)
