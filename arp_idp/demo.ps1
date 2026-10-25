# demo.ps1 - Run the ARP IDP review demo, step by step, with pauses.
# Open PowerShell, cd into this folder, then:
#     powershell -ExecutionPolicy Bypass -File demo.ps1
# Press Enter to advance between steps so you can narrate each one.

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"

# Find the real Python (not the Microsoft Store stub)
$PY = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
if (-not (Test-Path $PY)) { $PY = "python" }

function Step($title, $cmd) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
    Write-Host "> $cmd" -ForegroundColor DarkGray
    Read-Host "  (press Enter to run)"
    Invoke-Expression $cmd
    Write-Host ""
    Read-Host "  (press Enter for the next step)"
}

Step "1. DIAGNOSIS - audit THIS machine's live ARP table vs the baseline" `
     "& `"$PY`" main.py audit"

Step "2. The dataset - 5 benign + 5 attack scenarios (labelled fixtures)" `
     "& `"$PY`" main.py scenarios"

Step "3. DETECT - score every ARP claim in the capture" `
     "& `"$PY`" main.py analyze test_data/arp_dataset.pcap"

Step "4. Drill into the critical catch - gateway impersonation" `
     "& `"$PY`" main.py analyze test_data/arp_dataset.pcap --detail --min-tier CRITICAL"

Step "5. EVALUATE - measured metrics vs labelled ground truth" `
     "& `"$PY`" main.py backtest --data test_data"

Step "6. PREVENT - proportionate defensive actions (dry-run)" `
     "& `"$PY`" main.py respond test_data/arp_dataset.pcap --min-tier CRITICAL"

Step "7. MULTI-VLAN - detection across VLANs 10/20/30 + cross-VLAN movement" `
     "& `"$PY`" main.py gen-data --variant multivlan; & `"$PY`" main.py backtest --data test_data_mvlan"

Step "8. TESTS - 21 automated tests prove the engine is correct" `
     "& `"$PY`" -m pytest -q"

Write-Host "`nDemo complete." -ForegroundColor Green
