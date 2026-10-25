# Review 2 — Live Demo Cheat-Sheet

Everything you type, in order, with what to say at each step. Total time ~4 min.
Run from the `arp_toolkit` folder. Python is installed at
`C:\Users\akksh\AppData\Local\Programs\Python\Python312\python.exe` (not on PATH),
so the commands below set a `$PY` shortcut first.

> **Fastest option:** just run `powershell -ExecutionPolicy Bypass -File run_review2.ps1`
> — it does steps 1–4 and opens the dashboard. Use the step-by-step below if you
> want to narrate each stage to the reviewer.

---

## 0. Set up the Python shortcut (PowerShell)

```powershell
$PY = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
cd "$env:USERPROFILE\OneDrive\Desktop\CN\arp_toolkit"
```

## 1. Show the system is real — audit this machine's live ARP table
*"First, the diagnosis side: our auditor reads the real OS ARP table and flags anomalies. Here it is on this laptop."*
```powershell
& $PY arp_audit.py
```
→ Prints the live table, classifies static/dynamic, flags duplicates. 0 anomalies = healthy.

## 2. Generate the labelled test data
*"For repeatable evaluation we generate a labelled capture — five benign scenarios and five attacks — as a pcap. Nothing is sent on a network; these are fixtures."*
```powershell
& $PY make_captures.py --out test_data
```
→ Writes `arp_dataset.pcap`, `labels.json`, `baseline.json` (100 packets, 10 episodes).

## 3. Run the detector and show a critical catch
*"The detection engine runs the five signals with context scoring. Here are the high-severity incidents it raises."*
```powershell
& $PY detect.py --pcap test_data\arp_dataset.pcap --baseline test_data\baseline.json --min-tier HIGH
```
→ Point at the **gateway_impersonation → CRITICAL** incident and its recommended mitigation.

## 4. Run the evaluation — the measured metrics
*"Against the labelled ground truth, these are our four metrics — all measured, not mock."*
```powershell
& $PY evaluate.py --data test_data --out reports
```
→ Read out: **Detection 100%, False-positive 0%, latency ~140 ms mean, mitigation 80%.**
Explain the 80%: the ARP flood is correctly rated MEDIUM, so it gets a *ticket*, not an
auto-quarantine — proportionate response, by design.

## 5. Open the dashboard
*"And the same results in the operations dashboard."*
```powershell
& $PY dashboard.py --reports reports --data test_data --out dashboard.html
start dashboard.html
```

---

## If asked "does it work on live traffic?"
Yes — the same engine runs live via `detect.py --live -i "Ethernet"` (needs Npcap +
Administrator). We demo from a pcap so the results are repeatable and labelled.

## If asked "are the numbers real?"
Yes — every figure comes from the detector running over the labelled dataset
(`evaluate.py`). The Review 1 dashboard numbers were explicitly mock-ups; these are measured.

## If asked "what's the attacker side / did you build an attack tool?"
No. We generate labelled *packets in a file* to test the detector (standard IDS evaluation).
The project is defensive: detect, score, recommend. Enforcement (DAI / port quarantine)
is done by the switch, per the Cisco configs in `configs/`.

## Recovery
If anything errors, just run the all-in-one:
```powershell
powershell -ExecutionPolicy Bypass -File run_review2.ps1
```
