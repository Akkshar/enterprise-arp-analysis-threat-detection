# Review Runbook — how to present "Enterprise ARP Analysis & Threat Detection"

Keep this open on a second screen/phone. ~6-minute demo + Q&A.

---

## 0. Before you walk in (one-time setup, ~30 s)

Open **PowerShell**, then:

```powershell
$PY = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
$env:PYTHONIOENCODING = "utf-8"
cd "$env:USERPROFILE\OneDrive\Desktop\CN\arp_idp"
& $PY main.py gen-data                      # pre-build the dataset so step 3 is instant
```

Have open and ready: this runbook, the deck
(`Enterprise_ARP_Analysis_and_Detection_FINAL.pptx`), and the terminal.

> **Fallback if anything misbehaves:** `powershell -ExecutionPolicy Bypass -File demo.ps1`
> runs the whole thing step-by-step with Enter-to-advance.

---

## 1. The 60-second opening (say this)

> "ARP maps IP addresses to MAC addresses inside a LAN, but it has **no
> authentication** — any device can claim any IP, and everyone believes it.
> That's the root of ARP spoofing and gateway impersonation, which enable
> man-in-the-middle and denial of service.
>
> Our project has **two parts**. Part 1 is **diagnosis** — we built a
> multi-VLAN LAN and analysed how ARP resolves addresses and where it fails.
> Part 2 is the **solution** — a working **Intrusion Detection & Prevention
> system**, `arpguard`, that scores every ARP claim against a trusted baseline
> and takes defensive action. Let me show it running."

Show the **topology slide** (deck slide 4) while you say this.

---

## 2. The live demo — 7 steps

For each: **run the command**, then **say the line**, then **point at the output**.

### Step 1 — Diagnosis on a real machine
```powershell
& $PY main.py audit
```
> "First the diagnosis side. This reads *this laptop's* real OS ARP table and
> checks each entry against our trusted baseline of known gateways and servers.
> Zero mismatches here — the host is clean."

**Proves:** it works on real data, not just our test files.

### Step 2 — The labelled dataset
```powershell
& $PY main.py scenarios
```
> "For repeatable evaluation we generate a labelled capture — five benign
> scenarios and five attacks — written to a `.pcap`. Nothing is sent on a
> network; these are test fixtures, like a lab sample."

**Proves:** proper, honest evaluation methodology (ground truth you can score against).

### Step 3 — Detect
```powershell
& $PY main.py analyze test_data/arp_dataset.pcap
```
> "The detection engine runs six signals on every ARP claim and scores each
> incident into a risk tier. Red is CRITICAL, amber HIGH, and so on. Notice the
> benign events at the bottom sit at LOW — they didn't trigger an alert."

**Proves:** it separates real attacks from normal network churn.

### Step 4 — The critical catch (the money shot)
```powershell
& $PY main.py analyze test_data/arp_dataset.pcap --detail --min-tier CRITICAL
```
> "Here's a gateway impersonation — a rogue MAC claiming the gateway IP
> 192.168.10.1. It scores CRITICAL because the gateway is an **anchor** that
> never changes silently, so no benign explanation is possible. The engine
> already recommends the response: quarantine the port and drop via DAI."

**Proves:** the core attack is caught with a clear, explained verdict.

### Step 5 — Measured results
```powershell
& $PY main.py backtest --data test_data
```
> "Against the labelled ground truth: **100% detection, 0% false positives**,
> ~140 ms mean latency. These are *measured* from the run — not mock numbers.
> Mitigation is 80%: the ARP flood is rated MEDIUM, so it gets a ticket and a
> watch, not an automatic block — that's proportionate response by design."

**Proves:** the headline numbers, and that you understand the 80% nuance.

### Step 6 — Prevention (the "P" in IDP)
```powershell
& $PY main.py respond test_data/arp_dataset.pcap --min-tier CRITICAL
```
> "This is what makes it detection *and prevention*. For a critical incident it
> produces defensive, reversible actions: pin the true gateway binding with a
> static ARP entry so poison can't overwrite it, generate the switch command to
> quarantine the port, and re-announce the correct binding. It's dry-run here;
> `--apply` would actually run the host-safe ones."

**Proves:** it's a full IDP, not just an alerting tool.

### Step 7 — Multi-VLAN + tests
```powershell
& $PY main.py gen-data --variant multivlan
& $PY main.py backtest --data test_data_mvlan
& $PY -m pytest -q
```
> "The same engine works across VLANs 10, 20 and 30, and catches **cross-VLAN
> lateral movement** — one MAC appearing in two VLANs. Again 100% detection, 0%
> false positives. And 21 automated tests prove the engine is correct."

**Proves:** it scales beyond one subnet, and the code is tested.

---

## 3. The closing (say this)

> "So: we diagnosed how ARP works and fails, then built a detection-and-
> prevention system that catches the whole attack family with perfect detection
> and no false positives on our test data, while keeping the response
> proportionate. One honest caveat — these results are on labelled **synthetic**
> datasets, not live production traffic; the methodology is sound and the next
> step is a live multi-VLAN lab on a SPAN port."

---

## 4. If the teacher asks… (crisp answers)

**"Are these numbers real or made up?"**
Real — every figure comes from `backtest` running the detector over the labelled
dataset. The only mock values were in our Review-1 dashboard mock-up; these are
measured.

**"Does it work on live traffic?"**
Yes — `arpguard watch -i Ethernet --prevent`. It needs Npcap and Administrator,
and a SPAN port to see other hosts. We demo from a pcap so results are
repeatable and labelled.

**"Did you build an attack tool?"**
No. The "attacks" are labelled packets written to a file to test the detector —
standard IDS evaluation. The project is defensive: detect, score, recommend.
The switch enforces blocking via DAI and port security.

**"How is this different from Dynamic ARP Inspection (DAI)?"**
DAI decides per packet with no memory. Ours adds **context** — it remembers each
device's normal behaviour, so a DHCP renewal is cleared but an unexplained
gateway change is critical. It ranks risk and keeps incident history. It
**complements** DAI, which does the actual enforcement.

**"What are the six signals?"**
Gateway impersonation, MAC change, duplicate IP, abnormal rate, unknown device,
cross-VLAN. Each has a weight in YAML; context factors raise or lower it;
the sum maps to a tier.

**"Why only 80% mitigation — is 20% missed?"**
No — all attacks are detected. 80% get a *containing* action (quarantine).
The flood is MEDIUM, so its action is ticket-and-watch. We deliberately don't
auto-cut-off a device on a single medium-severity signal.

**"What's the limitation?"**
Synthetic data, modest dataset size, thresholds tuned for this topology, and
live capture needs Npcap + a SPAN port. All stated in the report (§9).

---

## 5. If a command fails mid-demo
- Re-run `& $PY main.py gen-data` (rebuilds the dataset), then retry.
- Or run the whole thing non-stop: `powershell -ExecutionPolicy Bypass -File demo.ps1`.
- Worst case, open the deck slide 11 (Results) and the report §6 — the numbers
  are there.

---

## 6. 30-second concept cheat-sheet (so you can answer anything)

- **ARP** = resolves IP → MAC on a LAN. Request is broadcast, reply is unicast.
- **ARP spoofing / poisoning** = sending forged replies so victims cache a wrong
  MAC for an IP. **Gateway impersonation** = doing this for the default gateway →
  you intercept everything leaving the subnet.
- **Anchor** = a trusted binding (gateway/server) we never let change silently.
- **Context** = DHCP events, maintenance windows, business hours — the facts that
  explain *legitimate* change so we don't false-alarm.
- **Risk tier** = Info < Low < Medium < High < Critical. Alert at Medium+.
- **Prevention** = pin anchor (static ARP), quarantine port (switch), reassert
  (re-announce true binding). Reversible, defensive.
- **DAI / DHCP snooping / port security** = the switch-side enforcement our
  sensor recommends; they do the actual blocking.
