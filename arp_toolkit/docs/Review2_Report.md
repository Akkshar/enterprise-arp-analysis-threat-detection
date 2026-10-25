# Enterprise ARP Threat Detection — Review 2 Report

**Context-aware anomaly detection and mitigation for enterprise LANs**

**Team:** Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan
**Course:** Computer Networks and Data Communication

---

## 1. Abstract

ARP has no authentication: any host can claim any IP, and receivers cache the
claim. This makes ARP spoofing — above all **gateway impersonation** — a direct
path to man-in-the-middle interception, session hijacking and denial of service.
Switch controls such as Dynamic ARP Inspection (DAI) act per-packet with no
memory of what is normal for each device, so they can miss subtle attacks or
drown operators in alerts.

This project builds a **context-aware ARP threat detection** prototype. It
monitors ARP (live or from capture), maintains a trusted IP-to-MAC baseline with
gateway/server **anchors**, runs **five detection signals**, and combines them
with per-device **context** into a **risk score** across five tiers. Each
incident carries the evidence and a proportionate recommended action. Measured
against a labelled dataset of benign and attack episodes, the detector achieves
**100% detection, 0% false positives, ~140 ms mean latency**, and routes 80% of
detected attacks to a containing action (the remainder to a watch-and-ticket
action, by design). The system **complements**, rather than replaces, DAI and
port security.

This report maps directly to the Review 1 plan and the project proposal, and
reports only **measured** figures — the Review 1 dashboard numbers were
explicitly mock-ups.

---

## 2. Two parts: diagnosis and solution

| Part | Question | Delivered as |
|------|----------|--------------|
| **Diagnosis** | What is happening on the LAN, and is any ARP binding wrong? | Live monitor, ARP-table auditor, PCAP analyzer, the detection engine's signals |
| **Solution** | How do we decide what matters and contain it without disruption? | Context-aware risk scoring, proportionate mitigation guidance, Cisco DAI + port-security configs |

---

## 3. Background: why ARP is exploitable (recap)

- **No authentication** — a receiver cannot verify who sent an ARP message.
- **Stateless and trusting** — unsolicited (gratuitous) replies are accepted.
- **Last write wins** — a newer binding silently overwrites the cache.
- **Broadcast reach** — one forged reply can reach the whole VLAN.

These are protocol *properties*, not bugs. The fix is monitoring and
verification **around** ARP, which is exactly what this system provides.

The whole attack family (spoofing, cache poisoning, MITM, gateway
impersonation, session hijacking, DoS) shares one signature: **an unexpected
IP-to-MAC binding**. One detector therefore covers all of them.

---

## 4. System architecture

A five-stage pipeline; each stage is an independent module.

```
 ARP (live sniff / PCAP)
        │
   1. CAPTURE  ──► normalise every packet to (time, op, src_ip, src_mac, ...)
        │
   2. BASELINE ──► trusted IP→MAC store: gateway & server ANCHORS,
        │           known-MAC inventory, DHCP events, maintenance windows
        │
   3. DETECT   ──► five signals compare each claim against baseline + state
        │
   4. SCORE    ──► signal weight × context factor, summed → 5 risk tiers
        │
   5. RESPOND  ──► incident (evidence + recommended action) → dashboard / log
```

Code modules (all in `arp_toolkit/`):

| Module | Responsibility |
|--------|----------------|
| `detection_engine.py` | Baseline, five signals, context scoring, incidents |
| `detect.py` | Capture front-end (PCAP or live) → incidents |
| `make_captures.py` | Labelled benign + attack dataset + matching baseline |
| `evaluate.py` | Metrics vs ground truth |
| `dashboard.py` | HTML dashboard from real output |
| `arp_audit.py`, `arp_monitor.py`, `pcap_analyzer.py` | Diagnosis-side tools |
| `configs/` | Cisco R1 + 2960 configs: DAI, DHCP snooping, port security |

---

## 5. The trusted baseline (the "memory")

The baseline is what makes detection *context-aware* instead of per-packet.

- **Anchors** — the gateway (critical) and static servers (high). An anchor is
  **never silently overwritten** by observed traffic; it changes only through a
  verified administrative update.
- **Known-MAC inventory** — the set of legitimate device MACs.
- **DHCP events** — `{ip, mac, time, window}` entries that *explain* a legitimate
  MAC change (a lease renewal).
- **Maintenance windows** — `{start, end, ip}` intervals that explain planned
  moves, NIC swaps and failovers.
- **Business hours** — activity outside them raises suspicion.
- **Learned bindings** — non-anchor IP→MAC pairs learned at runtime from benign
  traffic, so later changes become detectable.

> *A MAC change that matches a DHCP renewal or a maintenance window is expected.
> The same change with no such context is suspicious. An unexplained change to
> the **gateway** anchor is always critical.*

---

## 6. The five detection signals

| # | Signal | Fires when | Base tier |
|---|--------|-----------|-----------|
| 1 | **Gateway impersonation** | a non-anchor MAC claims a gateway IP | **Critical** (never lowered) |
| 2 | **MAC change** | a known IP's MAC changes | High (anchor) / Medium |
| 3 | **Duplicate IP** | ≥2 MACs claim one IP within the window | High |
| 4 | **Abnormal rate** | a MAC's ARP volume exceeds the threshold | Medium |
| 5 | **Unknown device** | a MAC not in inventory / off-hours | Low |

---

## 7. Context-aware risk scoring

Each firing signal contributes points:

```
points = base_weight(tier) × context_factor
incident_score = Σ points   (over the signals firing for the same device)
```

Base weights: Critical 100, High 70, Medium 40, Low 15, Info 5.
Context factors (examples):

| Situation | Factor | Effect |
|-----------|-------:|--------|
| MAC change matches a DHCP renewal | ×0.2 | strongly lowers |
| Change inside a maintenance window | ×0.25 | strongly lowers |
| Duplicate IP during a known failover | ×0.3 | lowers |
| Activity off-hours | ×1.3–1.4 | raises |
| An unknown MAC is involved | ×1.2 | raises |
| **Gateway impersonation** | ×1.0 | **never lowered** |

The total maps to a tier: Critical ≥100, High ≥70, Medium ≥40, Low ≥15, else
Info. A gateway-impersonation signal forces at least Critical regardless of
score, so no benign context can ever explain away a gateway claim.

**Worked example — gateway impersonation (real output):**
```
[CRITICAL] score=121.0  IP 192.168.10.1 claimed by de:ad:be:ef:00:66
                        (expected 00:1a:2b:00:00:01)
   - gateway_impersonation (100.0): claims gateway 192.168.10.1
   - unknown_device (21.0): not in known inventory [off-hours]
   -> Quarantine the switch port; drop via DAI; notify SOC immediately.
```

---

## 8. Evaluation methodology

Following the proposal's phased plan:

- **Phase 1 — replay:** a labelled `.pcap` with ground-truth episode labels.
- **Phase 2 — simulated traffic:** scripted benign events *and* attacks.
- *(Phase 3 — live multi-VLAN lab: stretch goal, not required for Review 2.)*

The dataset (`make_captures.py`) contains **10 episodes / 100 packets**:

| Benign (must **not** alert) | Attack (must alert) |
|---|---|
| Normal resolution | Gateway impersonation (off-hours) |
| DHCP lease renewal | Gratuitous-ARP poisoning (server) |
| Authorised device move / NIC swap | MITM relay |
| Server failover (registered standby) | ARP request flood |
| New-device onboarding | Duplicate-IP conflict |

An **alert** is an incident at tier ≥ Medium; Info/Low are logged but not
alerted (matching the alerting policy). Ground truth is labelled, so every alert
is scored true/false.

---

## 9. Results (measured)

```
Confusion matrix:  TP=5  FN=0  FP=0  TN=5   (alert tier ≥ MEDIUM)

Detection rate      : 100.0 %   (5/5 attacks caught)
False-positive rate :   0.0 %   (0/5 benign flagged)
Detection latency   : mean ~140 ms, max 600 ms  (first malicious ARP → alert)
Mitigation effect   :  80.0 %   (4/5 detected attacks get a containing action)
```

| Metric | Result | Proposal target | Met? |
|--------|--------|-----------------|------|
| Detection rate | 100% | high | ✅ |
| False-positive rate | 0% | low | ✅ |
| Detection latency | ~140 ms mean, 600 ms max | sub-second | ✅ |
| Mitigation effect | 80% containing | effective | ✅ (see note) |

**Reading the numbers honestly:**

- **Latency spread is meaningful.** Gateway impersonation and poisoning are
  caught on the first malicious packet (~0 ms). The flood takes until its rate
  crosses the threshold (~600 ms), and the duplicate-IP conflict until the second
  claimant appears. The mean (~140 ms) reflects that mix.
- **The 80% mitigation is correct behaviour, not a miss.** The ARP flood is
  rated Medium, so its recommended action is *raise a ticket and watch*, not an
  automatic port quarantine. Proportionate response is a design goal: we do not
  cut off a device on a single Medium signal.
- **No false positives** because context explains all five benign scenarios:
  the renewal and onboarding are DHCP-explained (Info), the move and failover
  fall in maintenance windows (Low).

---

## 10. Mitigation — the solution side

The sensor **detects, scores and recommends**; **enforcement stays with the
switch**. Recommended actions by tier:

| Tier | Recommended action |
|------|--------------------|
| Critical | Quarantine the switch port; drop via DAI; notify SOC |
| High | Isolate/verify the device; drop forged ARP via DAI; priority ticket |
| Medium | Raise a ticket; watch the device; verify the binding |
| Low / Info | Log for history and trend analysis |

Enforcement is configured on the network (see `configs/`):

- **Dynamic ARP Inspection + DHCP snooping** on the 2960 — drops forged ARP on
  untrusted ports against the snooping binding table (the strongest control).
- **Port security (sticky, max 1, violation restrict)** — one MAC per access
  port; defeats MAC flooding and rogue hosts.
- **Static ARP + short timeout** on R1 for the gateway/server anchors.

This is the defense-in-depth the proposal describes: our system adds **memory,
risk ranking, cross-device visibility and incident history** on top of the
switch's in-line enforcement.

---

## 11. Limitations and honesty

- Results are on a **synthetic labelled dataset**, not production traffic;
  real networks have more noise and edge cases. The methodology (labelled replay)
  is sound and extensible, but absolute percentages would shift on live data.
- The dataset is **modest (10 episodes)**; it demonstrates each signal and the
  benign/attack separation, not statistical significance.
- Thresholds (rate limit, windows) are **tuned for this topology**; a real
  deployment needs a learning period per site.
- Live capture needs **Npcap + Administrator** (Windows) and a SPAN/mirror port
  to see other hosts' traffic.

---

## 12. What was delivered vs the Review 1 plan

| Review 1 "Plan toward Review 2" | Status |
|---|---|
| Capture + trusted-binding store | ✅ `detect.py`, baseline in `detection_engine.py` |
| Detection engine (5 signals + scoring) | ✅ `detection_engine.py` |
| Dashboard (alerts, flagged devices, history) | ✅ `dashboard.py` |
| Simulation (benign + attack scenarios) | ✅ `make_captures.py` |
| Evaluate + tune (the 4 metrics) | ✅ `evaluate.py` |
| Live multi-VLAN lab | Stretch goal — future work |

---

## 13. Next steps (toward the final submission)

1. **Live multi-VLAN lab** (GNS3/Packet Tracer) on a SPAN port — Phase 3.
2. **Larger, noisier dataset** and a rule-only / DAI-only baseline to quantify
   the benefit of the context layer.
3. **Persist** incidents to a database and add trend analysis.
4. **Threshold auto-tuning** from a learning window per site.

---

## 14. References

- D. Plummer, *RFC 826: An Ethernet Address Resolution Protocol*, IETF, 1982.
- Cisco, *Dynamic ARP Inspection & DHCP Snooping Configuration Guide*.
- NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems*.
- Scapy (scapy.net); Wireshark ARP dissector (wireshark.org).
- B. A. Forouzan, *Data Communications and Networking*, 5th ed., McGraw-Hill.
