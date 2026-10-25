# Enterprise ARP Analysis & Threat Detection

**Problem Analysis, Network Design, Detection & Prevention**

**Team:** Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan
**Course:** Computer Networks and Data Communication

---

## 1. Abstract

The Address Resolution Protocol (ARP) binds Layer-3 IPv4 addresses to Layer-2
MAC addresses so that frames can be delivered inside a LAN. ARP is essential but
**unauthenticated**: any host can claim any IP, and receivers cache the claim.
This exposes enterprise LANs to ARP spoofing and, above all, **gateway
impersonation**, enabling man-in-the-middle interception, session hijacking and
denial of service.

This project is delivered in two parts. **Part 1 (Diagnosis)** builds a
multi-VLAN enterprise LAN, analyses how ARP resolves addresses at packet level,
and documents the normal and failing behaviours. **Part 2 (Solution)** is a
working **Intrusion Detection & Prevention (IDP)** prototype, `arpguard`, that
monitors ARP (live or from capture), scores every IP-to-MAC claim against a
trusted baseline with context, and takes proportionate, reversible defensive
action. Measured on labelled datasets, the detector achieves **100% detection
and 0% false positives** with **sub-second latency**, on both a single-VLAN and
a multi-VLAN (10/20/30) topology. The system **complements** switch controls
(Dynamic ARP Inspection, DHCP snooping, port security), adding memory, risk
ranking and cross-VLAN visibility.

---

## 2. Introduction & the industry problem

Devices know a destination's **IP**, but Ethernet delivery needs its **MAC**.
ARP (RFC 826) resolves this dynamically: a host **broadcasts** a request
("Who has 192.168.10.20? Tell 192.168.10.10") and the owner answers with a
**unicast** reply ("192.168.10.20 is-at …"). The binding is cached until it ages
out. Failed or forged resolution causes latency, connectivity loss, or silent
interception.

**Problem investigated:** *How does an enterprise device resolve a known IPv4
address to a MAC, how can an administrator verify it through packet analysis,
and how can ARP-based attacks be detected and prevented accurately and with few
false positives?*

---

## 3. Project overview — two parts

| Part | Question | Deliverables |
|------|----------|--------------|
| **1 — Diagnosis** | How does ARP work and fail on the LAN? | `lab/`: topology, Cisco configs, IP plan, observation tables, build+capture guide |
| **2 — Solution** | How do we detect and prevent ARP attacks? | `arp_idp/`: the `arpguard` IDP — detection engine, scoring, prevention, dashboard, tests |

---

## 4. Part 1 — Diagnosis (network design & ARP analysis)

### 4.1 Topology

A multi-VLAN LAN (see `lab/topology.svg`), router-on-a-stick on R1:

| VLAN | Subnet | Role | Gateway |
|------|--------|------|---------|
| 10 | 192.168.10.0/24 | users (PC1, PC2) | 192.168.10.1 |
| 20 | 192.168.20.0/24 | servers | 192.168.20.1 |
| 30 | 192.168.30.0/24 | guest | 192.168.30.1 |

SW1 (Catalyst 2960) provides access ports and a **SPAN** port mirroring all
VLANs to the IDP sensor. Static addressing means every IP-to-MAC mapping is
known in advance, so observed ARP can be checked rather than trusted.

### 4.2 ARP packet flow

**Same subnet (PC1 → PC2):** PC1 broadcasts a request (opcode 1, Ethernet dst
`FF:FF:FF:FF:FF:FF`, ARP target MAC all-zero); SW1 learns PC1's MAC on its port
and floods the broadcast; PC2 replies by unicast (opcode 2); SW1 forwards the
reply only on the learned port; PC1 caches the binding and sends ICMP.

**Across subnets (PC1 → Server in VLAN 20):** PC1 ANDs the destination with its
mask, finds it non-local, and ARPs for the **gateway** instead. R1 replies with
its subinterface MAC; PC1's frames to the server carry R1's MAC. The server's
MAC never appears in VLAN 10 — PC1's `arp -a` shows only 192.168.10.x entries.

### 4.3 Diagnosis tooling

`arpguard audit` reads the host's live OS ARP table and checks it against the
trusted baseline; `arpguard analyze <pcap>` parses a Wireshark/Packet-Tracer
export and reports request→reply behaviour and anomalies. Observation tables
(`lab/observation_tables.md`) record expected vs observed for each flow.

---

## 5. Part 2 — Solution (the IDP)

### 5.1 Why ARP is exploitable

No authentication; stateless and trusting (gratuitous replies accepted);
last-write-wins caching; broadcast reach. These are protocol *properties*. The
whole attack family shares one signature — **an unexpected IP-to-MAC binding** —
so one detector covers all of them.

### 5.2 Architecture

```
ARP (pcap | live) → Ingestion → DetectionEngine → Incident → Responder
  ArpObservation     normalise    6 signals + context  score+tier   recommend / pin / quarantine / reassert
  (+ baseline)                    (weights from YAML)   5 tiers
                                        ├─ backtest / metrics (labels)
                                        └─ audit (live OS ARP table)
```

Each stage is an independent module; weights live in
`config/signal_weights.yaml`, not in code.

### 5.3 Trusted baseline (the "memory")

Gateway/server **anchors** (never silently overwritten), a known-MAC inventory,
and the **context** that explains benign change — DHCP events, maintenance
windows, business hours. Non-anchor bindings are learned at runtime.

### 5.4 Detection signals

| Signal | Fires when | Base tier |
|--------|-----------|-----------|
| `gateway_impersonation` | a non-anchor MAC claims a gateway IP | CRITICAL (never lowered) |
| `mac_change` | a known IP's MAC changes | HIGH (anchor) / MEDIUM |
| `duplicate_ip` | ≥2 MACs claim one IP in the window | HIGH |
| `abnormal_rate` | a MAC's ARP volume exceeds the threshold | MEDIUM |
| `unknown_device` | a MAC not in inventory / off-hours | LOW |
| `cross_vlan` | one MAC seen in two VLANs (lateral movement) | MEDIUM |

### 5.5 Context-aware scoring

`points = base_weight(tier) × context_factor`, summed per offending binding →
tier (Critical ≥100, High ≥70, Medium ≥40, Low ≥15, else Info). DHCP renewal
×0.2, maintenance ×0.25, failover ×0.3 (lower); off-hours ×1.3–1.4, unknown MAC
×1.2 (raise). Gateway impersonation is never lowered.

### 5.6 Prevention tier (the "P" in IDP)

Proportionate, defensive, reversible actions, by policy tier:

| Action | From tier | Effect |
|--------|-----------|--------|
| `recommend` | MEDIUM | emit the proportionate recommended action |
| `pin_anchor` | HIGH | static-ARP the TRUE anchor binding on the host (poison can't overwrite) |
| `quarantine` | HIGH | generate the switch IOS command to err-disable the offending port |
| `reassert` | CRITICAL | broadcast a corrective gratuitous ARP for the true binding |

Default is **dry-run**; `--apply` runs the host-safe actions. The sensor detects
and recommends; the switch enforces.

---

## 6. Evaluation

### 6.1 Methodology

Labelled synthetic datasets (Phase 1 replay + Phase 2 simulated traffic). An
**alert** is an incident at tier ≥ Medium; Info/Low are logged, not alerted.
Ground truth is labelled, so every alert is scored true/false.

### 6.2 Results — single VLAN (10 episodes, 5 attack / 5 benign)

| Metric | Result |
|--------|--------|
| Detection rate | **100%** (5/5) |
| False-positive rate | **0%** (5/5 benign cleared) |
| Detection latency | **140 ms mean, 600 ms max** |
| Mitigation effect | **80%** containing action |
| Confusion | TP=5 FN=0 FP=0 TN=5 |

### 6.3 Results — multi-VLAN 10/20/30 (7 episodes, 4 attack / 3 benign)

| Metric | Result |
|--------|--------|
| Detection rate | **100%** (4/4, incl. cross-VLAN lateral movement) |
| False-positive rate | **0%** (3/3 benign cleared) |
| Detection latency | **250 ms mean, 1000 ms max** |
| Mitigation effect | **75%** containing action |
| Confusion | TP=4 FN=0 FP=0 TN=3 |

### 6.4 Reading the results honestly

- **Latency spread is meaningful.** Gateway/poisoning attacks are caught on the
  first malicious packet (~0 ms); rate, duplicate and cross-VLAN signals need a
  few packets (or the MAC's appearance in a second VLAN) to confirm, raising the
  mean and the 600–1000 ms maxima.
- **Mitigation 75–80% is by design.** The ARP flood and cross-VLAN movement are
  rated Medium → ticket + watch, not auto-quarantine. We do not cut off a device
  on one Medium signal.
- **Zero false positives, with context.** Renewal and onboarding are
  DHCP-explained (Info); move and failover fall in maintenance windows (Low).
- **Synthetic data caveat.** Figures are from labelled synthetic datasets, not
  production traffic; absolute numbers would shift on live data. The methodology
  (labelled replay) is sound and extensible.

### 6.5 Validation

21 automated tests (`pytest`) cover the baseline, every detection signal, the
scoring, the prevention responder and the backtest metrics — all passing.

---

## 7. Switch-side hardening (prevention enforcement)

`lab/configs/` configure the network to *enforce* what the sensor detects:

- **Dynamic ARP Inspection + DHCP snooping** on SW1 drop forged ARP on untrusted
  ports; the R1 trunk is trusted; a static ARP ACL permits the server anchor.
- **Port security** (sticky, max 1, violation restrict) defeats MAC flooding and
  rogue hosts; ARP rate-limited per access port.
- **Static ARP + short timeout** anchor the gateway and server on R1.

Defense-in-depth: the IDP adds memory, risk ranking, cross-VLAN visibility and
incident history on top of this in-line enforcement.

---

## 8. Implementation & how to run

```bash
cd arp_idp
pip install -e ".[dev]"                      # scapy, typer, rich, pyyaml, pytest
python main.py gen-data                      # single-VLAN fixtures
python main.py gen-data --variant multivlan  # multi-VLAN (10/20/30) fixtures
python main.py analyze test_data/arp_dataset.pcap --detail
python main.py backtest --data test_data
python main.py respond  test_data/arp_dataset.pcap       # detection + prevention (dry-run)
python main.py watch -i "Ethernet" --prevent             # live IDP (Npcap + admin)
pytest -q                                                 # 21 tests
```

Modules: `src/models` (schemas), `src/detection` (baseline, engine),
`src/ingestion` (pcap/live), `src/prevention` (responder), `src/evaluation`
(backtest), `src/data` (scenarios), `src/utils` (formatting, logging),
`config/` (YAML weights, settings), `main.py` (Typer CLI).

---

## 9. Limitations

- Results are on synthetic labelled datasets, not production traffic.
- Datasets are modest (10 / 7 episodes) — they demonstrate each signal, not
  statistical significance.
- Thresholds are tuned for this topology; a real deployment needs a per-site
  learning period.
- Live capture needs Npcap + Administrator and a SPAN/mirror port; some Packet
  Tracer images do not implement DAI/SPAN (documented workaround: analyse an
  exported pcap).

---

## 10. Conclusion

ARP is simple, essential and inherently trusting; in a flat or multi-VLAN
enterprise LAN that trust is a liability. Combining **packet-level diagnosis**,
**context-aware detection**, **proportionate prevention**, and **switch-enforced
validation** turns ARP from a soft target into an observable, defensible part of
the network. The `arpguard` prototype makes each step reproducible and
measurable, achieving perfect detection with no false positives on the test
datasets while keeping response proportionate.

---

## 11. References

- D. Plummer, *RFC 826: An Ethernet Address Resolution Protocol*, IETF, 1982.
- Cisco, *Dynamic ARP Inspection & DHCP Snooping Configuration Guide*.
- NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems (IDPS)*.
- Scapy (scapy.net); Wireshark ARP dissector (wireshark.org).
- B. A. Forouzan, *Data Communications and Networking*, 5th ed., McGraw-Hill.

---

## Appendix — command reference

| Command | Purpose |
|---------|---------|
| `arpguard gen-data [--variant multivlan]` | build labelled fixtures |
| `arpguard scenarios` | list benign/attack episodes |
| `arpguard analyze <pcap> [--detail] [--json out]` | detect over a capture |
| `arpguard respond <pcap> [--apply]` | detect + prevention |
| `arpguard backtest --data <dir>` | metrics vs ground truth |
| `arpguard watch -i <iface> --prevent [--apply]` | live IDP |
| `arpguard audit` | host ARP table vs baseline |
| `arpguard weights` | scoring configuration |
