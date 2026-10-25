# arpguard

Context-aware **ARP Intrusion Detection & Prevention (IDP)** for enterprise LANs. It ingests ARP traffic (live or from a PCAP), compares every IP-to-MAC claim against a trusted baseline with gateway/server **anchors**, runs modular **detection signals**, combines them with per-device **context**, and emits a composite **risk score** and tier (`INFO` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) — as a Rich terminal report or JSON. At or above a policy tier it takes proportionate, **defensive, reversible prevention** actions.

It runs **fully offline** against labelled PCAP fixtures, or **live** against a sniffed interface (Npcap + Administrator).

> Team: Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan — Computer Networks and Data Communication

## Quick start

```bash
# Python 3.12 (already installed). Scapy + Typer + Rich + PyYAML:
pip install -e ".[dev]"      # or: pip install scapy typer rich pyyaml

python main.py gen-data                                   # build labelled fixtures
python main.py scenarios                                  # list benign/attack episodes
python main.py analyze test_data/arp_dataset.pcap         # detect over a capture
python main.py analyze test_data/arp_dataset.pcap --detail --min-tier HIGH
python main.py backtest --data test_data                  # metrics vs ground truth
python main.py respond  test_data/arp_dataset.pcap        # detect + prevention (dry-run)
python main.py weights                                    # show the scoring config
```

### Live IDP

```bash
python main.py watch -i "Ethernet" --prevent             # live detect + recommend
python main.py watch -i "Ethernet" --prevent --apply     # host-safe prevention (admin)
python main.py audit                                      # check host ARP table vs baseline
```

Live capture needs **Npcap** (WinPcap-compatible mode) and Administrator on Windows; `--apply` writes static-ARP pins (reversible). The prototype **detects, scores and recommends**; switch enforcement (DAI / port quarantine) is emitted as commands for the operator.

## What it does

```
ARP (pcap | live) ──► Ingestion ──► DetectionEngine ──► Incident ──► Responder
   ArpObservation      normalise      5 signals + context    score + tier    recommend
   (+ baseline)                       (weights from YAML)    5 risk tiers    pin_anchor
                                                                             quarantine (switch cmd)
                                             ┌─ backtest / metrics (labels)  reassert
                                             └─ audit (live OS ARP table)
```

| Layer | Module | Role |
|---|---|---|
| Schemas | `src/models/incident.py` | `ArpObservation`, `Flag`, `Incident`, `RiskTier`. Unknown facts are `None`. |
| Config | `config/signal_weights.yaml`, `config/settings.py` | Signal severities, base weights, context factors, tier thresholds and the response policy. Every signal **must** have a weight — the engine fails fast otherwise. |
| Ingestion | `src/ingestion/sources.py` | PCAP replay and live sniff → normalised observations. |
| Baseline | `src/detection/baseline.py` | Trusted IP→MAC store: gateway/server anchors, known-MAC inventory, DHCP events, maintenance windows. |
| Detection | `src/detection/engine.py` | Five signals → scored flags → incidents. Points come from YAML, not code. |
| Prevention | `src/prevention/responder.py` | Proportionate defensive actions: recommend, pin anchor (static ARP), switch quarantine (generated), corrective re-assert. Dry-run by default. |
| Evaluation | `src/evaluation/backtest.py` | Detection rate, false-positive rate, latency, mitigation effect vs labelled ground truth. |
| Data | `src/data/scenarios.py` | Labelled benign + attack fixtures (packets to a PCAP, never transmitted). |
| CLI | `main.py` | `gen-data`, `scenarios`, `analyze`, `respond`, `backtest`, `watch`, `audit`, `weights`. |

## Detection signals

| Signal | Fires when | Base tier |
|---|---|---|
| `gateway_impersonation` | a non-anchor MAC claims a gateway IP | CRITICAL (never lowered) |
| `mac_change` | a known IP's MAC changes | HIGH (anchor) / MEDIUM |
| `duplicate_ip` | two+ MACs claim one IP within the window | HIGH |
| `abnormal_rate` | a MAC's ARP volume exceeds the threshold | MEDIUM |
| `unknown_device` | a MAC not in inventory / off-hours | LOW |

Context factors (DHCP renewal, maintenance window, failover, off-hours, unknown MAC) raise or lower each signal; gateway impersonation is never lowered. See `config/signal_weights.yaml`.

## Prevention (the "P" in IDP)

All actions are **defensive, restorative and reversible**, and touch only the trusted anchors' own bindings:

| Action | From tier | Effect |
|---|---|---|
| `recommend` | MEDIUM | emit the proportionate recommended action |
| `pin_anchor` | HIGH | add a static ARP entry for the TRUE anchor binding on this host (poison can't overwrite it) |
| `quarantine` | HIGH | generate the switch IOS command to err-disable the offending port (operator applies) |
| `reassert` | CRITICAL | broadcast a corrective gratuitous ARP re-announcing the true anchor binding |

`respond`/`watch` default to **dry-run** (actions described, not executed). Pass `--apply` to run the host-safe actions.

## Measured results (offline fixtures)

`python main.py backtest --data test_data`:

| Metric | Result |
|---|---|
| Detection rate | **100%** (5/5 attacks) |
| False-positive rate | **0%** (5/5 benign cleared) |
| Detection latency | **~140 ms mean, 600 ms max** |
| Mitigation effect | **80%** (containing action; flood correctly → ticket, not quarantine) |

All figures are measured from a detector run over the labelled dataset — not mock values.
Synthetic dataset; absolute numbers would shift on live production traffic.
