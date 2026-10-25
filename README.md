# Enterprise ARP Analysis & Threat Detection

**Problem Analysis · Network Design · Detection & Prevention**
Team: Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan
Course: Computer Networks and Data Communication

One project, two parts: a **diagnosis** of how ARP resolves addresses and fails
on an enterprise LAN, and a working **Intrusion Detection & Prevention (IDP)**
system that detects and contains ARP attacks.

## Submission map

| File / folder | What it is |
|---|---|
| **`FINAL_REPORT.docx`** / `.md` | The complete project report (both parts, results, references) |
| **`Enterprise_ARP_Analysis_and_Detection_FINAL.pptx`** | The consolidated presentation (15 slides) |
| **`lab/`** | **Part 1 — Diagnosis:** topology, Cisco configs, IP plan, observation tables, build+capture guide |
| **`arp_idp/`** | **Part 2 — Solution:** the `arpguard` IDP (detection + prevention), tests |
| `arp_toolkit/` | Supplementary: earlier analysis scripts, the Review-2 deck & HTML dashboard |

## Part 1 — Diagnosis (`lab/`)

- `topology.svg` — multi-VLAN LAN (VLAN 10 users / 20 servers / 30 guest), router-on-a-stick, SW1 with DAI + a SPAN port to the IDP sensor
- `configs/R1_startup-config.txt`, `configs/SW1_startup-config.txt` — production-style Cisco configs (subinterface gateways, DHCP snooping, Dynamic ARP Inspection, port security, SPAN)
- `IP_plan.md` — full addressing + anchor MACs
- `observation_tables.md` — expected vs observed for each ARP flow (fill from your capture)
- `BUILD_AND_CAPTURE.md` — step-by-step Packet Tracer build + Wireshark capture + feeding the IDP

## Part 2 — Solution: `arpguard` (`arp_idp/`)

A Typer + Rich CLI IDP. Setup and run:

```bash
cd arp_idp
pip install -e ".[dev]"                       # scapy, typer, rich, pyyaml, pytest
python main.py gen-data                        # single-VLAN labelled fixtures
python main.py gen-data --variant multivlan    # multi-VLAN (10/20/30) fixtures
python main.py analyze test_data/arp_dataset.pcap --detail
python main.py backtest --data test_data       # metrics vs ground truth
python main.py respond  test_data/arp_dataset.pcap     # detection + prevention (dry-run)
python main.py watch -i "Ethernet" --prevent          # live IDP (Npcap + admin)
pytest -q                                              # 21 tests
```

**Six detection signals** (gateway impersonation, MAC change, duplicate IP,
abnormal rate, unknown device, cross-VLAN) → **context-aware risk scoring** →
**five tiers** → **proportionate prevention** (recommend / pin-anchor /
quarantine / reassert).

## Measured results

| Dataset | Detection | False-positive | Latency (mean/max) | Mitigation |
|---|---|---|---|---|
| Single VLAN (10 episodes) | 100% | 0% | 140 / 600 ms | 80% |
| Multi-VLAN 10/20/30 (7 episodes) | 100% | 0% | 250 / 1000 ms | 75% |

All figures are measured from detector runs over labelled datasets (not mock
values); 21 automated tests pass. Synthetic data — absolute numbers would shift
on live production traffic.

## Scope & ethics

A defensive, academic project for a lab you own or are authorized to test. The
IDP **detects, scores and recommends**; enforcement (DAI / port quarantine) is
performed by the switch. "Attack" data is labelled packets written to a `.pcap`
fixture for testing the detector — never transmitted.
