# Enterprise ARP Analysis — Toolkit

**Problem Analysis, Network Design & Configuration**
Team: Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan

A set of Python tools, Cisco IOS configurations, and documentation for
investigating how enterprise hosts resolve IPv4 addresses to MAC addresses
with ARP, and how to detect/mitigate ARP cache poisoning.

## Topology (single VLAN, `192.168.10.0/24`)

| Device              | IP              | Default Gateway |
|---------------------|-----------------|-----------------|
| Router **R1** (GW)  | 192.168.10.1    | —               |
| Employee **PC1**    | 192.168.10.10   | 192.168.10.1    |
| Employee **PC2**    | 192.168.10.20   | 192.168.10.1    |
| Enterprise **Server** | 192.168.10.30 | 192.168.10.1    |
| Network **Printer** | 192.168.10.40   | 192.168.10.1    |

## Contents

```
arp_toolkit/
├── arp_monitor.py          # Live ARP sniffer + spoof detector (Scapy)
├── arp_craft.py            # Craft/send ARP request, reply, gratuitous (Scapy)
├── pcap_analyzer.py        # Parse .pcap, measure request->reply latency
├── arp_audit.py            # Cross-platform ARP-table audit -> CSV/JSON (stdlib)
├── requirements.txt
├── baseline.example.json   # Trusted IP->MAC bindings
├── configs/
│   ├── R1_startup-config.txt    # Cisco ISR default gateway
│   └── SW1_startup-config.txt   # Catalyst 2960 w/ port-security + DAI
└── docs/
    ├── Technical_Report.md         # Abstract -> Security Hardening
    └── Troubleshooting_and_Security.md  # Failure matrix + spoof detection
```

## Setup

### 1. Install Python 3.9+
This machine does **not** currently have real Python installed (only the
Microsoft Store stub). Install from <https://www.python.org/downloads/> and
tick **"Add python.exe to PATH"**. Verify:

```bash
python --version
```

### 2. Install dependencies
```bash
cd arp_toolkit
pip install -r requirements.txt
```

### 3. Windows only — install Npcap
`arp_monitor.py` and `arp_craft.py` capture/inject raw frames and need
**Npcap**: <https://npcap.com> → install with *"WinPcap API-compatible Mode"*
checked. (`arp_audit.py` does **not** need Npcap.)

On Linux/macOS run the packet tools with `sudo`.

## Quick start

```bash
# Audit this machine's ARP table (no admin, no Npcap, no deps):
python arp_audit.py --csv arp_audit.csv --json arp_audit.json

# List capture interfaces, then watch live ARP and log it:
python arp_monitor.py --list
python arp_monitor.py -i "Ethernet" --log arp_events.csv

# PC1 resolves the gateway's MAC:
python arp_craft.py request --psrc 192.168.10.10 --pdst 192.168.10.1

# Analyze a Wireshark capture for handshake latency + spoofing:
python pcap_analyzer.py capture.pcapng --csv handshakes.csv
```

## Typical lab workflow

1. Build the topology in Packet Tracer / GNS3 / real gear; paste
   `configs/R1_startup-config.txt` and `configs/SW1_startup-config.txt`.
2. Start a Wireshark capture (filter `arp`) on PC1.
3. From PC1, `ping 192.168.10.30` — watch the broadcast request / unicast reply.
4. Save the capture and run `pcap_analyzer.py` for metrics.
5. Run `arp_audit.py` before/after to see cache entries age and change.
6. Run `arp_monitor.py` while generating traffic to see live decoding and
   anomaly alerts.

## ⚠️ Scope & ethics

These tools are for a lab **you own or are authorized to test**.
`arp_craft.py` deliberately stops at legitimate protocol operations
(requests, replies, gratuitous ARP announcing *your own* binding); it is not
a poisoning tool. The poisoning side is covered only on the **detection**
front (`arp_monitor.py`, `pcap_analyzer.py`) and via switch hardening (DAI,
port-security) in the configs. Do not use on networks without permission.
