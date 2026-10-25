#!/usr/bin/env python3
"""
make_captures.py - Generate LABELLED synthetic ARP captures for evaluation.

Part of "Enterprise ARP Threat Detection".
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

Writes a single .pcap containing a sequence of benign and attack "episodes",
plus a labels.json describing each episode (ground truth). These are test
FIXTURES: packets are written to a file, never transmitted on a network.
They implement Phase 1/2 of the evaluation plan (replay + simulated traffic)
so the detector can be measured against known ground truth.

Usage:
    python make_captures.py --out test_data
    # -> test_data/arp_dataset.pcap  and  test_data/labels.json
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime

try:
    from scapy.all import ARP, Ether, wrpcap
except ImportError:
    raise SystemExit("Scapy required: pip install scapy")

# --- Topology identities (match baseline.detection.example.json) -----------
GW_IP, GW_MAC = "192.168.10.1", "00:1a:2b:00:00:01"      # gateway anchor
SRV_IP, SRV_MAC = "192.168.10.30", "00:1a:2b:00:00:30"   # static anchor
PC1_IP, PC1_MAC = "192.168.10.10", "00:1a:2b:00:00:10"
PC2_IP, PC2_MAC = "192.168.10.20", "00:1a:2b:00:00:20"
PRN_IP, PRN_MAC = "192.168.10.40", "00:1a:2b:00:00:40"

STANDBY_MAC = "00:1a:2b:00:00:31"   # server failover NIC (known/registered)
ONBOARD_IP, ONBOARD_MAC = "192.168.10.50", "00:1a:2b:00:00:50"  # authorised new host
RENEW_MAC = "00:1a:2b:00:0a:20"     # PC2's new NIC after a DHCP renewal
MOVE_MAC = "00:1a:2b:00:0b:10"      # PC1's new NIC after an authorised swap

ROGUE_MAC = "de:ad:be:ef:00:66"     # attacker
ROGUE2_MAC = "de:ad:be:ef:00:77"

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO = "00:00:00:00:00:00"

# Base clock: a normal business day, 09:00 local.
DAY = datetime(2026, 10, 24, 9, 0, 0).timestamp()
NIGHT = datetime(2026, 10, 24, 2, 0, 0).timestamp()  # off-hours


def req(t, src_ip, src_mac, tgt_ip):
    p = Ether(src=src_mac, dst=BROADCAST) / ARP(
        op=1, hwsrc=src_mac, psrc=src_ip, hwdst=ZERO, pdst=tgt_ip)
    p.time = t
    return p


def reply(t, src_ip, src_mac, dst_ip, dst_mac):
    p = Ether(src=src_mac, dst=dst_mac) / ARP(
        op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    p.time = t
    return p


def gratuitous(t, ip, mac):
    p = Ether(src=mac, dst=BROADCAST) / ARP(
        op=2, hwsrc=mac, psrc=ip, hwdst=BROADCAST, pdst=ip)
    p.time = t
    return p


# --------------------------------------------------------------------------
# Episodes. Each returns (packets, label_record). t0 = episode start time.
# --------------------------------------------------------------------------
def ep_normal(t0):
    pk = [
        req(t0 + 0.0, PC1_IP, PC1_MAC, GW_IP),
        reply(t0 + 0.002, GW_IP, GW_MAC, PC1_IP, PC1_MAC),
        req(t0 + 1.0, PC1_IP, PC1_MAC, PC2_IP),
        reply(t0 + 1.003, PC2_IP, PC2_MAC, PC1_IP, PC1_MAC),
        req(t0 + 2.0, PRN_IP, PRN_MAC, GW_IP),
        reply(t0 + 2.002, GW_IP, GW_MAC, PRN_IP, PRN_MAC),
    ]
    return pk, dict(type="normal_resolution", label="benign")


def ep_dhcp_renewal(t0):
    # PC2 comes back on a new NIC; covered by a DHCP event in the baseline.
    pk = [gratuitous(t0 + 0.0, PC2_IP, RENEW_MAC),
          req(t0 + 0.5, PC2_IP, RENEW_MAC, GW_IP)]
    return pk, dict(type="dhcp_renewal", label="benign")


def ep_device_move(t0):
    # Authorised NIC swap on PC1 during a maintenance window.
    pk = [gratuitous(t0 + 0.0, PC1_IP, MOVE_MAC),
          req(t0 + 0.4, PC1_IP, MOVE_MAC, GW_IP)]
    return pk, dict(type="device_move", label="benign")


def ep_failover(t0):
    # Server fails over to a registered standby NIC inside a maintenance window.
    pk = [gratuitous(t0 + 0.0, SRV_IP, SRV_MAC),
          gratuitous(t0 + 0.3, SRV_IP, STANDBY_MAC),
          reply(t0 + 0.6, SRV_IP, STANDBY_MAC, PC1_IP, PC1_MAC)]
    return pk, dict(type="server_failover", label="benign")


def ep_onboarding(t0):
    # A brand-new authorised host obtains a lease (DHCP event covers it).
    pk = [gratuitous(t0 + 0.0, ONBOARD_IP, ONBOARD_MAC),
          req(t0 + 0.5, ONBOARD_IP, ONBOARD_MAC, GW_IP),
          reply(t0 + 0.503, GW_IP, GW_MAC, ONBOARD_IP, ONBOARD_MAC)]
    return pk, dict(type="onboarding", label="benign")


def ep_gateway_impersonation(t0):
    # Rogue host repeatedly claims the gateway IP (off-hours here).
    pk = [gratuitous(t0 + i * 0.5, GW_IP, ROGUE_MAC) for i in range(4)]
    return pk, dict(type="gateway_impersonation", label="attack")


def ep_gratuitous_poisoning(t0):
    # Rogue host poisons the binding of the enterprise server.
    pk = [gratuitous(t0 + i * 0.5, SRV_IP, ROGUE_MAC) for i in range(4)]
    return pk, dict(type="gratuitous_poisoning", label="attack")


def ep_mitm_relay(t0):
    # Rogue claims the gateway to the victims and the victim to the gateway.
    pk = [
        gratuitous(t0 + 0.0, GW_IP, ROGUE_MAC),
        reply(t0 + 0.2, GW_IP, ROGUE_MAC, PC1_IP, PC1_MAC),
        reply(t0 + 0.4, PC1_IP, ROGUE_MAC, GW_IP, GW_MAC),
        gratuitous(t0 + 1.0, GW_IP, ROGUE_MAC),
    ]
    return pk, dict(type="mitm_relay", label="attack")


def ep_arp_flood(t0):
    # Rogue (its own address .200) sprays ARP requests across the subnet,
    # scanning/exhausting. Tests the abnormal-rate signal specifically.
    pk = [req(t0 + i * 0.03, "192.168.10.200", ROGUE_MAC,
              f"192.168.10.{50 + (i % 150)}") for i in range(60)]
    return pk, dict(type="arp_flood", label="attack")


def ep_duplicate_ip(t0):
    # Two MACs persistently fight over the printer's IP (one is a rogue).
    pk = []
    for i in range(6):
        pk.append(gratuitous(t0 + i * 0.6, PRN_IP, PRN_MAC))
        pk.append(gratuitous(t0 + i * 0.6 + 0.1, PRN_IP, ROGUE2_MAC))
    return pk, dict(type="duplicate_ip_conflict", label="attack")


# Episode schedule: (start_time, builder). Attacks include one off-hours.
SCHEDULE = [
    (DAY + 0,    ep_normal),
    (DAY + 60,   ep_dhcp_renewal),
    (DAY + 120,  ep_device_move),
    (DAY + 180,  ep_failover),
    (DAY + 240,  ep_onboarding),
    (NIGHT + 0,  ep_gateway_impersonation),   # off-hours attack
    (DAY + 360,  ep_gratuitous_poisoning),
    (DAY + 420,  ep_mitm_relay),
    (DAY + 480,  ep_arp_flood),
    (DAY + 540,  ep_duplicate_ip),
]


def build():
    packets, labels = [], []
    for idx, (t0, builder) in enumerate(SCHEDULE):
        pk, rec = builder(t0)
        end = max(p.time for p in pk)
        rec.update(id=idx, start=t0, end=end, n_packets=len(pk))
        labels.append(rec)
        packets.extend(pk)
    packets.sort(key=lambda p: p.time)
    return packets, labels


def build_baseline():
    """Baseline whose context windows line up with the generated episodes,
    so benign change is explained regardless of local timezone."""
    return {
        "gateways": {GW_IP: GW_MAC},
        "static_hosts": {SRV_IP: SRV_MAC},
        "known_macs": [GW_MAC, PC1_MAC, PC2_MAC, SRV_MAC, STANDBY_MAC, PRN_MAC],
        "business_hours": [8, 20],
        "dhcp_events": [
            {"ip": PC2_IP, "mac": RENEW_MAC, "time": DAY + 60, "window": 180},
            {"ip": ONBOARD_IP, "mac": ONBOARD_MAC, "time": DAY + 240, "window": 180},
        ],
        "maintenance": [
            {"start": DAY + 120 - 5, "end": DAY + 120 + 10, "ip": PC1_IP},
            {"start": DAY + 180 - 5, "end": DAY + 180 + 10, "ip": SRV_IP},
        ],
    }


def main():
    ap = argparse.ArgumentParser(description="Generate labelled ARP test data.")
    ap.add_argument("--out", default="test_data", help="Output directory.")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    packets, labels = build()
    pcap_path = os.path.join(args.out, "arp_dataset.pcap")
    labels_path = os.path.join(args.out, "labels.json")
    baseline_path = os.path.join(args.out, "baseline.json")
    wrpcap(pcap_path, packets)
    with open(labels_path, "w") as fh:
        json.dump({"generated": datetime.now().isoformat(timespec="seconds"),
                   "episodes": labels}, fh, indent=2)
    with open(baseline_path, "w") as fh:
        json.dump(build_baseline(), fh, indent=2)

    n_atk = sum(1 for e in labels if e["label"] == "attack")
    print(f"Wrote {len(packets)} packets across {len(labels)} episodes "
          f"({n_atk} attack / {len(labels) - n_atk} benign)")
    print(f"  {pcap_path}")
    print(f"  {labels_path}")
    print(f"  {baseline_path}")


if __name__ == "__main__":
    main()
