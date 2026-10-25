"""Labelled synthetic ARP scenarios (benign + attack) for backtesting.

These are test FIXTURES: packets written to a .pcap, never transmitted.
Equivalent to rugscan's JSON fixtures + labels. Generates a matching baseline
so context windows line up regardless of timezone.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

GW_IP, GW_MAC = "192.168.10.1", "00:1a:2b:00:00:01"
SRV_IP, SRV_MAC = "192.168.10.30", "00:1a:2b:00:00:30"
PC1_IP, PC1_MAC = "192.168.10.10", "00:1a:2b:00:00:10"
PC2_IP, PC2_MAC = "192.168.10.20", "00:1a:2b:00:00:20"
PRN_IP, PRN_MAC = "192.168.10.40", "00:1a:2b:00:00:40"
STANDBY_MAC = "00:1a:2b:00:00:31"
ONBOARD_IP, ONBOARD_MAC = "192.168.10.50", "00:1a:2b:00:00:50"
RENEW_MAC = "00:1a:2b:00:0a:20"
MOVE_MAC = "00:1a:2b:00:0b:10"
ROGUE_MAC = "de:ad:be:ef:00:66"
ROGUE2_MAC = "de:ad:be:ef:00:77"
BCAST, ZERO = "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"

DAY = datetime(2026, 10, 24, 9, 0, 0).timestamp()
NIGHT = datetime(2026, 10, 24, 2, 0, 0).timestamp()


def _req(t, sip, smac, tip):
    from scapy.all import ARP, Ether
    p = Ether(src=smac, dst=BCAST) / ARP(op=1, hwsrc=smac, psrc=sip, hwdst=ZERO, pdst=tip)
    p.time = t
    return p


def _reply(t, sip, smac, dip, dmac):
    from scapy.all import ARP, Ether
    p = Ether(src=smac, dst=dmac) / ARP(op=2, hwsrc=smac, psrc=sip, hwdst=dmac, pdst=dip)
    p.time = t
    return p


def _grat(t, ip, mac):
    from scapy.all import ARP, Ether
    p = Ether(src=mac, dst=BCAST) / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=BCAST, pdst=ip)
    p.time = t
    return p


def _episodes():
    e = []
    e.append((DAY + 0, "normal_resolution", "benign", [
        _req(DAY + 0, PC1_IP, PC1_MAC, GW_IP), _reply(DAY + 0.002, GW_IP, GW_MAC, PC1_IP, PC1_MAC),
        _req(DAY + 1, PC1_IP, PC1_MAC, PC2_IP), _reply(DAY + 1.003, PC2_IP, PC2_MAC, PC1_IP, PC1_MAC)]))
    e.append((DAY + 60, "dhcp_renewal", "benign", [
        _grat(DAY + 60, PC2_IP, RENEW_MAC), _req(DAY + 60.5, PC2_IP, RENEW_MAC, GW_IP)]))
    e.append((DAY + 120, "device_move", "benign", [
        _grat(DAY + 120, PC1_IP, MOVE_MAC), _req(DAY + 120.4, PC1_IP, MOVE_MAC, GW_IP)]))
    e.append((DAY + 180, "server_failover", "benign", [
        _grat(DAY + 180, SRV_IP, SRV_MAC), _grat(DAY + 180.3, SRV_IP, STANDBY_MAC),
        _reply(DAY + 180.6, SRV_IP, STANDBY_MAC, PC1_IP, PC1_MAC)]))
    e.append((DAY + 240, "onboarding", "benign", [
        _grat(DAY + 240, ONBOARD_IP, ONBOARD_MAC), _req(DAY + 240.5, ONBOARD_IP, ONBOARD_MAC, GW_IP)]))
    e.append((NIGHT + 0, "gateway_impersonation", "attack",
              [_grat(NIGHT + i * 0.5, GW_IP, ROGUE_MAC) for i in range(4)]))
    e.append((DAY + 360, "gratuitous_poisoning", "attack",
              [_grat(DAY + 360 + i * 0.5, SRV_IP, ROGUE_MAC) for i in range(4)]))
    e.append((DAY + 420, "mitm_relay", "attack", [
        _grat(DAY + 420, GW_IP, ROGUE_MAC), _reply(DAY + 420.2, GW_IP, ROGUE_MAC, PC1_IP, PC1_MAC),
        _reply(DAY + 420.4, PC1_IP, ROGUE_MAC, GW_IP, GW_MAC), _grat(DAY + 421, GW_IP, ROGUE_MAC)]))
    e.append((DAY + 480, "arp_flood", "attack",
              [_req(DAY + 480 + i * 0.03, "192.168.10.200", ROGUE_MAC,
                    f"192.168.10.{50 + (i % 150)}") for i in range(60)]))
    dup = []
    for i in range(6):
        dup.append(_grat(DAY + 540 + i * 0.6, PRN_IP, PRN_MAC))
        dup.append(_grat(DAY + 540 + i * 0.6 + 0.1, PRN_IP, ROGUE2_MAC))
    e.append((DAY + 540, "duplicate_ip_conflict", "attack", dup))
    return e


def _baseline():
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
            {"start": DAY + 115, "end": DAY + 130, "ip": PC1_IP},
            {"start": DAY + 175, "end": DAY + 190, "ip": SRV_IP},
        ],
    }


def scenario_list() -> list[dict]:
    return [{"id": i, "type": typ, "label": label, "packets": len(pk)}
            for i, (_t, typ, label, pk) in enumerate(_episodes())]


# ==========================================================================
# Multi-VLAN variant (VLANs 10/20/30) - Phase 3 coverage in software.
# ==========================================================================
# VLAN 10 users 192.168.10.0/24, VLAN 20 servers 192.168.20.0/24,
# VLAN 30 guest 192.168.30.0/24. Frames are 802.1Q-tagged so a SPAN-port
# sensor sees every VLAN and can catch cross-VLAN lateral movement.
GW10_IP, GW10_MAC = "192.168.10.1", "00:1a:2b:00:00:01"
GW20_IP, GW20_MAC = "192.168.20.1", "00:1a:2b:00:a0:01"
GW30_IP, GW30_MAC = "192.168.30.1", "00:1a:2b:00:b0:01"
MV_PC1_IP, MV_PC1_MAC = "192.168.10.10", "00:1a:2b:00:00:10"
MV_PC2_IP, MV_PC2_MAC = "192.168.10.20", "00:1a:2b:00:00:20"
MV_SRV_IP, MV_SRV_MAC = "192.168.20.30", "00:1a:2b:00:a0:30"
MV_GUEST_IP, MV_GUEST_MAC = "192.168.30.50", "00:1a:2b:00:b0:50"


def _treq(t, vlan, sip, smac, tip):
    from scapy.all import ARP, Dot1Q, Ether
    p = Ether(src=smac, dst=BCAST) / Dot1Q(vlan=vlan) / ARP(
        op=1, hwsrc=smac, psrc=sip, hwdst=ZERO, pdst=tip)
    p.time = t
    return p


def _treply(t, vlan, sip, smac, dip, dmac):
    from scapy.all import ARP, Dot1Q, Ether
    p = Ether(src=smac, dst=dmac) / Dot1Q(vlan=vlan) / ARP(
        op=2, hwsrc=smac, psrc=sip, hwdst=dmac, pdst=dip)
    p.time = t
    return p


def _tgrat(t, vlan, ip, mac):
    from scapy.all import ARP, Dot1Q, Ether
    p = Ether(src=mac, dst=BCAST) / Dot1Q(vlan=vlan) / ARP(
        op=2, hwsrc=mac, psrc=ip, hwdst=BCAST, pdst=ip)
    p.time = t
    return p


def _mv_episodes():
    e = []
    # --- benign ---
    e.append((DAY + 0, "v10_user_resolution", "benign", [
        _treq(DAY + 0, 10, MV_PC1_IP, MV_PC1_MAC, GW10_IP),
        _treply(DAY + 0.002, 10, GW10_IP, GW10_MAC, MV_PC1_IP, MV_PC1_MAC),
        _treq(DAY + 1, 10, MV_PC1_IP, MV_PC1_MAC, MV_PC2_IP),
        _treply(DAY + 1.003, 10, MV_PC2_IP, MV_PC2_MAC, MV_PC1_IP, MV_PC1_MAC)]))
    e.append((DAY + 60, "v20_server_access", "benign", [
        _treq(DAY + 60, 20, GW20_IP, GW20_MAC, MV_SRV_IP),
        _treply(DAY + 60.003, 20, MV_SRV_IP, MV_SRV_MAC, GW20_IP, GW20_MAC)]))
    e.append((DAY + 120, "v30_guest_onboarding", "benign", [
        _tgrat(DAY + 120, 30, MV_GUEST_IP, MV_GUEST_MAC),
        _treq(DAY + 120.5, 30, MV_GUEST_IP, MV_GUEST_MAC, GW30_IP)]))
    # --- attacks ---
    e.append((NIGHT + 0, "v10_gateway_impersonation", "attack",
              [_tgrat(NIGHT + i * 0.5, 10, GW10_IP, ROGUE_MAC) for i in range(4)]))
    e.append((DAY + 240, "v20_server_poisoning", "attack",
              [_tgrat(DAY + 240 + i * 0.5, 20, MV_SRV_IP, ROGUE_MAC) for i in range(4)]))
    # cross-VLAN lateral movement: same rogue MAC hops VLAN 30 -> VLAN 10
    e.append((DAY + 300, "cross_vlan_lateral", "attack", [
        _tgrat(DAY + 300, 30, "192.168.30.66", ROGUE2_MAC),
        _treq(DAY + 300.3, 30, "192.168.30.66", ROGUE2_MAC, GW30_IP),
        _tgrat(DAY + 301, 10, "192.168.10.66", ROGUE2_MAC),
        _treq(DAY + 301.3, 10, "192.168.10.66", ROGUE2_MAC, GW10_IP)]))
    e.append((DAY + 360, "v30_arp_flood", "attack",
              [_treq(DAY + 360 + i * 0.03, 30, "192.168.30.200", ROGUE_MAC,
                     f"192.168.30.{50 + (i % 150)}") for i in range(60)]))
    return e


def _mv_baseline():
    return {
        "gateways": {GW10_IP: GW10_MAC, GW20_IP: GW20_MAC, GW30_IP: GW30_MAC},
        "static_hosts": {MV_SRV_IP: MV_SRV_MAC},
        "known_macs": [GW10_MAC, GW20_MAC, GW30_MAC, MV_PC1_MAC, MV_PC2_MAC,
                       MV_SRV_MAC],
        "business_hours": [8, 20],
        "dhcp_events": [
            {"ip": MV_GUEST_IP, "mac": MV_GUEST_MAC, "time": DAY + 120, "window": 180},
        ],
        "maintenance": [],
    }


def generate(out_dir: str | Path, variant: str = "single") -> dict:
    from scapy.all import wrpcap
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    eps = _mv_episodes() if variant == "multivlan" else _episodes()
    baseline = _mv_baseline() if variant == "multivlan" else _baseline()
    packets, labels = [], []
    for idx, (t0, typ, label, pk) in enumerate(eps):
        labels.append({"id": idx, "type": typ, "label": label,
                       "start": t0, "end": max(p.time for p in pk), "n_packets": len(pk)})
        packets.extend(pk)
    packets.sort(key=lambda p: p.time)
    wrpcap(str(out / "arp_dataset.pcap"), packets)
    (out / "labels.json").write_text(json.dumps(
        {"generated": datetime.now().isoformat(timespec="seconds"),
         "variant": variant, "episodes": labels}, indent=2))
    (out / "baseline.json").write_text(json.dumps(baseline, indent=2))
    n_atk = sum(1 for e in labels if e["label"] == "attack")
    return {"packets": len(packets), "episodes": len(labels),
            "attacks": n_atk, "benign": len(labels) - n_atk,
            "variant": variant, "dir": str(out)}
