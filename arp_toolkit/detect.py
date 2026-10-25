#!/usr/bin/env python3
"""
detect.py - Run the ARP threat detector over a pcap or live interface.

Part of "Enterprise ARP Threat Detection".
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

Front-end that feeds normalised ARP events into detection_engine.Detector and
prints / exports risk-scored incidents.

Examples:
    python detect.py --pcap test_data/arp_dataset.pcap \
        --baseline test_data/baseline.json --json incidents.json
    python detect.py --live -i "Ethernet" --baseline test_data/baseline.json
"""

from __future__ import annotations

import argparse
import json
import sys

from detection_engine import ArpEvent, Detector, TrustedBaseline

TIER_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def events_from_pcap(path):
    from scapy.all import ARP, rdpcap
    for pkt in rdpcap(path):
        if not pkt.haslayer(ARP):
            continue
        a = pkt[ARP]
        yield ArpEvent(time=float(pkt.time), op=int(a.op),
                       src_ip=a.psrc, src_mac=a.hwsrc,
                       dst_ip=a.pdst, dst_mac=a.hwdst)


def run_live(iface, detector, min_tier):
    from scapy.all import ARP, sniff

    def handle(pkt):
        if not pkt.haslayer(ARP):
            return
        a = pkt[ARP]
        before = len(detector.incidents)
        detector.process(ArpEvent(time=float(pkt.time), op=int(a.op),
                                   src_ip=a.psrc, src_mac=a.hwsrc,
                                   dst_ip=a.pdst, dst_mac=a.hwdst))
        for inc in detector.incidents[before:]:
            if TIER_ORDER[inc.tier] >= TIER_ORDER[min_tier]:
                _print_incident(inc)

    print("Live detection running (Ctrl-C to stop)...\n")
    sniff(filter="arp", iface=iface, prn=handle, store=False)


def _print_incident(inc):
    print(f"[{inc.tier}] score={inc.score}  IP {inc.claimed_ip} "
          f"claimed by {inc.offending_mac} "
          f"(expected {inc.baseline_mac or '?'})")
    for s in inc.signals:
        print(f"      - {s.name} ({s.points}): {s.detail}")
    from detection_engine import MITIGATION
    print(f"      -> {MITIGATION[inc.tier]}")


def main():
    ap = argparse.ArgumentParser(description="ARP threat detector.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="Analyze a capture file.")
    src.add_argument("--live", action="store_true", help="Sniff a live interface.")
    ap.add_argument("-i", "--iface", help="Interface for --live.")
    ap.add_argument("--baseline", required=True, help="Trusted baseline JSON.")
    ap.add_argument("--json", help="Write incidents to this JSON file.")
    ap.add_argument("--min-tier", default="LOW",
                    choices=list(TIER_ORDER), help="Minimum tier to display.")
    args = ap.parse_args()

    baseline = TrustedBaseline.load(args.baseline)
    detector = Detector(baseline)

    if args.live:
        try:
            run_live(args.iface, detector, args.min_tier)
        except KeyboardInterrupt:
            pass
        except PermissionError:
            sys.exit("Run as Administrator/root (Npcap on Windows) for live capture.")
    else:
        detector.run(events_from_pcap(args.pcap))
        shown = [i for i in detector.incidents
                 if TIER_ORDER[i.tier] >= TIER_ORDER[args.min_tier]]
        shown.sort(key=lambda i: (-TIER_ORDER[i.tier], i.first_time))
        print(f"{len(detector.incidents)} incident(s); "
              f"showing {len(shown)} at tier >= {args.min_tier}\n")
        for inc in shown:
            _print_incident(inc)
        print("\nSummary:", detector.summary())

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([i.to_dict() for i in detector.incidents], fh, indent=2)
        print(f"\nWrote {args.json}")


if __name__ == "__main__":
    main()
