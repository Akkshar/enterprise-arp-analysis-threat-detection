#!/usr/bin/env python3
"""
pcap_analyzer.py - Parse a Wireshark .pcap/.pcapng and report ARP metrics.

Part of the "Enterprise ARP Analysis" project.
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

For every ARP REQUEST it finds the matching unicast REPLY and reports the
resolution latency (reply_time - request_time). It also summarizes all
IP->MAC bindings seen and flags any IP that appears with more than one MAC
(a strong indicator of spoofing or a misconfiguration/duplicate IP).

Primary parser: Scapy (handles .pcap and .pcapng).
Optional fast path: dpkt (.pcap only) via --engine dpkt.

Requirements:
    pip install scapy          # default engine
    pip install dpkt           # only if you use --engine dpkt

Examples:
    python pcap_analyzer.py capture.pcapng
    python pcap_analyzer.py capture.pcap --engine dpkt --csv handshakes.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict


def _summarize(requests, replies, bindings, matches, args):
    """Shared reporting for both engines.

    requests : list of (time, who_has_ip, tell_ip, sender_mac)
    replies  : list of (time, is_at_ip, mac, to_ip)
    bindings : dict ip -> set(macs)
    matches  : list of dicts with keys request_t, reply_t, ip, mac, latency_ms
    """
    print("=" * 68)
    print("ARP CAPTURE ANALYSIS")
    print("=" * 68)
    print(f"ARP requests seen : {len(requests)}")
    print(f"ARP replies  seen : {len(replies)}")
    print(f"Matched handshakes: {len(matches)}")
    print()

    if matches:
        lat = [m["latency_ms"] for m in matches]
        print("Resolution latency (request -> matching reply):")
        print(f"  min  = {min(lat):.3f} ms")
        print(f"  max  = {max(lat):.3f} ms")
        print(f"  mean = {sum(lat) / len(lat):.3f} ms")
        print()
        print(f"  {'target IP':<16}{'resolved MAC':<20}{'latency (ms)':>14}")
        print("  " + "-" * 50)
        for m in sorted(matches, key=lambda x: x["request_t"]):
            print(f"  {m['ip']:<16}{m['mac']:<20}{m['latency_ms']:>14.3f}")
        print()

    print("IP -> MAC bindings observed:")
    anomalies = 0
    for ip in sorted(bindings):
        macs = bindings[ip]
        flag = ""
        if len(macs) > 1:
            flag = "  <== MULTIPLE MACs (possible spoofing / duplicate IP)"
            anomalies += 1
        print(f"  {ip:<16} -> {', '.join(sorted(macs))}{flag}")
    print()
    print(f"Anomalies (IPs with >1 MAC): {anomalies}")
    print("=" * 68)

    if args.csv and matches:
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["request_time", "reply_time", "target_ip",
                        "resolved_mac", "latency_ms"])
            for m in sorted(matches, key=lambda x: x["request_t"]):
                w.writerow([f"{m['request_t']:.6f}", f"{m['reply_t']:.6f}",
                            m["ip"], m["mac"], f"{m['latency_ms']:.3f}"])
        print(f"Handshake detail written to {args.csv}")


def _match_handshakes(requests, replies):
    """Pair each request with the earliest later reply for the same IP."""
    matches = []
    # index replies by the IP they resolve, keep them time-ordered
    replies_by_ip = defaultdict(list)
    for t, ip, mac, _to in replies:
        replies_by_ip[ip].append((t, mac))
    for ip in replies_by_ip:
        replies_by_ip[ip].sort()

    used = defaultdict(int)  # ip -> index of next unused reply
    for rt, who_has, _tell, _smac in sorted(requests):
        cand = replies_by_ip.get(who_has, [])
        i = used[who_has]
        while i < len(cand) and cand[i][0] < rt:
            i += 1
        if i < len(cand):
            reply_t, mac = cand[i]
            used[who_has] = i + 1
            matches.append({
                "request_t": rt, "reply_t": reply_t, "ip": who_has,
                "mac": mac, "latency_ms": (reply_t - rt) * 1000.0,
            })
    return matches


def analyze_scapy(path, args):
    try:
        from scapy.all import ARP, rdpcap
    except ImportError:
        sys.exit("Scapy not installed. Run: pip install scapy  (or use --engine dpkt)")

    packets = rdpcap(path)
    requests, replies = [], []
    bindings = defaultdict(set)

    for pkt in packets:
        if not pkt.haslayer(ARP):
            continue
        arp = pkt[ARP]
        t = float(pkt.time)
        if arp.hwsrc and arp.psrc and arp.psrc != "0.0.0.0":
            bindings[arp.psrc].add(arp.hwsrc.lower())
        if arp.op == 1:
            requests.append((t, arp.pdst, arp.psrc, arp.hwsrc))
        elif arp.op == 2:
            replies.append((t, arp.psrc, arp.hwsrc.lower(), arp.pdst))

    matches = _match_handshakes(requests, replies)
    _summarize(requests, replies, bindings, matches, args)


def analyze_dpkt(path, args):
    try:
        import dpkt
    except ImportError:
        sys.exit("dpkt not installed. Run: pip install dpkt  (or use the default scapy engine)")

    import socket

    def mac_str(b):
        return ":".join(f"{x:02x}" for x in b)

    requests, replies = [], []
    bindings = defaultdict(set)

    with open(path, "rb") as fh:
        try:
            pcap = dpkt.pcap.Reader(fh)
        except ValueError:
            sys.exit("dpkt engine only reads classic .pcap. Use the scapy engine for .pcapng.")
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            if not isinstance(eth.data, dpkt.arp.ARP):
                continue
            arp = eth.data
            spa = socket.inet_ntoa(arp.spa)
            tpa = socket.inet_ntoa(arp.tpa)
            sha = mac_str(arp.sha)
            if spa != "0.0.0.0":
                bindings[spa].add(sha)
            if arp.op == dpkt.arp.ARP_OP_REQUEST:
                requests.append((ts, tpa, spa, sha))
            elif arp.op == dpkt.arp.ARP_OP_REPLY:
                replies.append((ts, spa, sha, tpa))

    matches = _match_handshakes(requests, replies)
    _summarize(requests, replies, bindings, matches, args)


def main():
    ap = argparse.ArgumentParser(description="Analyze ARP handshakes in a pcap.")
    ap.add_argument("pcap", help="Path to .pcap / .pcapng file.")
    ap.add_argument("--engine", choices=["scapy", "dpkt"], default="scapy")
    ap.add_argument("--csv", help="Write matched-handshake detail to this CSV.")
    args = ap.parse_args()

    if args.engine == "dpkt":
        analyze_dpkt(args.pcap, args)
    else:
        analyze_scapy(args.pcap, args)


if __name__ == "__main__":
    main()
