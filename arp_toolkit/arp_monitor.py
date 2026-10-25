#!/usr/bin/env python3
"""
arp_monitor.py - Live ARP traffic listener, parser, and spoofing detector.

Part of the "Enterprise ARP Analysis" project.
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

Captures ARP frames on a chosen interface, decodes the opcode
(1 = request, 2 = reply), logs sender/target IP-to-MAC mappings, and
flags anomalies that are characteristic of ARP cache poisoning
(a single IP suddenly presenting a new MAC, or one MAC claiming many IPs).

This is a DEFENSIVE / observational tool. It only reads traffic.

Requirements:
    pip install scapy
    Windows: install Npcap (https://npcap.com) with "WinPcap API-compatible mode".
    Linux/macOS: run with sudo (raw socket access).

Usage examples:
    # List interfaces, then sniff on one of them:
    python arp_monitor.py --list
    python arp_monitor.py -i "Ethernet" --log arp_events.csv
    python arp_monitor.py -i eth0 --count 200
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import ARP, sniff, get_if_list, conf
except ImportError:
    sys.exit("Scapy is not installed. Run:  pip install scapy")

# --- Known-good baseline for the project topology (optional ground truth) ---
# Fill these in with the real MACs from your lab once known. Entries here are
# treated as the "trusted" binding; any deviation is flagged immediately.
STATIC_BINDINGS: dict[str, str] = {
    # "192.168.10.1":  "aa:bb:cc:00:00:01",   # R1 (default gateway)
    # "192.168.10.10": "aa:bb:cc:00:00:10",   # PC1
}

OPCODES = {1: "request", 2: "reply", 3: "rev-request", 4: "rev-reply"}


class ArpTracker:
    """Keeps running IP->MAC state and raises anomaly flags."""

    def __init__(self, writer: csv.writer | None = None):
        self.ip_to_mac: dict[str, str] = {}       # last seen binding
        self.mac_to_ips: dict[str, set] = defaultdict(set)
        self.writer = writer
        self.alerts = 0

    def _log_row(self, ts, op, src_ip, src_mac, dst_ip, dst_mac, note=""):
        if self.writer:
            self.writer.writerow([ts, op, src_ip, src_mac, dst_ip, dst_mac, note])

    def process(self, pkt):
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        ts = datetime.now().isoformat(timespec="seconds")
        op = OPCODES.get(arp.op, f"op{arp.op}")
        src_ip, src_mac = arp.psrc, arp.hwsrc
        dst_ip, dst_mac = arp.pdst, arp.hwdst

        notes = []

        # 1) Does this contradict a hard-coded trusted binding?
        trusted = STATIC_BINDINGS.get(src_ip)
        if trusted and src_mac.lower() != trusted.lower():
            notes.append(f"SPOOF? {src_ip} should be {trusted}, got {src_mac}")

        # 2) Did an IP we already learned suddenly change MAC?
        prev = self.ip_to_mac.get(src_ip)
        if prev and prev.lower() != src_mac.lower():
            notes.append(f"MAC CHANGE for {src_ip}: {prev} -> {src_mac}")

        # 3) Is one MAC claiming an unusual number of IPs? (gateway impersonation)
        self.mac_to_ips[src_mac].add(src_ip)
        if len(self.mac_to_ips[src_mac]) >= 3:
            notes.append(f"MAC {src_mac} now claims {len(self.mac_to_ips[src_mac])} IPs")

        self.ip_to_mac[src_ip] = src_mac
        note = " | ".join(notes)

        arrow = "?" if arp.op == 1 else "->"
        if arp.op == 1:
            line = f"[{ts}] REQUEST  who-has {dst_ip}  tell {src_ip} ({src_mac})"
        elif arp.op == 2:
            line = f"[{ts}] REPLY    {src_ip} is-at {src_mac}  -> {dst_ip} ({dst_mac})"
        else:
            line = f"[{ts}] {op.upper():8} {src_ip}/{src_mac} {arrow} {dst_ip}/{dst_mac}"

        if note:
            self.alerts += 1
            line += f"\n    *** ALERT: {note}"
        print(line)
        self._log_row(ts, op, src_ip, src_mac, dst_ip, dst_mac, note)


def main():
    ap = argparse.ArgumentParser(description="Live ARP monitor and spoof detector.")
    ap.add_argument("-i", "--iface", help="Interface to sniff (name or index).")
    ap.add_argument("-c", "--count", type=int, default=0,
                    help="Stop after N ARP packets (0 = run forever).")
    ap.add_argument("--log", help="Append events to this CSV file.")
    ap.add_argument("--list", action="store_true",
                    help="List available interfaces and exit.")
    args = ap.parse_args()

    if args.list:
        print("Available interfaces:")
        for name in get_if_list():
            print("  ", name)
        print("\n(On Windows these are NPF device names; you can also pass the "
              "friendly name shown by Scapy's conf.ifaces.)")
        try:
            print(conf.ifaces)
        except Exception:
            pass
        return

    writer = None
    fh = None
    if args.log:
        fh = open(args.log, "a", newline="")
        writer = csv.writer(fh)
        if fh.tell() == 0:
            writer.writerow(["timestamp", "opcode", "src_ip", "src_mac",
                             "dst_ip", "dst_mac", "note"])

    tracker = ArpTracker(writer)
    print(f"Sniffing ARP on {args.iface or 'default interface'} "
          f"(Ctrl-C to stop)...\n")
    try:
        sniff(
            filter="arp",
            iface=args.iface,
            prn=tracker.process,
            store=False,
            count=args.count,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("Permission denied. Run as Administrator/root (and install Npcap on Windows).")
    finally:
        if fh:
            fh.close()
        print(f"\nDone. {tracker.alerts} alert(s) raised. "
              f"{len(tracker.ip_to_mac)} unique IP(s) observed.")


if __name__ == "__main__":
    main()
