#!/usr/bin/env python3
"""
arp_craft.py - Craft and send ARP request / reply frames with Scapy.

Part of the "Enterprise ARP Analysis" project.
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

This is a protocol-demonstration tool for a LAB you control. It sends:
  * a broadcast ARP REQUEST  ("who-has <target> tell <sender>")
  * a unicast   ARP REPLY    ("<sender> is-at <mac>")  -- e.g. a gratuitous
    ARP that a host legitimately uses to announce / refresh its own binding.

Use it only on networks you are authorized to test. Sending replies that
bind an IP you do not own to your MAC is ARP spoofing and is out of scope
for this tool -- see arp_monitor.py for the DETECTION side.

Requirements:
    pip install scapy
    Windows: Npcap.  Linux/macOS: run with sudo.

Examples:
    # Ask the gateway's MAC (standard resolution PC1 -> R1):
    python arp_craft.py request --pdst 192.168.10.1 --psrc 192.168.10.10

    # Gratuitous ARP announcing our own binding to the whole VLAN:
    python arp_craft.py gratuitous --ip 192.168.10.10

    # Targeted unicast reply to a specific host (lab demo):
    python arp_craft.py reply --psrc 192.168.10.10 --hwsrc 00:11:22:33:44:55 \
        --pdst 192.168.10.20 --hwdst 00:aa:bb:cc:dd:ee
"""

from __future__ import annotations

import argparse
import sys

try:
    from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf
except ImportError:
    sys.exit("Scapy is not installed. Run:  pip install scapy")

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


def my_mac(iface):
    try:
        return get_if_hwaddr(iface) if iface else get_if_hwaddr(conf.iface)
    except Exception:
        return None


def do_request(args):
    """Broadcast 'who-has pdst, tell psrc' and wait for the reply."""
    src_mac = args.hwsrc or my_mac(args.iface) or ZERO_MAC
    ether = Ether(dst=BROADCAST, src=src_mac)
    arp = ARP(op=1, psrc=args.psrc, hwsrc=src_mac,
              pdst=args.pdst, hwdst=ZERO_MAC)
    print(f"Sending ARP REQUEST: who-has {args.pdst} tell {args.psrc} ({src_mac})")
    ans, _ = srp(ether / arp, timeout=args.timeout, iface=args.iface,
                 verbose=False)
    if not ans:
        print("No reply received (host down, filtered, or wrong interface).")
        return
    for _, rcv in ans:
        print(f"  REPLY: {rcv[ARP].psrc} is-at {rcv[ARP].hwsrc}")


def do_reply(args):
    """Send a unicast ARP reply: 'psrc is-at hwsrc' to hwdst/pdst."""
    src_mac = args.hwsrc or my_mac(args.iface) or ZERO_MAC
    ether = Ether(dst=args.hwdst, src=src_mac)
    arp = ARP(op=2, psrc=args.psrc, hwsrc=src_mac,
              pdst=args.pdst, hwdst=args.hwdst)
    print(f"Sending ARP REPLY: {args.psrc} is-at {src_mac} -> "
          f"{args.pdst} ({args.hwdst})")
    sendp(ether / arp, count=args.count, inter=args.inter,
          iface=args.iface, verbose=False)
    print(f"Sent {args.count} frame(s).")


def do_gratuitous(args):
    """Gratuitous ARP: a host announcing/refreshing its OWN binding.

    Broadcast reply where psrc == pdst. Legitimately used after boot,
    failover, or IP change so every host updates its cache.
    """
    src_mac = args.hwsrc or my_mac(args.iface) or ZERO_MAC
    ether = Ether(dst=BROADCAST, src=src_mac)
    arp = ARP(op=2, psrc=args.ip, hwsrc=src_mac,
              pdst=args.ip, hwdst=BROADCAST)
    print(f"Sending GRATUITOUS ARP: {args.ip} is-at {src_mac} (broadcast)")
    sendp(ether / arp, count=args.count, inter=args.inter,
          iface=args.iface, verbose=False)
    print(f"Sent {args.count} frame(s).")


def main():
    ap = argparse.ArgumentParser(description="Craft/send ARP frames (lab use).")
    ap.add_argument("-i", "--iface", help="Interface to send on.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("request", help="Broadcast ARP request and await reply.")
    r.add_argument("--psrc", required=True, help="Sender IP (tell ...).")
    r.add_argument("--pdst", required=True, help="Target IP (who-has ...).")
    r.add_argument("--hwsrc", help="Sender MAC (default: this NIC's MAC).")
    r.add_argument("--timeout", type=float, default=2.0)
    r.set_defaults(func=do_request)

    p = sub.add_parser("reply", help="Send a unicast ARP reply.")
    p.add_argument("--psrc", required=True, help="IP being advertised.")
    p.add_argument("--pdst", required=True, help="Destination (target) IP.")
    p.add_argument("--hwdst", required=True, help="Destination MAC.")
    p.add_argument("--hwsrc", help="Advertised MAC (default: this NIC's MAC).")
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--inter", type=float, default=0.0)
    p.set_defaults(func=do_reply)

    g = sub.add_parser("gratuitous", help="Announce our own IP->MAC binding.")
    g.add_argument("--ip", required=True, help="Our IP to announce.")
    g.add_argument("--hwsrc", help="Our MAC (default: this NIC's MAC).")
    g.add_argument("--count", type=int, default=1)
    g.add_argument("--inter", type=float, default=0.0)
    g.set_defaults(func=do_gratuitous)

    args = ap.parse_args()
    try:
        args.func(args)
    except PermissionError:
        sys.exit("Permission denied. Run as Administrator/root (Npcap on Windows).")


if __name__ == "__main__":
    main()
