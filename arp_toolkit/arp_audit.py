#!/usr/bin/env python3
"""
arp_audit.py - Cross-platform ARP cache auditor.

Part of the "Enterprise ARP Analysis" project.
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

Reads the local OS ARP/neighbor table:
    * Windows / macOS : `arp -a`
    * Linux           : `ip neigh`  (falls back to `arp -n`)

...normalizes the entries, classifies static vs dynamic, flags anomalies
(duplicate MAC across IPs, duplicate IP with different MACs, incomplete/
failed resolutions, and deviations from an optional trusted baseline),
and exports the result to CSV and/or JSON.

Pure standard library -- no third-party packages required.

Examples:
    python arp_audit.py
    python arp_audit.py --json arp_audit.json --csv arp_audit.csv
    python arp_audit.py --baseline baseline.json
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime

MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INCOMPLETE = {"incomplete", "failed", "(incomplete)"}


def norm_mac(mac: str) -> str:
    return mac.replace("-", ":").lower()


def run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=15).stdout
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"war: command {' '.join(cmd)} failed: {e}", file=sys.stderr)
        return ""


def parse_windows(text: str) -> list[dict]:
    """Parse `arp -a` on Windows.
       Interface: 192.168.10.10 --- 0x5
         Internet Address      Physical Address      Type
         192.168.10.1          aa-bb-cc-00-00-01     dynamic
    """
    out, iface = [], ""
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith("interface:"):
            m = IP_RE.search(s)
            iface = m.group(0) if m else ""
            continue
        ip = IP_RE.search(s)
        mac = MAC_RE.search(s)
        if ip and mac:
            typ = s.split()[-1].lower()
            out.append({"ip": ip.group(0), "mac": norm_mac(mac.group(0)),
                        "type": "static" if typ == "static" else "dynamic",
                        "state": typ, "iface": iface})
    return out


def parse_arp_unix(text: str) -> list[dict]:
    """Parse BSD/macOS `arp -a`:
       host (192.168.10.1) at aa:bb:cc:0:0:1 on en0 ifscope [ethernet]
    """
    out = []
    for line in text.splitlines():
        ip = IP_RE.search(line)
        mac = MAC_RE.search(line)
        if not ip:
            continue
        low = line.lower()
        state = "incomplete" if ("incomplete" in low or not mac) else "dynamic"
        is_static = "permanent" in low or "static" in low
        iface_m = re.search(r" on (\S+)", line)
        out.append({"ip": ip.group(0),
                    "mac": norm_mac(mac.group(0)) if mac else "",
                    "type": "static" if is_static else "dynamic",
                    "state": "static" if is_static else state,
                    "iface": iface_m.group(1) if iface_m else ""})
    return out


def parse_ip_neigh(text: str) -> list[dict]:
    """Parse Linux `ip neigh`:
       192.168.10.1 dev eth0 lladdr aa:bb:cc:00:00:01 REACHABLE
       192.168.10.99 dev eth0  FAILED
    """
    out = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        if not IP_RE.fullmatch(ip):
            continue
        mac_m = MAC_RE.search(line)
        iface_m = re.search(r" dev (\S+)", line)
        state = parts[-1].lower()
        is_static = state == "permanent"
        out.append({"ip": ip,
                    "mac": norm_mac(mac_m.group(0)) if mac_m else "",
                    "type": "static" if is_static else "dynamic",
                    "state": state,
                    "iface": iface_m.group(1) if iface_m else ""})
    return out


def collect() -> list[dict]:
    system = platform.system()
    if system == "Windows":
        return parse_windows(run(["arp", "-a"]))
    if system == "Darwin":
        return parse_arp_unix(run(["arp", "-a"]))
    # Linux (and other): prefer `ip neigh`
    text = run(["ip", "neigh"])
    if text.strip():
        return parse_ip_neigh(text)
    return parse_arp_unix(run(["arp", "-n"]))


def audit(entries: list[dict], baseline: dict | None) -> list[dict]:
    """Attach an 'anomalies' list to each entry."""
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)
    for e in entries:
        if e["mac"]:
            ip_to_macs[e["ip"]].add(e["mac"])
            mac_to_ips[e["mac"]].add(e["ip"])

    for e in entries:
        flags = []
        ip, mac = e["ip"], e["mac"]

        if e["state"] in INCOMPLETE or not mac:
            flags.append("incomplete/failed resolution")

        if mac and len(ip_to_macs[ip]) > 1:
            flags.append(f"IP {ip} maps to {len(ip_to_macs[ip])} MACs")

        if mac and len(mac_to_ips[mac]) > 1:
            others = sorted(mac_to_ips[mac] - {ip})
            # multicast/broadcast MACs legitimately map to many IPs; skip those
            if not (mac.startswith("01:00:5e") or mac == "ff:ff:ff:ff:ff:ff"):
                flags.append(f"MAC {mac} shared with {', '.join(others)}")

        if baseline:
            expect = baseline.get(ip)
            if expect and mac and norm_mac(expect) != mac:
                flags.append(f"baseline mismatch: expected {norm_mac(expect)}")

        e["anomalies"] = flags
    return entries


def main():
    ap = argparse.ArgumentParser(description="Audit the local ARP/neighbor table.")
    ap.add_argument("--json", help="Write results to this JSON file.")
    ap.add_argument("--csv", help="Write results to this CSV file.")
    ap.add_argument("--baseline", help="JSON file of trusted {ip: mac} bindings.")
    ap.add_argument("--quiet", action="store_true", help="Suppress table print.")
    args = ap.parse_args()

    baseline = None
    if args.baseline:
        with open(args.baseline) as fh:
            baseline = json.load(fh)

    entries = audit(collect(), baseline)
    ts = datetime.now().isoformat(timespec="seconds")
    flagged = [e for e in entries if e["anomalies"]]

    if not args.quiet:
        print(f"ARP audit @ {ts}  ({platform.system()})")
        print(f"{'IP':<16}{'MAC':<20}{'TYPE':<9}{'STATE':<12}ANOMALIES")
        print("-" * 78)
        for e in sorted(entries, key=lambda x: tuple(int(p) for p in x['ip'].split('.')) if IP_RE.fullmatch(x['ip']) else (0,)):
            an = "; ".join(e["anomalies"]) or "-"
            print(f"{e['ip']:<16}{e['mac'] or '(none)':<20}"
                  f"{e['type']:<9}{e['state']:<12}{an}")
        print("-" * 78)
        print(f"{len(entries)} entries, {len(flagged)} flagged.")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"timestamp": ts, "os": platform.system(),
                       "entries": entries}, fh, indent=2)
        print(f"Wrote {args.json}")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["ip", "mac", "type", "state", "iface", "anomalies"])
            for e in entries:
                w.writerow([e["ip"], e["mac"], e["type"], e["state"],
                            e["iface"], "; ".join(e["anomalies"])])
        print(f"Wrote {args.csv}")

    # non-zero exit if anomalies found (useful in scripts / CI)
    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()
