# Troubleshooting Matrix & ARP Spoofing Detection

Companion to the Enterprise ARP Analysis report.
Team: Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan

---

## 1. LAN troubleshooting matrix

| # | Symptom | Likely cause | How to confirm | Fix |
|---|---------|--------------|----------------|-----|
| 1 | First ping to a host is slow, rest are fast | Cold ARP cache — one resolution round-trip before traffic flows | `arp -a` empty before, populated after; capture shows request→reply then ICMP | Normal. Pre-populate static ARP for latency-sensitive hosts if needed |
| 2 | Host unreachable, `arp -a` shows `incomplete`/`FAILED` | Target down, wrong VLAN, or cable/port issue — no reply to the request | `arp_audit.py` flags "incomplete/failed"; `show mac address-table` lacks the MAC | Check link/port, VLAN membership, target power |
| 3 | Two hosts intermittently lose connectivity | **Duplicate IP** — two NICs claim one IP, caches flap between MACs | `arp_audit.py` flags "IP maps to N MACs"; Windows logs a duplicate-IP event | Find/renumber the offending host |
| 4 | A port goes `err-disabled` / traffic dropped on one port | **Port-security violation** (unexpected MAC, or >max MACs) | `show port-security`, `show interface status` = err-disabled/secure-shutdown | Remove rogue device; `shutdown`/`no shutdown` or clear; adjust `maximum` |
| 5 | All hosts' traffic to gateway is intercepted/slow; gateway MAC changed | **ARP poisoning** of the gateway binding | `arp_monitor.py` "MAC CHANGE for .1"; DAI drops logged | Enable/verify DAI; static ARP for gateway; isolate attacker port |
| 6 | Switch floods all unicast; CAM table full | **MAC flooding** (CAM overflow attack) | `show mac address-table count` near max; many random MACs on one port | Port security `maximum`, `violation restrict/shutdown` |
| 7 | Return traffic takes a different path / asymmetric routing | Two gateways or mismatched masks/routes in the subnet | `tracert`/`traceroute` differs each way; check host gateway + mask | Single consistent gateway (`.1`), uniform `/24` mask |
| 8 | Static-IP host cannot reach anything | Wrong gateway/mask, or IP outside subnet | `ipconfig`/`ip addr`; gateway must be `192.168.10.1`, mask `255.255.255.0` | Correct static config |
| 9 | Printer/server reachable by IP but ARP entry keeps aging out | ARP timeout too short vs. traffic pattern; device sleeps | Watch entry disappear in `arp_audit.py` runs | Increase `arp timeout`, or static ARP on R1 |
| 10 | DAI dropping legitimate ARP after enabling it | No DHCP-snooping binding (static hosts), or trusted port not set | `show ip arp inspection statistics` (drops rising); `show ip dhcp snooping binding` empty | Add ARP ACL for static hosts, or mark server/uplink ports `trust` |

### Quick command reference

**Hosts**
```bash
# Windows / macOS
arp -a
arp -d *               # clear cache (Win: run as admin)
# Linux
ip neigh
ip neigh flush all
```

**Cisco R1 / SW1**
```
show ip arp
show mac address-table dynamic
show port-security address
show ip arp inspection
show ip arp inspection statistics
show ip dhcp snooping binding
debug arp
clear arp-cache
```

---

## 2. Detecting ARP spoofing attempts

ARP poisoning shows up as **binding instability**: an IP's MAC changes
without the host actually moving, or one MAC starts answering for several IPs
(classic gateway impersonation). Three signals, in increasing order of
confidence:

1. **MAC change for a known IP** — a cached IP suddenly resolves to a new MAC.
2. **One MAC claiming multiple IPs** — especially the gateway + a victim.
3. **Baseline mismatch** — the observed MAC differs from a known-good value.

### 2.1 Live detection — already built into `arp_monitor.py`

The monitor keeps `ip→mac` and `mac→{ips}` state and raises an alert on any of
the three signals above. Minimal standalone version of the core idea:

```python
from collections import defaultdict
from scapy.all import ARP, sniff

ip_to_mac = {}
mac_to_ips = defaultdict(set)

def check(pkt):
    if not pkt.haslayer(ARP):
        return
    a = pkt[ARP]
    ip, mac = a.psrc, a.hwsrc
    if ip in ip_to_mac and ip_to_mac[ip] != mac:
        print(f"[ALERT] {ip} changed MAC {ip_to_mac[ip]} -> {mac}")
    mac_to_ips[mac].add(ip)
    if len(mac_to_ips[mac]) >= 3:
        print(f"[ALERT] {mac} now claims {sorted(mac_to_ips[mac])}")
    ip_to_mac[ip] = mac

sniff(filter="arp", prn=check, store=False)
```

Run the full tool with logging:
```bash
python arp_monitor.py -i "Ethernet" --log arp_events.csv
```

### 2.2 Baseline enforcement — `arp_audit.py`

```bash
# One-time: record trusted bindings in baseline.json (see baseline.example.json)
python arp_audit.py --baseline baseline.json --csv audit.csv
# Exit code 1 == anomalies found -> wire into a cron/Task Scheduler alert
```

### 2.3 Capture-based forensics — `pcap_analyzer.py`

```bash
python pcap_analyzer.py suspect.pcapng --csv handshakes.csv
# "MULTIPLE MACs" next to an IP == spoofing/duplicate-IP evidence
```

### 2.4 Architectural recommendations (defense + detection together)

- **Enable DAI with DHCP snooping** so forged ARP is dropped *at the switch*
  before it reaches victims — detection becomes a backstop, not the only line.
- **Static ARP for the gateway** on critical hosts; **static ARP for server/
  printer** on R1 so those bindings can't be overwritten.
- **Port security sticky-MAC** so a rogue NIC can't even transmit on a port.
- **Centralize** `arp_events.csv` / `audit.csv` into your log store and alert
  on any ALERT line or non-zero audit exit — rapid MAC/IP churn is the tell.
- **Segment** where possible: smaller broadcast domains shrink the attack's
  blast radius (future work — this lab is intentionally a single flat VLAN).
