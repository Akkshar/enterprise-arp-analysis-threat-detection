# Enterprise ARP Analysis: Problem Analysis, Network Design & Configuration

**Team:** Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan
**Subject:** Computer Networks
**Scope:** Single-VLAN enterprise LAN on `192.168.10.0/24`

---

## 1. Abstract

The Address Resolution Protocol (ARP) is the glue between Layer 3 (IPv4)
and Layer 2 (Ethernet) addressing. Every intra-LAN frame ultimately needs a
destination **MAC** address, yet applications and routing operate on **IP**
addresses, so each host must dynamically discover the MAC that owns a given
IP. This report analyzes ARP behaviour in a small enterprise LAN consisting
of a router/default-gateway, two employee PCs, a server, and a network
printer, all on one VLAN. We examine the request/reply exchange at packet
level, how the access switch learns and floods frames, how operating systems
cache and age bindings, and the security exposure created by ARP's complete
lack of authentication — culminating in ARP spoofing / cache poisoning. We
pair the analysis with a working toolkit (Scapy generators, a live monitor,
a PCAP analyzer, a cross-platform cache auditor) and production-style Cisco
IOS configurations that harden the network with port security and Dynamic
ARP Inspection.

---

## 2. Introduction to ARP

ARP (RFC 826) resolves a known IPv4 address to an unknown MAC address on a
broadcast link. It is a stateless request/reply protocol carried directly in
Ethernet frames (EtherType `0x0806`), not inside IP.

### 2.1 Frame fields (Ethernet/IPv4 case)

| Field | Meaning |
|-------|---------|
| Hardware type | 1 (Ethernet) |
| Protocol type | `0x0800` (IPv4) |
| HW / proto length | 6 / 4 bytes |
| **Opcode** | **1 = request, 2 = reply** |
| Sender HW addr (SHA) | sender MAC |
| Sender proto addr (SPA) | sender IP |
| Target HW addr (THA) | target MAC (all-zero in a request) |
| Target proto addr (TPA) | target IP being resolved |

### 2.2 The exchange

1. **Request (broadcast).** Host needs the MAC for an IP. It sends an ARP
   request to `ff:ff:ff:ff:ff:ff`: *"Who has 192.168.10.1? Tell
   192.168.10.10."* Every host in the broadcast domain receives it.
2. **Reply (unicast).** Only the owner of the target IP answers, directly to
   the requester: *"192.168.10.1 is-at aa:bb:cc:00:00:01."*
3. **Cache.** The requester stores the binding in its ARP cache for a timeout
   (minutes on hosts, up to 4 h on IOS by default) so it need not ask again.

### 2.3 Variants

- **Gratuitous ARP** — a host broadcasts a reply for *its own* IP after boot,
  an IP change, or a failover, so neighbours refresh their caches. Legitimate,
  but also the mechanic an attacker abuses.
- **Proxy ARP** — a router answers on behalf of hosts it can reach. Not used
  in this flat single-VLAN design.

---

## 3. Network Topology Design

A single Layer-2 broadcast domain (VLAN 10) on `192.168.10.0/24`. R1 provides
the default gateway; a Catalyst 2960 access switch connects all hosts.

```
                       ┌──────────────────┐
                       │   Router  R1      │
                       │  192.168.10.1 /24 │  (default gateway)
                       └─────────┬────────┘
                                 │ Fa0/1 (uplink, trusted)
                       ┌─────────┴────────┐
                       │   Switch  SW1     │  Catalyst 2960, VLAN 10
                       │  SVI 192.168.10.2 │
                       └─┬───┬───┬───┬─────┘
                  Fa0/2 │   │Fa0/3  │Fa0/4 │Fa0/5
                     ┌──┴┐ ┌┴──┐  ┌─┴──┐ ┌─┴───┐
                     │PC1│ │PC2│  │SRV │ │PRINT│
                     │.10│ │.20│  │.30 │ │.40  │
                     └───┘ └───┘  └────┘ └─────┘
```

| Device  | IP            | MAC (lab) | Switch port |
|---------|---------------|-----------|-------------|
| R1 (GW) | 192.168.10.1  | _fill in_ | Fa0/1       |
| PC1     | 192.168.10.10 | _fill in_ | Fa0/2       |
| PC2     | 192.168.10.20 | _fill in_ | Fa0/3       |
| Server  | 192.168.10.30 | _fill in_ | Fa0/4       |
| Printer | 192.168.10.40 | _fill in_ | Fa0/5       |

**Design rationale.** A flat VLAN keeps the lab simple and makes all ARP
traffic observable in one broadcast domain. The trade-off is a large
blast-radius for broadcast storms and ARP attacks — which is exactly why the
switch config leans on port security, BPDU guard, DHCP snooping and DAI.

---

## 4. Packet Flow Analysis

**Scenario:** PC1 (`.10`) pings the Server (`.30`) with an empty ARP cache.

1. PC1 checks its ARP cache for `192.168.10.30` → miss.
2. PC1 broadcasts **ARP request** (opcode 1): SHA=PC1-MAC, SPA=.10,
   THA=00:00:00:00:00:00, TPA=.30, Ethernet dst = broadcast.
3. **SW1 learning + flooding.** SW1 records PC1's source MAC against Fa0/2 in
   its CAM table, then floods the broadcast out every other VLAN-10 port
   (Fa0/1, Fa0/3, Fa0/4, Fa0/5).
4. PC2 and Printer receive it, see TPA ≠ their IP, and drop it (they may still
   cache PC1's binding opportunistically).
5. Server sees TPA = its IP and sends a **unicast ARP reply** (opcode 2):
   SHA=SRV-MAC, SPA=.30, THA=PC1-MAC, TPA=.10.
6. SW1 has already learned SRV-MAC (or learns it now) and forwards the reply
   **only** out Fa0/2 — no flooding, because the destination is known-unicast.
7. PC1 caches `.30 → SRV-MAC` and sends the actual ICMP echo. The gateway is
   resolved the same way when traffic leaves the subnet.

Key observations:
- The request is **broadcast**, the reply is **unicast**.
- The **switch learns source MACs** from every frame and only floods when the
  destination is unknown/broadcast/multicast.
- Resolution latency (request→reply) is typically **sub-millisecond** on a LAN;
  `pcap_analyzer.py` measures it precisely.

---

## 5. Wireshark / Simulation Observations

Capture on PC1 with display filter `arp`. Expected rows:

| No. | Source | Destination | Protocol | Info |
|-----|--------|-------------|----------|------|
| 1 | PC1-MAC | Broadcast | ARP | Who has 192.168.10.30? Tell 192.168.10.10 |
| 2 | SRV-MAC | PC1-MAC   | ARP | 192.168.10.30 is at _SRV-MAC_ |

Toolkit cross-checks:

- `python pcap_analyzer.py capture.pcapng` → counts requests/replies, pairs
  each request with its reply, prints min/max/mean latency, and flags any IP
  seen with more than one MAC.
- `python arp_monitor.py -i "Ethernet"` → live decode of the same exchange,
  with inline **ALERT** lines if a binding changes.
- `python arp_audit.py` → shows the resulting cache entries, their
  dynamic/static type, and anomalies.

Representative anomaly (poisoning): the gateway IP `192.168.10.1` suddenly
resolving to the attacker's MAC, and that same MAC also claiming the server's
IP — caught by both the "MAC CHANGE" and "MAC claims N IPs" heuristics.

---

## 6. Security Hardening

ARP has **no authentication** — any host can answer any request, or send
unsolicited replies, and receivers believe them. This enables **ARP spoofing
/ cache poisoning**, the basis for man-in-the-middle, traffic interception,
and denial of service.

### 6.1 Switch-side controls (see `configs/SW1_startup-config.txt`)

- **Port security** (`maximum 1`, `sticky`, `violation restrict`): one MAC per
  access port, defeating CAM-table flooding and making rogue hosts obvious.
- **DHCP snooping**: builds a trusted `IP↔MAC↔port` binding table; untrusted
  ports can't offer DHCP.
- **Dynamic ARP Inspection (DAI)**: validates every ARP on untrusted ports
  against the snooping binding table and drops forged ones — the single most
  effective anti-poisoning control. Uplink to R1 is `trust`ed; access ports
  are untrusted and rate-limited.
- **BPDU guard / PortFast** on access ports; unused ports shut down.

### 6.2 Router / host controls

- **Shorter ARP timeout** and optional **static ARP** entries for critical
  infrastructure (server, printer) on R1 so a spoofed reply can't overwrite
  them.
- **Static/sticky gateway entries** on endpoints where feasible.

### 6.3 Detection (this toolkit)

- `arp_monitor.py` flags MAC changes, one-MAC-many-IPs, and baseline
  mismatches in real time.
- `pcap_analyzer.py` flags any IP with multiple MACs across a capture.
- `arp_audit.py` audits the live cache against a trusted `baseline.json` and
  exits non-zero when anomalies exist (CI-friendly).

### 6.4 Defense-in-depth summary

| Layer | Control | Mitigates |
|-------|---------|-----------|
| Switch | DAI + DHCP snooping | ARP spoofing/poisoning |
| Switch | Port security (sticky) | MAC flooding, rogue hosts |
| Router | Static ARP, short timeout | Gateway impersonation |
| Host | Static gateway entry | MITM via gateway spoof |
| Ops | Monitor + audit tooling | Early detection, forensics |

---

## 7. Conclusion

ARP is simple, essential, and inherently trusting. In a flat enterprise VLAN
that trust is a liability: a single unauthenticated reply can redirect traffic
for the whole subnet. The combination of **packet-level understanding**,
**switch-enforced validation (DAI + port security)**, **router/host static
anchoring**, and **continuous monitoring** turns ARP from a soft target into a
manageable, observable part of the LAN. The accompanying toolkit makes each of
these steps reproducible on real or simulated gear.

---

## References

- D. Plummer, *RFC 826: An Ethernet Address Resolution Protocol*, 1982.
- Cisco, *Catalyst 2960 Configuration Guide — Dynamic ARP Inspection & Port Security*.
- Scapy documentation, <https://scapy.readthedocs.io>.
