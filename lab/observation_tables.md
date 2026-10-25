# ARP Observation Tables — Expected vs Observed

Project: Enterprise ARP Analysis & Threat Detection
Team: Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan

Fill the **Observed** column from Packet Tracer Simulation Mode (PDU details)
or a Wireshark capture. Expected values come from the IP plan and ARP's rules.

---

## A. Same-subnet resolution — PC1 → PC2 (both VLAN 10)

Run on PC1: `arp -d`  then  `ping 192.168.10.20`  then  `arp -a`.

| # | Observation | Expected | Observed |
|---|-------------|----------|----------|
| 1 | First frame after `arp -d` | ARP **request**, opcode 1, from PC1 | [FILL] |
| 2 | Request Ethernet destination | FF:FF:FF:FF:FF:FF (broadcast) | [FILL] |
| 3 | Request ARP target MAC | 00:00:00:00:00:00 (unknown) | [FILL] |
| 4 | PC2 response | ARP **reply**, opcode 2, unicast to PC1 | [FILL] |
| 5 | SW1 forwards the reply | out PC1's port only (not flooded) | [FILL] |
| 6 | PC1 cache (`arp -a`) | 192.168.10.20 → PC2's MAC (dynamic) | [FILL] |
| 7 | Resolution latency (req→reply) | sub-millisecond | [FILL] |

## B. Cross-subnet resolution — PC1 (VLAN10) → Server (VLAN20)

Run on PC1: `arp -d`  then  `ping 192.168.20.30`  then  `arp -a`.

| # | Observation | Expected | Observed |
|---|-------------|----------|----------|
| 1 | PC1 subnet check | .20.30 not local → needs the gateway | [FILL] |
| 2 | PC1 ARP target | 192.168.10.1 (gateway), **not** the server | [FILL] |
| 3 | R1 reply | R1's G0/0.10 MAC, unicast to PC1 | [FILL] |
| 4 | PC1 cache after ping | only 192.168.10.x entries (gateway) | [FILL] |
| 5 | Server's MAC on PC1 | **never appears** in VLAN 10 | [FILL] |
| 6 | R1 cache (`show ip arp`) | PC1 on G0/0.10, server on G0/0.20 | [FILL] |

## C. Switch learning

| # | Observation | Expected | Observed |
|---|-------------|----------|----------|
| 1 | `show mac address-table dynamic` | PC1 MAC learned on Fa0/1 | [FILL] |
| 2 | Broadcast flooding | request reaches all VLAN-10 ports | [FILL] |
| 3 | Unicast reply | forwarded only on the learned port | [FILL] |

## D. Attack detection (IDP) — expected tier per scenario

Feed the capture to the IDP: `arpguard analyze <pcap> -b baseline.json`.

| Scenario | Signal(s) expected | Expected tier | Observed tier |
|----------|--------------------|---------------|---------------|
| Gateway impersonation (rogue claims 192.168.10.1) | GATEWAY_IMPERSONATION | CRITICAL | [FILL] |
| Server poisoning (rogue claims 192.168.20.30) | MAC_CHANGE + UNKNOWN_DEVICE | HIGH/CRITICAL | [FILL] |
| Duplicate IP (two MACs claim one IP) | DUPLICATE_IP + MAC_CHANGE | HIGH/CRITICAL | [FILL] |
| ARP flood (one MAC, many requests) | ABNORMAL_RATE | MEDIUM | [FILL] |
| Cross-VLAN lateral (one MAC in VLAN 30 + VLAN 10) | CROSS_VLAN | MEDIUM | [FILL] |
| DHCP renewal (benign) | — (explained) | INFO (no alert) | [FILL] |
| Server failover (benign) | DUPLICATE_IP (in window) | LOW (no alert) | [FILL] |

## E. Prevention (IDP response) — expected actions

`arpguard respond <pcap> -b baseline.json` (dry-run) or `--apply`.

| Tier observed | Expected recommended action |
|---------------|-----------------------------|
| CRITICAL | pin_anchor (static ARP) + quarantine port + reassert + notify SOC |
| HIGH | pin_anchor + quarantine + verify device |
| MEDIUM | recommend (ticket + watch), no auto-block |
| LOW/INFO | log only |
