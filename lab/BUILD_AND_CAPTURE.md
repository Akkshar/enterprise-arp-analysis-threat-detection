# Build & Capture Guide — Packet Tracer + Wireshark → IDP

Project: Enterprise ARP Analysis & Threat Detection
Team: Stuti Zingade · Ritika Tulsyan · Akkshar Ranjan

This is the **diagnosis / analysis** half (Part 1). It builds the lab, captures
real ARP, and feeds the capture to the detection/prevention system (Part 2).

See `topology.svg` for the diagram and `IP_plan.md` for addressing.

---

## 1. Build the topology (Cisco Packet Tracer)

1. Place devices: **R1** (router, e.g. 2911), **SW1** (2960), **PC1**, **PC2**,
   **Server**, a **laptop as Guest**, and one PC as the **IDP sensor**.
2. Cable: R1 `G0/0` ↔ SW1 `Gi0/1`; PC1→Fa0/1, PC2→Fa0/2, Server→Fa0/3,
   Guest→Fa0/4, Sensor→Fa0/24.
3. Address each end device from `IP_plan.md` (Desktop → IP Configuration):
   IP, mask `255.255.255.0`, and the gateway for its VLAN.
4. Paste `configs/R1_startup-config.txt` into R1's CLI and
   `configs/SW1_startup-config.txt` into SW1's CLI (adjust interface names to
   your Packet Tracer models; some 2960 images don't support DAI — see note).
5. Verify links are up: on R1 `show ip interface brief`; on SW1 `show vlan brief`
   and `show interfaces trunk`.

> **Packet Tracer note:** DAI / DHCP snooping / SPAN support varies by PT
> version. If your image rejects `ip arp inspection` or `monitor session`,
> keep them in the config as the documented design and do the live IDP step
> (Part 2) against an **exported pcap** instead of a SPAN feed — the detection
> result is identical.

## 2. Capture ARP (the diagnosis)

### Option A — Simulation Mode (pure Packet Tracer)
1. Switch to **Simulation Mode** (bottom-right).
2. **Edit Filters** → show only **ARP** and **ICMP**.
3. On **PC1** command prompt: `arp -d`, then `ping 192.168.10.20`.
4. Use **Capture / Forward** to step through the events; open each ARP PDU and
   read **opcode, sender/target MAC and IP** into `observation_tables.md` (A).
5. Repeat for the cross-subnet case: `arp -d`, `ping 192.168.20.30` (table B).

### Option B — Wireshark on a real/VM host (richer evidence)
1. Start Wireshark on the capturing interface, display filter `arp`.
2. Clear the cache and ping as above; stop and **File → Export** as `.pcap`.

## 3. Feed the capture to the IDP (the solution)

```bash
cd ../arp_idp
pip install -e ".[dev]"            # scapy, typer, rich, pyyaml, pytest

# Use your captured pcap, or the labelled synthetic dataset:
python main.py gen-data --variant multivlan        # builds test_data_mvlan/
python main.py analyze test_data_mvlan/arp_dataset.pcap -b test_data_mvlan/baseline.json --detail
python main.py backtest --data test_data_mvlan      # metrics vs ground truth
python main.py respond  test_data_mvlan/arp_dataset.pcap -b test_data_mvlan/baseline.json
```

To analyse **your own** Packet Tracer / Wireshark export, point `analyze` at it
and pass a baseline built from `IP_plan.md` (gateways + server as anchors,
your real MACs in `known_macs`).

## 4. Demonstrate an ARP attack + detection (optional, lab only)

1. Add an attacker PC to VLAN 10. Use a gratuitous-ARP tool (or Packet Tracer's
   limited ARP) to claim `192.168.10.1`.
2. Capture it, export, and run `arpguard analyze` → expect a **CRITICAL
   gateway_impersonation** incident.
3. Show the switch-side prevention working: `show ip arp inspection statistics`
   (DAI drops rising) and `show port-security` (violation on the rogue port).

## 5. Record results

- Fill every `[FILL]` in `observation_tables.md` from your captures.
- Screenshot: (1) topology built, (2) ARP request+reply in Wireshark/PT,
  (3) `ping` + `arp -a` output, (4) an `arpguard analyze` CRITICAL incident.
- Compare **expected vs observed**; explain any deviation.
