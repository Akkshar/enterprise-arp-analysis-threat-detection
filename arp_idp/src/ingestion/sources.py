"""ARP observation sources: PCAP replay and live capture.

Mirrors rugscan's provider split (mock fixture vs live RPC): here the "mock"
source is a labelled PCAP, and the live source is a sniffed interface. Both
yield normalised ArpObservation objects.
"""

from __future__ import annotations

from collections.abc import Iterator

from src.models.incident import ArpObservation


def _vlan_of(pkt) -> int | None:
    from scapy.all import Dot1Q
    return int(pkt[Dot1Q].vlan) if pkt.haslayer(Dot1Q) else None


def _to_obs(pkt) -> ArpObservation:
    from scapy.all import ARP
    a = pkt[ARP]
    return ArpObservation(time=float(pkt.time), op=int(a.op),
                          src_ip=a.psrc, src_mac=a.hwsrc,
                          dst_ip=a.pdst, dst_mac=a.hwdst, vlan=_vlan_of(pkt))


def from_pcap(path: str) -> Iterator[ArpObservation]:
    from scapy.all import ARP, rdpcap
    for pkt in rdpcap(path):
        if pkt.haslayer(ARP):
            yield _to_obs(pkt)


def live(iface: str | None, on_packet):
    """Sniff the interface, calling on_packet(ArpObservation) for each ARP."""
    from scapy.all import ARP, sniff

    def handle(pkt):
        if pkt.haslayer(ARP):
            on_packet(_to_obs(pkt))

    sniff(filter="arp", iface=iface, prn=handle, store=False)
