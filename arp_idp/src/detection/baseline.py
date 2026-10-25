"""Trusted IP->MAC baseline with anchors and benign-change context.

The baseline is the IDP's memory: gateway/server anchors (never silently
overwritten), the known-MAC inventory, and the DHCP events / maintenance
windows that EXPLAIN legitimate change.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


class TrustedBaseline:
    def __init__(self, data: dict | None = None):
        data = data or {}
        self.gateways = {k: v.lower() for k, v in data.get("gateways", {}).items()}
        self.static_hosts = {k: v.lower() for k, v in data.get("static_hosts", {}).items()}
        self.known_macs = {m.lower() for m in data.get("known_macs", [])}
        self.business_hours = tuple(data.get("business_hours", [8, 20]))
        self.dhcp_events = data.get("dhcp_events", [])
        self.maintenance = data.get("maintenance", [])
        self.learned: dict[str, str] = {}

    @classmethod
    def load(cls, path: str | Path) -> "TrustedBaseline":
        with open(path) as fh:
            return cls(json.load(fh))

    # -- lookups ---------------------------------------------------------
    def expected_mac(self, ip: str) -> str | None:
        if ip in self.gateways:
            return self.gateways[ip]
        if ip in self.static_hosts:
            return self.static_hosts[ip]
        return self.learned.get(ip)

    def is_anchor(self, ip: str) -> bool:
        return ip in self.gateways or ip in self.static_hosts

    def is_gateway(self, ip: str) -> bool:
        return ip in self.gateways

    def anchor_role(self, ip: str) -> str | None:
        if ip in self.gateways:
            return "gateway"
        if ip in self.static_hosts:
            return "server"
        return None

    def learn(self, ip: str, mac: str):
        if not self.is_anchor(ip) and ip and ip != "0.0.0.0":
            self.learned[ip] = mac.lower()

    # -- context ---------------------------------------------------------
    def dhcp_explains(self, ip: str, mac: str, t: float) -> bool:
        for e in self.dhcp_events:
            if e["ip"] == ip and e["mac"].lower() == mac.lower():
                if abs(t - e["time"]) <= e.get("window", 120):
                    return True
        return False

    def in_maintenance(self, ip: str, t: float) -> bool:
        for w in self.maintenance:
            if w["start"] <= t <= w["end"] and (w.get("ip") in (None, ip)):
                return True
        return False

    def off_hours(self, t: float) -> bool:
        hour = datetime.fromtimestamp(t).hour
        lo, hi = self.business_hours
        return not (lo <= hour < hi)

    def anchors(self) -> dict[str, dict]:
        out = {ip: {"mac": mac, "role": "gateway"} for ip, mac in self.gateways.items()}
        out.update({ip: {"mac": mac, "role": "server"} for ip, mac in self.static_hosts.items()})
        return out
