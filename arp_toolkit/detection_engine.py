#!/usr/bin/env python3
"""
detection_engine.py - Context-aware ARP threat detection engine.

Part of "Enterprise ARP Threat Detection".
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

This is the heart of the SOLUTION half of the project. It consumes a stream
of normalised ARP observations and produces risk-scored INCIDENTS using five
detection signals combined with per-device context:

  1. gateway_impersonation  - a non-anchor MAC claims a gateway IP   (CRITICAL)
  2. mac_change             - a known IP's MAC changes               (base HIGH)
  3. duplicate_ip           - two MACs claim one IP at once          (base HIGH)
  4. abnormal_rate          - a host's ARP volume spikes             (base MEDIUM)
  5. unknown_device         - new MAC / off-hours / odd behaviour    (base LOW)

Context (DHCP events, maintenance windows, business hours, known inventory)
raises or lowers each signal's weight, so benign churn is explained instead of
alerted. Gateway impersonation is never lowered by context.

Pure standard library -- the engine does NOT import scapy, so it is easy to
unit-test. Scapy is only used by the capture front-ends (detect.py, etc.).
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime

# --------------------------------------------------------------------------
# Risk model
# --------------------------------------------------------------------------
TIERS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
TIER_RANK = {t: i for i, t in enumerate(TIERS)}

# Base points contributed by a signal at its nominal tier.
BASE_WEIGHT = {
    "INFO": 5,
    "LOW": 15,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 100,
}

# Total-score thresholds -> overall incident tier.
SCORE_TO_TIER = [
    (100, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (15, "LOW"),
    (0, "INFO"),
]

MITIGATION = {
    "CRITICAL": "Quarantine the switch port; drop via DAI; notify SOC immediately.",
    "HIGH": "Isolate/verify the device; drop forged ARP via DAI; raise priority ticket.",
    "MEDIUM": "Raise a ticket; watch the device; verify the binding against inventory.",
    "LOW": "Log for history; confirm the device during next onboarding review.",
    "INFO": "Record for trend analysis only.",
}

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


def score_to_tier(score: float) -> str:
    for threshold, tier in SCORE_TO_TIER:
        if score >= threshold:
            return tier
    return "INFO"


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------
@dataclass
class ArpEvent:
    """One normalised ARP observation (from live sniff or a pcap)."""
    time: float
    op: int                 # 1 request, 2 reply
    src_ip: str
    src_mac: str
    dst_ip: str
    dst_mac: str
    vlan: int | None = None
    port: str | None = None


@dataclass
class Signal:
    name: str
    base_tier: str
    context_factor: float   # <1 lowers, >1 raises
    detail: str
    points: float = 0.0

    def compute(self) -> float:
        self.points = round(BASE_WEIGHT[self.base_tier] * self.context_factor, 1)
        return self.points


@dataclass
class Incident:
    first_time: float
    last_time: float
    claimed_ip: str
    offending_mac: str
    baseline_mac: str | None
    vlan: int | None
    port: str | None
    signals: list = field(default_factory=list)
    score: float = 0.0
    tier: str = "INFO"
    escalations: list = field(default_factory=list)  # [(time, tier)] as tier rises

    def alert_time(self, min_tier: str) -> float | None:
        """Earliest time this incident reached >= min_tier (None if never)."""
        want = TIER_RANK[min_tier]
        for t, tier in self.escalations:
            if TIER_RANK[tier] >= want:
                return t
        return None

    def finalize(self):
        self.score = round(sum(s.points for s in self.signals), 1)
        # An unlowerable CRITICAL signal forces at least CRITICAL overall.
        has_critical = any(s.base_tier == "CRITICAL" and s.context_factor >= 1.0
                           for s in self.signals)
        self.tier = "CRITICAL" if has_critical else score_to_tier(self.score)
        return self

    def to_dict(self):
        d = asdict(self)
        d["first_iso"] = datetime.fromtimestamp(self.first_time).isoformat(timespec="seconds")
        d["mitigation"] = MITIGATION[self.tier]
        return d


# --------------------------------------------------------------------------
# Trusted baseline (the "memory" that makes detection context-aware)
# --------------------------------------------------------------------------
class TrustedBaseline:
    """Expected IP->MAC bindings plus the context that explains benign change.

    JSON schema (see baseline.detection.example.json):
      {
        "gateways":      {"192.168.10.1": "00:1a:..:01"},   # anchors (critical)
        "static_hosts":  {"192.168.10.30": "00:1a:..:30"},  # anchors (high)
        "known_macs":    ["00:1a:..:10", ...],
        "business_hours":[8, 20],
        "dhcp_events":   [{"ip":"..","mac":"..","time":T,"window":120}],
        "maintenance":   [{"start":T,"end":T,"ip":".. or null"}]
      }
    Dynamic bindings learned at runtime are kept separately.
    """

    def __init__(self, data: dict | None = None):
        data = data or {}
        self.gateways = {k: v.lower() for k, v in data.get("gateways", {}).items()}
        self.static_hosts = {k: v.lower() for k, v in data.get("static_hosts", {}).items()}
        self.known_macs = {m.lower() for m in data.get("known_macs", [])}
        self.business_hours = tuple(data.get("business_hours", [8, 20]))
        self.dhcp_events = data.get("dhcp_events", [])
        self.maintenance = data.get("maintenance", [])
        self.learned: dict[str, str] = {}  # ip -> mac, learned at runtime

    @classmethod
    def load(cls, path: str) -> "TrustedBaseline":
        with open(path) as fh:
            return cls(json.load(fh))

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

    def learn(self, ip: str, mac: str):
        # Anchors are never silently overwritten by learning.
        if not self.is_anchor(ip):
            self.learned[ip] = mac.lower()

    # -- context explanations --------------------------------------------
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


# --------------------------------------------------------------------------
# Detector
# --------------------------------------------------------------------------
class Detector:
    def __init__(self, baseline: TrustedBaseline,
                 rate_window: float = 5.0, rate_threshold: int = 20,
                 incident_gap: float = 10.0):
        self.bl = baseline
        self.rate_window = rate_window
        self.rate_threshold = rate_threshold
        self.incident_gap = incident_gap

        self.ip_last_mac: dict[str, str] = {}
        self.ip_macs_recent: dict[str, dict] = defaultdict(dict)  # ip -> {mac: last_t}
        self.mac_times: dict[str, deque] = defaultdict(deque)     # mac -> arp timestamps
        self.open_incidents: dict[str, Incident] = {}            # claimed_ip -> incident
        self.incidents: list[Incident] = []

    # -- signal evaluation for one event ---------------------------------
    def _signals_for(self, ev: ArpEvent) -> list[Signal]:
        out: list[Signal] = []
        ip, mac, t = ev.src_ip, (ev.src_mac or "").lower(), ev.time
        if not ip or ip in ("0.0.0.0",) or not mac or mac in (ZERO_MAC, BROADCAST):
            return out

        expected = self.bl.expected_mac(ip)

        # 1) Gateway impersonation (never lowered).
        if self.bl.is_gateway(ip) and mac != self.bl.gateways[ip]:
            out.append(Signal("gateway_impersonation", "CRITICAL", 1.0,
                              f"{mac} claims gateway {ip} (anchor {self.bl.gateways[ip]})"))

        # 2) MAC change for a known IP (anchor or learned), not the gateway case above.
        elif expected and mac != expected:
            factor = 1.0
            why = ""
            if self.bl.dhcp_explains(ip, mac, t):
                factor, why = 0.2, " [DHCP-explained]"
            elif self.bl.in_maintenance(ip, t):
                factor, why = 0.25, " [maintenance window]"
            elif self.bl.off_hours(t):
                factor, why = 1.3, " [off-hours]"
            base = "HIGH" if self.bl.is_anchor(ip) else "MEDIUM"
            out.append(Signal("mac_change", base, factor,
                              f"{ip}: {expected} -> {mac}{why}"))

        # 3) Duplicate IP: >1 distinct MAC for this IP within the rate window.
        recent = self.ip_macs_recent[ip]
        recent[mac] = t
        for m, lt in list(recent.items()):
            if t - lt > self.rate_window:
                del recent[m]
        if len(recent) >= 2:
            factor = 1.0
            why = ""
            if self.bl.in_maintenance(ip, t):
                factor, why = 0.3, " [failover/maintenance window]"
            unknown = any(m not in self.bl.known_macs for m in recent)
            if unknown and not why:
                factor = 1.2
            out.append(Signal("duplicate_ip", "HIGH", factor,
                              f"{ip} claimed by {sorted(recent)}{why}"))

        # 4) Abnormal ARP rate for this MAC.
        dq = self.mac_times[mac]
        dq.append(t)
        while dq and t - dq[0] > self.rate_window:
            dq.popleft()
        if len(dq) > self.rate_threshold:
            out.append(Signal("abnormal_rate", "MEDIUM", 1.2,
                              f"{mac} sent {len(dq)} ARP in {self.rate_window:.0f}s "
                              f"(threshold {self.rate_threshold})"))

        # 5) Unknown device / behaviour.
        if mac not in self.bl.known_macs and not self.bl.dhcp_explains(ip, mac, t):
            factor = 1.4 if self.bl.off_hours(t) else 1.0
            out.append(Signal("unknown_device", "LOW", factor,
                              f"{mac} not in known inventory"
                              + (" [off-hours]" if factor > 1 else "")))

        return out

    # -- incident aggregation --------------------------------------------
    def process(self, ev: ArpEvent):
        signals = self._signals_for(ev)
        # learn benign bindings so later changes are detectable
        if not any(s.base_tier in ("CRITICAL", "HIGH") for s in signals):
            self.bl.learn(ev.src_ip, ev.src_mac)
        if ev.src_ip:
            self.ip_last_mac[ev.src_ip] = (ev.src_mac or "").lower()
        if not signals:
            return

        for s in signals:
            s.compute()

        key = ev.src_ip
        inc = self.open_incidents.get(key)
        if inc and ev.time - inc.last_time > self.incident_gap:
            inc = None  # too old; start a fresh incident
        if inc is None:
            inc = Incident(first_time=ev.time, last_time=ev.time,
                           claimed_ip=ev.src_ip, offending_mac=(ev.src_mac or "").lower(),
                           baseline_mac=self.bl.expected_mac(ev.src_ip),
                           vlan=ev.vlan, port=ev.port)
            self.open_incidents[key] = inc
            self.incidents.append(inc)
        inc.last_time = ev.time

        # merge signals, keeping the strongest instance of each signal name
        existing = {s.name: s for s in inc.signals}
        for s in signals:
            cur = existing.get(s.name)
            if cur is None or s.points > cur.points:
                if cur is not None:
                    inc.signals.remove(cur)
                inc.signals.append(s)
                existing[s.name] = s
        inc.finalize()
        # Stamp the time whenever the incident reaches a new, higher tier,
        # so the latency metric measures when an ALERT was actually raised.
        highest = inc.escalations[-1][1] if inc.escalations else "INFO"
        if not inc.escalations or TIER_RANK[inc.tier] > TIER_RANK[highest]:
            inc.escalations.append((ev.time, inc.tier))

    def run(self, events) -> list[Incident]:
        for ev in events:
            self.process(ev)
        return self.incidents

    def summary(self) -> dict:
        by_tier = defaultdict(int)
        for inc in self.incidents:
            by_tier[inc.tier] += 1
        return {"incidents": len(self.incidents), "by_tier": dict(by_tier)}
