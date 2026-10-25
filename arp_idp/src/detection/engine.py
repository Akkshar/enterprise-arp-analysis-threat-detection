"""Detection engine: five context-aware signals -> scored incidents.

Points come from config/signal_weights.yaml, not from code (mirrors rugscan's
YAML-driven ScoringEngine). Each firing signal becomes a Flag; flags are summed
per offending binding into an Incident with a risk tier.
"""

from __future__ import annotations

from collections import defaultdict, deque

from config.settings import load_weights
from src.detection.baseline import TrustedBaseline
from src.models.incident import (ArpObservation, Flag, Incident, RiskTier,
                                 Severity, TIER_RANK)

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"

RECOMMENDATION = {
    RiskTier.CRITICAL: "Quarantine the switch port; drop via DAI; notify SOC immediately.",
    RiskTier.HIGH: "Isolate/verify the device; drop forged ARP via DAI; raise priority ticket.",
    RiskTier.MEDIUM: "Raise a ticket; watch the device; verify the binding against inventory.",
    RiskTier.LOW: "Log for history; confirm the device during next onboarding review.",
    RiskTier.INFO: "Record for trend analysis only.",
}


class DetectionEngine:
    def __init__(self, baseline: TrustedBaseline, weights_path: str | None = None):
        self.bl = baseline
        self.cfg = load_weights(weights_path)
        self.base_weight = self.cfg["base_weight"]
        self.sig = self.cfg["signals"]
        self.cf = self.cfg["context_factors"]
        self.rate_window = self.cfg["rate_window_seconds"]
        self.rate_threshold = self.cfg["rate_threshold"]
        self.incident_gap = self.cfg["incident_gap_seconds"]

        self.ip_macs_recent: dict[str, dict] = defaultdict(dict)
        self.mac_times: dict[str, deque] = defaultdict(deque)
        self.mac_vlan: dict[str, int] = {}          # first-seen VLAN per MAC
        self.open_incidents: dict[str, Incident] = {}
        self.incidents: list[Incident] = []

    def _flag(self, code: str, signal_key: str, detail: str, factor: float = 1.0) -> Flag:
        sev = Severity(self.sig[signal_key]["severity"])
        unlowerable = bool(self.sig[signal_key].get("unlowerable", False))
        if unlowerable:
            factor = 1.0
        points = round(self.base_weight[sev.value] * factor, 1)
        return Flag(code=code, severity=sev, points=points, detail=detail,
                    context_factor=factor, unlowerable=unlowerable)

    def _score_tier(self, score: float, has_unlowerable_critical: bool) -> RiskTier:
        if has_unlowerable_critical:
            return RiskTier.CRITICAL
        for tier, thr in self.cfg["tier_thresholds"].items():
            if score >= thr:
                return RiskTier(tier)
        return RiskTier.INFO

    # -- per-observation signal evaluation -------------------------------
    def _signals_for(self, ev: ArpObservation) -> list[Flag]:
        out: list[Flag] = []
        ip, mac, t = ev.src_ip, (ev.src_mac or "").lower(), ev.time
        if not ip or ip == "0.0.0.0" or not mac or mac in (ZERO_MAC, BROADCAST):
            return out

        expected = self.bl.expected_mac(ip)

        # 1) gateway impersonation (never lowered)
        if self.bl.is_gateway(ip) and mac != self.bl.gateways[ip]:
            out.append(self._flag("GATEWAY_IMPERSONATION", "gateway_impersonation",
                                  f"{mac} claims gateway {ip} (anchor {self.bl.gateways[ip]})"))
        # 2) MAC change for a known IP
        elif expected and mac != expected:
            factor, why, key = 1.0, "", ("mac_change_anchor" if self.bl.is_anchor(ip)
                                         else "mac_change_host")
            if self.bl.dhcp_explains(ip, mac, t):
                factor, why = self.cf["dhcp_explained"], " [DHCP-explained]"
            elif self.bl.in_maintenance(ip, t):
                factor, why = self.cf["maintenance_window"], " [maintenance window]"
            elif self.bl.off_hours(t):
                factor, why = self.cf["off_hours"], " [off-hours]"
            out.append(self._flag("MAC_CHANGE", key, f"{ip}: {expected} -> {mac}{why}", factor))

        # 3) duplicate IP
        recent = self.ip_macs_recent[ip]
        recent[mac] = t
        for m, lt in list(recent.items()):
            if t - lt > self.rate_window:
                del recent[m]
        if len(recent) >= 2:
            factor, why = 1.0, ""
            if self.bl.in_maintenance(ip, t):
                factor, why = self.cf["failover_window"], " [failover/maintenance]"
            elif any(m not in self.bl.known_macs for m in recent):
                factor = self.cf["unknown_mac_involved"]
            out.append(self._flag("DUPLICATE_IP", "duplicate_ip",
                                  f"{ip} claimed by {sorted(recent)}{why}", factor))

        # 4) abnormal rate
        dq = self.mac_times[mac]
        dq.append(t)
        while dq and t - dq[0] > self.rate_window:
            dq.popleft()
        if len(dq) > self.rate_threshold:
            out.append(self._flag("ABNORMAL_RATE", "abnormal_rate",
                                  f"{mac} sent {len(dq)} ARP in {self.rate_window:.0f}s "
                                  f"(threshold {self.rate_threshold})",
                                  self.cf["unknown_mac_involved"]))

        # 5) unknown device
        if mac not in self.bl.known_macs and not self.bl.dhcp_explains(ip, mac, t):
            factor = self.cf["off_hours_unknown"] if self.bl.off_hours(t) else 1.0
            out.append(self._flag("UNKNOWN_DEVICE", "unknown_device",
                                  f"{mac} not in known inventory"
                                  + (" [off-hours]" if factor > 1 else ""), factor))

        # 6) cross-VLAN: one MAC seen in two VLANs (lateral movement)
        if ev.vlan is not None:
            seen = self.mac_vlan.get(mac)
            if seen is not None and seen != ev.vlan:
                out.append(self._flag("CROSS_VLAN", "cross_vlan",
                                      f"{mac} seen in VLAN {seen} and VLAN {ev.vlan}"))
            else:
                self.mac_vlan.setdefault(mac, ev.vlan)
        return out

    # -- incident aggregation --------------------------------------------
    def process(self, ev: ArpObservation) -> Incident | None:
        flags = self._signals_for(ev)
        if not any(f.severity in (RiskTier.CRITICAL, RiskTier.HIGH) for f in flags):
            self.bl.learn(ev.src_ip, ev.src_mac)
        if not flags:
            return None

        key = ev.src_ip
        inc = self.open_incidents.get(key)
        if inc and ev.time - inc.last_time > self.incident_gap:
            inc = None
        if inc is None:
            inc = Incident(claimed_ip=ev.src_ip, offending_mac=(ev.src_mac or "").lower(),
                           baseline_mac=self.bl.expected_mac(ev.src_ip),
                           first_time=ev.time, last_time=ev.time,
                           vlan=ev.vlan, port=ev.port)
            self.open_incidents[key] = inc
            self.incidents.append(inc)
        inc.last_time = ev.time

        existing = {f.code: f for f in inc.flags}
        for f in flags:
            cur = existing.get(f.code)
            if cur is None or f.points > cur.points:
                if cur is not None:
                    inc.flags.remove(cur)
                inc.flags.append(f)
                existing[f.code] = f

        inc.risk_score = round(sum(f.points for f in inc.flags), 1)
        has_crit = any(f.unlowerable and f.severity == RiskTier.CRITICAL for f in inc.flags)
        inc.risk_tier = self._score_tier(inc.risk_score, has_crit)
        inc.recommended_action = RECOMMENDATION[inc.risk_tier]

        highest = inc.escalations[-1][1] if inc.escalations else RiskTier.INFO.value
        if not inc.escalations or TIER_RANK[inc.risk_tier] > TIER_RANK[RiskTier(highest)]:
            inc.escalations.append((ev.time, inc.risk_tier.value))
        return inc

    def run(self, observations) -> list[Incident]:
        for ev in observations:
            self.process(ev)
        return self.incidents

    def summary(self) -> dict:
        by_tier = defaultdict(int)
        for inc in self.incidents:
            by_tier[inc.risk_tier.value] += 1
        return {"incidents": len(self.incidents), "by_tier": dict(by_tier)}
