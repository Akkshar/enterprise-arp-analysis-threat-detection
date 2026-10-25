"""Core schemas for the ARP IDP: events, flags, and the incident report.

Mirrors the rugscan RiskReport model family: a report carries typed flags
(each with a code, severity and points) plus the composite risk score/tier.
Unknown facts are ``None``, never guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import StrEnum


class RiskTier(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Severity of an individual flag (same scale as the tier).
Severity = RiskTier

TIER_ORDER = [RiskTier.INFO, RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL]
TIER_RANK = {t: i for i, t in enumerate(TIER_ORDER)}


@dataclass
class ArpObservation:
    """One normalised ARP observation from a capture or live interface."""
    time: float
    op: int                 # 1 request, 2 reply
    src_ip: str
    src_mac: str
    dst_ip: str = ""
    dst_mac: str = ""
    vlan: int | None = None
    port: str | None = None


@dataclass
class Flag:
    """A single detection signal that fired, with its scored contribution."""
    code: str               # e.g. GATEWAY_IMPERSONATION
    severity: Severity
    points: float
    detail: str
    context_factor: float = 1.0
    unlowerable: bool = False   # critical flags that context can never reduce


@dataclass
class Incident:
    """Composite report for one offending binding (≈ rugscan RiskReport)."""
    claimed_ip: str
    offending_mac: str
    baseline_mac: str | None
    first_time: float
    last_time: float
    vlan: int | None = None
    port: str | None = None
    flags: list[Flag] = field(default_factory=list)
    risk_score: float = 0.0
    risk_tier: RiskTier = RiskTier.INFO
    escalations: list = field(default_factory=list)   # [(time, tier)]
    recommended_action: str = ""

    @property
    def first_iso(self) -> str:
        return datetime.fromtimestamp(self.first_time).isoformat(timespec="seconds")

    def top_flag(self) -> Flag | None:
        return max(self.flags, key=lambda f: f.points) if self.flags else None

    def alert_time(self, min_tier: RiskTier) -> float | None:
        want = TIER_RANK[min_tier]
        for t, tier in self.escalations:
            if TIER_RANK[RiskTier(tier)] >= want:
                return t
        return None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_tier"] = self.risk_tier.value
        d["first_iso"] = self.first_iso
        for fl in d["flags"]:
            fl["severity"] = fl["severity"].value if hasattr(fl["severity"], "value") else fl["severity"]
        return d
