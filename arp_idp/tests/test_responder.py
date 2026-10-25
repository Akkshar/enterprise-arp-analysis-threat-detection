from datetime import datetime

from config.settings import load_weights
from src.detection.baseline import TrustedBaseline
from src.models.incident import Incident, RiskTier
from src.prevention.responder import Responder

NOON = datetime(2026, 10, 24, 12, 0, 0).timestamp()
BASE = {
    "gateways": {"192.168.10.1": "00:1a:2b:00:00:01"},
    "static_hosts": {"192.168.10.30": "00:1a:2b:00:00:30"},
    "known_macs": [],
}


def responder(apply=False):
    bl = TrustedBaseline(BASE)
    return Responder(bl, load_weights()["response_policy"], apply=apply, iface="Ethernet"), bl


def critical_gw_incident():
    return Incident(claimed_ip="192.168.10.1", offending_mac="de:ad:be:ef:00:66",
                    baseline_mac="00:1a:2b:00:00:01", first_time=NOON, last_time=NOON,
                    risk_tier=RiskTier.CRITICAL,
                    recommended_action="Quarantine the switch port.")


def test_dry_run_does_not_apply():
    r, _ = responder(apply=False)
    actions = r.respond(critical_gw_incident())
    kinds = {a.kind for a in actions}
    assert {"recommend", "pin_anchor", "quarantine", "reassert"} <= kinds
    assert all(not a.applied for a in actions)                 # nothing executed
    pin = next(a for a in actions if a.kind == "pin_anchor")
    assert "00-1a-2b-00-00-01" in pin.command                  # pins the TRUE anchor mac


def test_pin_only_for_anchors():
    r, _ = responder()
    non_anchor = Incident(claimed_ip="192.168.10.77", offending_mac="de:ad:be:ef:00:66",
                          baseline_mac=None, first_time=NOON, last_time=NOON,
                          risk_tier=RiskTier.HIGH)
    kinds = {a.kind for a in r.respond(non_anchor)}
    assert "pin_anchor" not in kinds   # no true anchor MAC to pin
    assert "quarantine" in kinds       # port quarantine still generated


def test_medium_incident_only_recommends():
    r, _ = responder()
    med = Incident(claimed_ip="192.168.10.30", offending_mac="x", baseline_mac="y",
                   first_time=NOON, last_time=NOON, risk_tier=RiskTier.MEDIUM,
                   recommended_action="Raise a ticket.")
    kinds = {a.kind for a in r.respond(med)}
    assert kinds == {"recommend"}      # pin/quarantine need HIGH+


def test_unpin_command():
    r, _ = responder()
    assert "192.168.10.1" in r.unpin("192.168.10.1")
