from datetime import datetime

from src.detection.baseline import TrustedBaseline
from src.detection.engine import DetectionEngine
from src.models.incident import ArpObservation, RiskTier

NOON = datetime(2026, 10, 24, 12, 0, 0).timestamp()
NIGHT = datetime(2026, 10, 24, 2, 0, 0).timestamp()

BASE = {
    "gateways": {"192.168.10.1": "00:1a:2b:00:00:01"},
    "static_hosts": {"192.168.10.30": "00:1a:2b:00:00:30"},
    "known_macs": ["00:1a:2b:00:00:01", "00:1a:2b:00:00:10", "00:1a:2b:00:00:30"],
    "business_hours": [8, 20],
    "dhcp_events": [{"ip": "192.168.10.20", "mac": "00:aa:00:00:00:20", "time": NOON, "window": 120}],
    "maintenance": [],
}


def eng():
    return DetectionEngine(TrustedBaseline(BASE))


def obs(t, ip, mac, vlan=None):
    return ArpObservation(time=t, op=2, src_ip=ip, src_mac=mac, vlan=vlan)


def test_gateway_impersonation_is_critical_and_unlowerable():
    e = eng()
    inc = e.process(obs(NIGHT, "192.168.10.1", "de:ad:be:ef:00:66"))
    assert inc.risk_tier == RiskTier.CRITICAL
    codes = {f.code for f in inc.flags}
    assert "GATEWAY_IMPERSONATION" in codes
    gi = next(f for f in inc.flags if f.code == "GATEWAY_IMPERSONATION")
    assert gi.unlowerable and gi.points == 100


def test_dhcp_renewal_is_not_an_alert():
    e = eng()
    inc = e.process(obs(NOON, "192.168.10.20", "00:aa:00:00:00:20"))
    # explained renewal -> at most INFO/LOW, never MEDIUM+
    assert inc is None or inc.risk_tier in (RiskTier.INFO, RiskTier.LOW)


def test_known_benign_resolution_raises_nothing():
    e = eng()
    assert e.process(obs(NOON, "192.168.10.1", "00:1a:2b:00:00:01")) is None
    assert e.process(obs(NOON, "192.168.10.10", "00:1a:2b:00:00:10")) is None


def test_server_poisoning_flags_mac_change():
    e = eng()
    inc = e.process(obs(NOON, "192.168.10.30", "de:ad:be:ef:00:66"))
    codes = {f.code for f in inc.flags}
    assert "MAC_CHANGE" in codes
    assert inc.risk_tier in (RiskTier.HIGH, RiskTier.CRITICAL)


def test_duplicate_ip():
    e = eng()
    e.process(obs(NOON, "192.168.10.40", "00:1a:2b:00:00:40"))
    inc = e.process(obs(NOON + 0.1, "192.168.10.40", "de:ad:be:ef:00:77"))
    assert "DUPLICATE_IP" in {f.code for f in inc.flags}


def test_abnormal_rate():
    e = eng()
    inc = None
    for i in range(30):
        inc = e.process(obs(NOON + i * 0.05, "192.168.10.200", "de:ad:be:ef:00:66"))
    assert inc is not None and "ABNORMAL_RATE" in {f.code for f in inc.flags}


def test_cross_vlan_lateral_movement():
    e = eng()
    e.process(obs(NOON, "192.168.30.66", "de:ad:be:ef:00:77", vlan=30))
    inc = e.process(obs(NOON + 1, "192.168.10.66", "de:ad:be:ef:00:77", vlan=10))
    assert "CROSS_VLAN" in {f.code for f in inc.flags}


def test_off_hours_raises_score():
    day = eng().process(obs(NOON + 5000, "192.168.10.99", "00:bb:00:00:00:99"))
    night = eng().process(obs(NIGHT, "192.168.10.99", "00:bb:00:00:00:99"))
    assert night.risk_score > day.risk_score
