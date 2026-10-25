from datetime import datetime

from src.detection.baseline import TrustedBaseline

DATA = {
    "gateways": {"192.168.10.1": "00:1a:2b:00:00:01"},
    "static_hosts": {"192.168.10.30": "00:1a:2b:00:00:30"},
    "known_macs": ["00:1a:2b:00:00:10"],
    "business_hours": [8, 20],
    "dhcp_events": [{"ip": "192.168.10.20", "mac": "00:aa:00:00:00:20", "time": 1000, "window": 60}],
    "maintenance": [{"start": 2000, "end": 2100, "ip": "192.168.10.10"}],
}


def bl():
    return TrustedBaseline(DATA)


def test_anchors_and_lookup():
    b = bl()
    assert b.is_gateway("192.168.10.1")
    assert b.is_anchor("192.168.10.30")
    assert b.anchor_role("192.168.10.1") == "gateway"
    assert b.anchor_role("192.168.10.30") == "server"
    assert b.expected_mac("192.168.10.1") == "00:1a:2b:00:00:01"


def test_learn_never_overwrites_anchor():
    b = bl()
    b.learn("192.168.10.1", "de:ad:be:ef:00:66")   # attempt to poison the anchor
    assert b.expected_mac("192.168.10.1") == "00:1a:2b:00:00:01"
    b.learn("192.168.10.99", "00:11:22:33:44:55")   # non-anchor is learned
    assert b.expected_mac("192.168.10.99") == "00:11:22:33:44:55"


def test_context_windows():
    b = bl()
    assert b.dhcp_explains("192.168.10.20", "00:aa:00:00:00:20", 1030)
    assert not b.dhcp_explains("192.168.10.20", "00:aa:00:00:00:20", 2000)
    assert b.in_maintenance("192.168.10.10", 2050)
    assert not b.in_maintenance("192.168.10.10", 2500)


def test_off_hours():
    b = bl()
    noon = datetime(2026, 10, 24, 12, 0, 0).timestamp()
    night = datetime(2026, 10, 24, 2, 0, 0).timestamp()
    assert not b.off_hours(noon)
    assert b.off_hours(night)
