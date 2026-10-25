import json

import pytest

from src.data.scenarios import generate, scenario_list
from src.evaluation.backtest import run_backtest


def test_scenario_list_balanced():
    scen = scenario_list()
    assert len(scen) == 10
    assert sum(1 for s in scen if s["label"] == "attack") == 5
    assert sum(1 for s in scen if s["label"] == "benign") == 5


def test_generate_single(tmp_path):
    info = generate(tmp_path, "single")
    assert info["attacks"] == 5 and info["benign"] == 5
    assert (tmp_path / "arp_dataset.pcap").exists()
    assert (tmp_path / "labels.json").exists()
    assert (tmp_path / "baseline.json").exists()


def test_generate_multivlan(tmp_path):
    info = generate(tmp_path, "multivlan")
    assert info["variant"] == "multivlan"
    bl = json.loads((tmp_path / "baseline.json").read_text())
    assert len(bl["gateways"]) == 3           # VLANs 10/20/30


def test_backtest_single_perfect_detection(tmp_path):
    generate(tmp_path, "single")
    m = run_backtest(tmp_path, "MEDIUM")
    assert m["detection_rate"] == 1.0         # all attacks caught
    assert m["false_positive_rate"] == 0.0    # no benign flagged
    assert m["confusion"]["FN"] == 0
    assert m["latency_ms"]["mean"] > 0        # realistic, non-zero latency


def test_backtest_multivlan_detects_cross_vlan(tmp_path):
    generate(tmp_path, "multivlan")
    m = run_backtest(tmp_path, "MEDIUM")
    assert m["detection_rate"] == 1.0
    assert m["false_positive_rate"] == 0.0
    types = {r["type"]: r["verdict"] for r in m["per_episode"]}
    assert types["cross_vlan_lateral"] == "TP"
