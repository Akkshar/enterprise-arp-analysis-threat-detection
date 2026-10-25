"""Backtest the IDP against labelled ground truth.

Mirrors rugscan's backtest: runs the detector over a labelled capture and
computes detection rate, false-positive rate, latency and mitigation effect,
plus a per-episode confusion matrix.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.detection.baseline import TrustedBaseline
from src.detection.engine import DetectionEngine
from src.ingestion.sources import from_pcap
from src.models.incident import RiskTier, TIER_RANK

CONTAINING = {RiskTier.CRITICAL, RiskTier.HIGH}


def _episode_of(t, episodes, gap=10.0):
    for ep in episodes:
        if ep["start"] <= t <= ep["end"] + gap:
            return ep
    return None


def run_backtest(data_dir: str | Path, alert_tier: str = "MEDIUM") -> dict:
    data_dir = Path(data_dir)
    pcap = data_dir / "arp_dataset.pcap"
    labels = json.loads((data_dir / "labels.json").read_text())["episodes"]
    baseline = TrustedBaseline.load(data_dir / "baseline.json")

    engine = DetectionEngine(baseline)
    engine.run(from_pcap(str(pcap)))

    alert_rank = TIER_RANK[RiskTier(alert_tier)]
    per_ep = {ep["id"]: [] for ep in episodes_ids(labels)}
    for inc in engine.incidents:
        ep = _episode_of(inc.first_time, labels)
        if ep is None:
            continue
        per_ep.setdefault(ep["id"], []).append(inc)

    attacks = [e for e in labels if e["label"] == "attack"]
    benign = [e for e in labels if e["label"] == "benign"]

    tp = fn = fp = 0
    latencies, contained, rows = [], 0, []
    for ep in labels:
        incs = per_ep.get(ep["id"], [])
        alerts = [i for i in incs if TIER_RANK[i.risk_tier] >= alert_rank]
        top = max((i.risk_tier for i in incs), key=lambda t: TIER_RANK[t], default=None)
        top_s = top.value if top else "-"
        detected = bool(alerts)
        if ep["label"] == "attack":
            if detected:
                tp += 1
                at = [t for t in (i.alert_time(RiskTier(alert_tier)) for i in alerts) if t is not None]
                first = min(at) if at else min(i.first_time for i in alerts)
                latencies.append(max(0.0, first - ep["start"]))
                if any(i.risk_tier in CONTAINING for i in alerts):
                    contained += 1
                verdict = "TP"
            else:
                fn += 1; verdict = "FN"
        else:
            if detected:
                fp += 1; verdict = "FP"
            else:
                verdict = "TN"
        rows.append({"id": ep["id"], "type": ep["type"], "label": ep["label"],
                     "top_tier": top_s, "verdict": verdict})

    tn = len(benign) - fp
    return {
        "alert_tier": alert_tier,
        "episodes": {"attack": len(attacks), "benign": len(benign)},
        "confusion": {"TP": tp, "FN": fn, "FP": fp, "TN": tn},
        "detection_rate": round(tp / len(attacks), 4) if attacks else 0.0,
        "false_positive_rate": round(fp / len(benign), 4) if benign else 0.0,
        "latency_ms": {
            "mean": round(sum(latencies) / len(latencies) * 1000, 1) if latencies else 0.0,
            "max": round(max(latencies) * 1000, 1) if latencies else 0.0,
        },
        "mitigation_effect": round(contained / tp, 4) if tp else 0.0,
        "per_episode": rows,
        "incidents": [i.to_dict() for i in engine.incidents],
    }


def episodes_ids(labels):
    return labels
