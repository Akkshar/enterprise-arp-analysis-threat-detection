#!/usr/bin/env python3
"""
evaluate.py - Measure the detector against labelled ground truth.

Part of "Enterprise ARP Threat Detection".
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

Runs the detector over a labelled capture and computes the four success
metrics from the proposal:
  * Detection rate   - share of attack episodes that raised an alert
  * False-positive   - share of benign episodes that raised an alert
  * Detection latency- time from episode start to first alert (attacks)
  * Mitigation effect- share of detected attacks whose recommended action
                       is a containing one (quarantine / DAI drop)

An "alert" is an incident at or above --alert-tier (default MEDIUM); INFO/LOW
incidents are logged but not counted as alerts (matches the alerting policy).

Outputs metrics.json + incidents.json and prints a confusion-matrix-style
report. Exit code is non-zero if any attack was missed.

Usage:
    python evaluate.py --data test_data --out reports
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from detection_engine import Detector, TrustedBaseline, TIER_RANK, MITIGATION
from detect import events_from_pcap

CONTAINING = {"CRITICAL", "HIGH"}  # tiers whose mitigation actually contains


def episode_of(t, episodes, gap=10.0):
    for ep in episodes:
        if ep["start"] <= t <= ep["end"] + gap:
            return ep
    return None


def main():
    ap = argparse.ArgumentParser(description="Evaluate ARP detector vs labels.")
    ap.add_argument("--data", default="test_data",
                    help="Dir with arp_dataset.pcap, labels.json, baseline.json")
    ap.add_argument("--out", default="reports", help="Output directory.")
    ap.add_argument("--alert-tier", default="MEDIUM",
                    choices=list(TIER_RANK), help="Minimum tier counted as an alert.")
    args = ap.parse_args()

    pcap = os.path.join(args.data, "arp_dataset.pcap")
    labels_p = os.path.join(args.data, "labels.json")
    baseline_p = os.path.join(args.data, "baseline.json")
    for p in (pcap, labels_p, baseline_p):
        if not os.path.exists(p):
            sys.exit(f"Missing {p}. Run: python make_captures.py --out {args.data}")

    episodes = json.load(open(labels_p))["episodes"]
    detector = Detector(TrustedBaseline.load(baseline_p))
    detector.run(events_from_pcap(pcap))

    alert_rank = TIER_RANK[args.alert_tier]
    # Attach alert incidents to episodes.
    per_ep = {ep["id"]: {"alerts": [], "all": []} for ep in episodes}
    unassigned = []
    for inc in detector.incidents:
        ep = episode_of(inc.first_time, episodes)
        if ep is None:
            unassigned.append(inc)
            continue
        per_ep[ep["id"]]["all"].append(inc)
        if TIER_RANK[inc.tier] >= alert_rank:
            per_ep[ep["id"]]["alerts"].append(inc)

    attacks = [e for e in episodes if e["label"] == "attack"]
    benign = [e for e in episodes if e["label"] == "benign"]

    tp = fn = 0
    latencies = []
    contained = 0
    rows = []
    for ep in episodes:
        alerts = per_ep[ep["id"]]["alerts"]
        detected = bool(alerts)
        top = max((a.tier for a in per_ep[ep["id"]]["all"]),
                  key=lambda t: TIER_RANK[t], default="-")
        if ep["label"] == "attack":
            if detected:
                tp += 1
                # latency = when an alert-tier was first reached, minus episode start
                alert_times = [t for t in (a.alert_time(args.alert_tier) for a in alerts)
                               if t is not None]
                first = min(alert_times) if alert_times else min(a.first_time for a in alerts)
                latencies.append(max(0.0, first - ep["start"]))
                if any(a.tier in CONTAINING for a in alerts):
                    contained += 1
            else:
                fn += 1
        verdict = ("TP" if (ep["label"] == "attack" and detected) else
                   "FN" if ep["label"] == "attack" else
                   "FP" if detected else "TN")
        rows.append((ep["id"], ep["type"], ep["label"], top, detected, verdict))

    fp = sum(1 for e in benign if per_ep[e["id"]]["alerts"])
    tn = len(benign) - fp

    det_rate = tp / len(attacks) if attacks else 0.0
    fp_rate = fp / len(benign) if benign else 0.0
    mean_lat = sum(latencies) / len(latencies) if latencies else 0.0
    max_lat = max(latencies) if latencies else 0.0
    mitig = contained / tp if tp else 0.0

    # ---- report ----
    print("=" * 72)
    print("ARP THREAT DETECTION - EVALUATION")
    print(f"alert tier >= {args.alert_tier}   |   "
          f"{len(attacks)} attack / {len(benign)} benign episodes")
    print("=" * 72)
    print(f"{'id':>2}  {'episode':<24}{'truth':<9}{'top tier':<10}{'verdict'}")
    print("-" * 72)
    for eid, typ, lab, top, det, verd in rows:
        print(f"{eid:>2}  {typ:<24}{lab:<9}{top:<10}{verd}")
    print("-" * 72)
    print(f"Confusion matrix:  TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    print()
    print("METRICS")
    print(f"  Detection rate      : {det_rate*100:5.1f} %  ({tp}/{len(attacks)} attacks)")
    print(f"  False-positive rate : {fp_rate*100:5.1f} %  ({fp}/{len(benign)} benign)")
    print(f"  Detection latency   : mean {mean_lat*1000:6.1f} ms, max {max_lat*1000:6.1f} ms")
    print(f"  Mitigation effect   : {mitig*100:5.1f} %  ({contained}/{tp} detected attacks"
          f" get a containing action)")
    if unassigned:
        print(f"  (note: {len(unassigned)} incident(s) fell outside any labelled episode)")
    print("=" * 72)

    os.makedirs(args.out, exist_ok=True)
    metrics = {
        "alert_tier": args.alert_tier,
        "episodes": {"attack": len(attacks), "benign": len(benign)},
        "confusion": {"TP": tp, "FN": fn, "FP": fp, "TN": tn},
        "detection_rate": round(det_rate, 4),
        "false_positive_rate": round(fp_rate, 4),
        "latency_ms": {"mean": round(mean_lat * 1000, 1), "max": round(max_lat * 1000, 1)},
        "mitigation_effect": round(mitig, 4),
        "per_episode": [
            {"id": eid, "type": typ, "label": lab, "top_tier": top,
             "detected": det, "verdict": verd}
            for eid, typ, lab, top, det, verd in rows
        ],
    }
    with open(os.path.join(args.out, "metrics.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)
    with open(os.path.join(args.out, "incidents.json"), "w") as fh:
        json.dump([i.to_dict() for i in detector.incidents], fh, indent=2)
    print(f"Wrote {args.out}/metrics.json and {args.out}/incidents.json")

    sys.exit(1 if fn else 0)


if __name__ == "__main__":
    main()
