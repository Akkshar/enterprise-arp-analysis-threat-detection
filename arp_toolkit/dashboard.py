#!/usr/bin/env python3
"""
dashboard.py - Render a standalone HTML dashboard from detector output.

Part of "Enterprise ARP Threat Detection".
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

Reads reports/metrics.json + reports/incidents.json (from evaluate.py) and
test_data/labels.json, and writes a single self-contained dashboard.html with
KPI tiles, flagged devices, incident history and the measured metrics. Every
number comes from an actual detector run -- no mock values.

Usage:
    python dashboard.py --reports reports --data test_data --out dashboard.html
"""

from __future__ import annotations

import argparse
import html
import json
import os
from datetime import datetime

# Palette matched to the Review 1 deck (indigo/teal/amber).
TIER_COLOR = {
    "CRITICAL": "#FF5A5F", "HIGH": "#FFB020", "MEDIUM": "#3D8BFD",
    "LOW": "#00A99D", "INFO": "#6B6890",
}


def tier_badge(tier):
    c = TIER_COLOR.get(tier, "#6B6890")
    dark = tier in ("HIGH",)  # amber bg needs dark text
    fg = "#241A5C" if dark else "#fff"
    return (f'<span class="badge" style="background:{c};color:{fg}">'
            f'{html.escape(tier)}</span>')


def main():
    ap = argparse.ArgumentParser(description="Render the ARP detection dashboard.")
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--data", default="test_data")
    ap.add_argument("--out", default="dashboard.html")
    args = ap.parse_args()

    metrics = json.load(open(os.path.join(args.reports, "metrics.json")))
    incidents = json.load(open(os.path.join(args.reports, "incidents.json")))
    labels = json.load(open(os.path.join(args.data, "labels.json")))["episodes"]

    events = sum(e.get("n_packets", 0) for e in labels)
    active = sum(1 for i in incidents if i["tier"] in ("CRITICAL", "HIGH"))
    conf = metrics["confusion"]

    def fmt_pct(x):
        return f"{x*100:.1f}%"

    kpis = [
        (str(events), "ARP packets analysed"),
        (str(active), "Active incidents (Crit/High)"),
        (fmt_pct(metrics["false_positive_rate"]), "False-positive rate"),
        (f'{metrics["latency_ms"]["mean"]:.0f} ms', "Mean detection latency"),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><div class="kpi-num">{html.escape(v)}</div>'
        f'<div class="kpi-lab">{html.escape(l)}</div></div>' for v, l in kpis)

    # Flagged devices (sorted by severity then time)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    flagged = sorted(incidents, key=lambda i: (order[i["tier"]], i["first_time"]))
    rows = ""
    for i in flagged:
        top_signal = max(i["signals"], key=lambda s: s["points"])["name"] if i["signals"] else "-"
        rows += (
            f'<tr><td class="mono">{html.escape(i["offending_mac"])}</td>'
            f'<td class="mono">{html.escape(i["claimed_ip"])}</td>'
            f'<td class="mono">{html.escape(i["baseline_mac"] or "—")}</td>'
            f'<td>{html.escape(top_signal)}</td>'
            f'<td>{i["score"]}</td>'
            f'<td>{tier_badge(i["tier"])}</td></tr>')

    # Incident history (chronological)
    hist = ""
    for i in sorted(incidents, key=lambda x: x["first_time"]):
        t = html.escape(i["first_iso"].split("T")[-1])
        sig = ", ".join(s["name"] for s in i["signals"])
        hist += (
            f'<div class="hist-row"><span class="hist-time mono">{t}</span>'
            f'{tier_badge(i["tier"])}'
            f'<span class="hist-text">{html.escape(i["claimed_ip"])} '
            f'claimed by {html.escape(i["offending_mac"])} '
            f'<span class="muted">({html.escape(sig)})</span></span></div>')

    # Metrics + confusion
    met_rows = (
        f'<tr><td>Detection rate</td><td class="num">{fmt_pct(metrics["detection_rate"])}</td>'
        f'<td>{conf["TP"]}/{conf["TP"]+conf["FN"]} attacks caught</td></tr>'
        f'<tr><td>False-positive rate</td><td class="num">{fmt_pct(metrics["false_positive_rate"])}</td>'
        f'<td>{conf["FP"]}/{conf["FP"]+conf["TN"]} benign flagged</td></tr>'
        f'<tr><td>Mean / max latency</td><td class="num">{metrics["latency_ms"]["mean"]:.0f} / '
        f'{metrics["latency_ms"]["max"]:.0f} ms</td><td>first malicious ARP → alert</td></tr>'
        f'<tr><td>Mitigation effect</td><td class="num">{fmt_pct(metrics["mitigation_effect"])}</td>'
        f'<td>detected attacks given a containing action</td></tr>')

    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARP Threat Detection — Dashboard</title>
<style>
  :root {{
    --bg:#1b1448; --panel:#241A5C; --panel2:#2B2552; --line:#3a3270;
    --fg:#ffffff; --muted:#9a93c0; --accent:#00A99D;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:24px 16px 48px; }}
  header {{ display:flex; justify-content:space-between; align-items:baseline;
    flex-wrap:wrap; gap:8px; border-bottom:1px solid var(--line); padding-bottom:14px; }}
  h1 {{ font-size:20px; margin:0; letter-spacing:.3px; }}
  h1 .accent {{ color:var(--accent); }}
  .sub {{ color:var(--muted); font-size:13px; }}
  h2 {{ font-size:13px; text-transform:uppercase; letter-spacing:1px;
    color:var(--muted); margin:28px 0 12px; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
    gap:14px; margin-top:20px; }}
  .kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
    padding:18px 16px; }}
  .kpi-num {{ font-size:30px; font-weight:700; color:var(--accent); }}
  .kpi-lab {{ color:var(--muted); font-size:13px; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel);
    border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
  th,td {{ text-align:left; padding:10px 14px; font-size:14px;
    border-bottom:1px solid var(--line); }}
  th {{ background:var(--panel2); color:var(--muted); font-weight:600;
    text-transform:uppercase; font-size:11px; letter-spacing:.6px; }}
  tr:last-child td {{ border-bottom:none; }}
  td.num, td.mono {{ font-variant-numeric:tabular-nums; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:13px; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:999px;
    font-size:11px; font-weight:700; letter-spacing:.4px; }}
  .num {{ color:var(--accent); font-weight:600; }}
  .hist-row {{ display:flex; align-items:center; gap:12px; padding:9px 14px;
    background:var(--panel); border:1px solid var(--line); border-top:none; font-size:14px; }}
  .hist-row:first-of-type {{ border-top:1px solid var(--line);
    border-radius:12px 12px 0 0; }}
  .hist-row:last-of-type {{ border-radius:0 0 12px 12px; }}
  .hist-time {{ color:var(--muted); width:84px; flex:none; }}
  .hist-text {{ flex:1; }}
  .muted {{ color:var(--muted); }}
  footer {{ color:var(--muted); font-size:12px; margin-top:28px;
    border-top:1px solid var(--line); padding-top:14px; }}
  .cols {{ display:grid; grid-template-columns:1fr; gap:10px; }}
</style></head>
<body><div class="wrap">
  <header>
    <div>
      <h1>Enterprise <span class="accent">ARP Threat Detection</span></h1>
      <div class="sub">Context-aware anomaly detection &amp; mitigation · Review 2 dashboard</div>
    </div>
    <div class="sub">Generated {generated} · alert tier ≥ {html.escape(metrics["alert_tier"])}</div>
  </header>

  <div class="kpis">{kpi_html}</div>

  <h2>Flagged devices</h2>
  <table>
    <tr><th>Offending MAC</th><th>Claimed IP</th><th>Baseline MAC</th>
        <th>Top signal</th><th>Score</th><th>Risk</th></tr>
    {rows}
  </table>

  <h2>Measured performance</h2>
  <table>
    <tr><th>Metric</th><th>Value</th><th>Basis</th></tr>
    {met_rows}
  </table>
  <div class="sub" style="margin-top:8px">Confusion matrix (alert tier ≥ {html.escape(metrics["alert_tier"])}):
    TP={conf["TP"]} · FN={conf["FN"]} · FP={conf["FP"]} · TN={conf["TN"]}
    over {metrics["episodes"]["attack"]} attack and {metrics["episodes"]["benign"]} benign episodes.</div>

  <h2>Incident history</h2>
  <div class="cols">{hist}</div>

  <footer>
    All figures are measured from a detector run over the labelled synthetic
    dataset (<span class="mono">test_data/arp_dataset.pcap</span>), not mock values.
    The sensor detects, scores and recommends; enforcement (DAI / port quarantine)
    remains with the switch.
  </footer>
</div></body></html>"""

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"Wrote {args.out}  ({len(incidents)} incidents, {events} packets)")


if __name__ == "__main__":
    main()
