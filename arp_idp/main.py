"""arpguard - CLI entrypoint for the ARP Intrusion Detection & Prevention system.

    python main.py gen-data                               # build labelled fixtures
    python main.py scenarios                              # list benign/attack episodes
    python main.py analyze test_data/arp_dataset.pcap     # detect over a capture
    python main.py analyze <pcap> --detail --min-tier HIGH
    python main.py respond  <pcap> --apply                # detect + host-safe prevention
    python main.py backtest --data test_data              # metrics vs ground truth
    python main.py watch -i "Ethernet" --prevent          # live IDP (needs Npcap/admin)
    python main.py weights                                # show the scoring config
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from config.settings import get_settings, load_weights
from src.detection.baseline import TrustedBaseline
from src.detection.engine import DetectionEngine
from src.ingestion.sources import from_pcap, live
from src.models.incident import Incident, RiskTier, TIER_RANK
from src.prevention.responder import Responder
from src.utils.formatting import (render_actions, render_incident,
                                  render_incident_list, render_metrics)
from src.utils.logger import configure_logging, silence_scapy, utf8_stdout

# Suppress Scapy's libpcap import warning for clean CLI output (set before any
# Scapy import, which happens lazily inside the commands).
silence_scapy()

app = typer.Typer(
    name="arpguard",
    help="Context-aware ARP Intrusion Detection & Prevention for enterprise LANs.",
    no_args_is_help=True,
    add_completion=False,
)
out = Console()
err = Console(stderr=True)


class Tier(StrEnum):
    INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"


def _baseline(path: Optional[Path]) -> TrustedBaseline:
    p = path or get_settings().default_baseline
    if not Path(p).exists():
        err.print(f"[red]Baseline not found:[/] {p}\nRun [bold]python main.py gen-data[/] first.")
        raise typer.Exit(2)
    return TrustedBaseline.load(p)


class Variant(StrEnum):
    SINGLE = "single"
    MULTIVLAN = "multivlan"


@app.command("gen-data")
def gen_data(
    out_dir: Annotated[Path, typer.Option("--out", "-o")] = get_settings().data_dir,
    variant: Annotated[Variant, typer.Option("--variant", help="single VLAN or multi-VLAN (10/20/30).")] = Variant.SINGLE,
):
    """Generate the labelled synthetic dataset (pcap + labels + baseline)."""
    from src.data.scenarios import generate
    info = generate(out_dir, variant.value)
    out.print(f"[green]Wrote[/] {info['packets']} packets across {info['episodes']} episodes "
              f"({info['attacks']} attack / {info['benign']} benign, variant=[bold]{info['variant']}[/]) "
              f"to [bold]{info['dir']}[/]")


@app.command("scenarios")
def scenarios():
    """List the benign and attack scenarios in the dataset (like list-fixtures)."""
    from src.data.scenarios import scenario_list
    t = Table(title="Scenarios", expand=False)
    t.add_column("id", justify="right", width=3)
    t.add_column("episode"); t.add_column("label", width=8); t.add_column("packets", justify="right")
    for s in scenario_list():
        style = "red" if s["label"] == "attack" else "green"
        t.add_row(str(s["id"]), s["type"], f"[{style}]{s['label']}[/]", str(s["packets"]))
    out.print(t)


@app.command("analyze")
def analyze(
    pcap: Annotated[Path, typer.Argument(help="Capture file to analyse.")],
    baseline: Annotated[Optional[Path], typer.Option("--baseline", "-b")] = None,
    min_tier: Annotated[Tier, typer.Option("--min-tier")] = Tier.LOW,
    detail: Annotated[bool, typer.Option("--detail", help="Full per-incident panels.")] = False,
    json_out: Annotated[Optional[Path], typer.Option("--json", "-o", help="Write incidents JSON.")] = None,
    fail_on: Annotated[Optional[Tier], typer.Option("--fail-on", help="Exit 1 if any incident >= tier (CI gate).")] = None,
):
    """Detect ARP threats in a capture and render scored incidents."""
    utf8_stdout()
    engine = DetectionEngine(_baseline(baseline))
    engine.run(from_pcap(str(pcap)))
    mt = RiskTier(min_tier.value)
    if detail:
        shown = [i for i in engine.incidents if TIER_RANK[i.risk_tier] >= TIER_RANK[mt]]
        shown.sort(key=lambda i: (-TIER_RANK[i.risk_tier], i.first_time))
        for inc in shown:
            render_incident(inc, out)
    else:
        render_incident_list(engine.incidents, out, mt)
    out.print(f"\n[dim]Summary:[/] {engine.summary()}")
    if json_out:
        json_out.write_text(json.dumps([i.to_dict() for i in engine.incidents], indent=2))
        out.print(f"[green]Wrote[/] {json_out}")
    if fail_on:
        rank = TIER_RANK[RiskTier(fail_on.value)]
        if any(TIER_RANK[i.risk_tier] >= rank for i in engine.incidents):
            err.print(f"[bold red]FAIL[/]: incident at or above {fail_on.value}")
            raise typer.Exit(1)


@app.command("respond")
def respond(
    pcap: Annotated[Path, typer.Argument(help="Capture file to analyse + respond to.")],
    baseline: Annotated[Optional[Path], typer.Option("--baseline", "-b")] = None,
    apply: Annotated[bool, typer.Option("--apply", help="Actually run host-safe prevention (needs admin).")] = False,
    iface: Annotated[Optional[str], typer.Option("--iface", "-i")] = None,
    min_tier: Annotated[Tier, typer.Option("--min-tier")] = Tier.MEDIUM,
):
    """Detect, then take proportionate DEFENSIVE prevention actions (IDP mode)."""
    utf8_stdout()
    bl = _baseline(baseline)
    cfg = load_weights()
    engine = DetectionEngine(bl)
    engine.run(from_pcap(str(pcap)))
    responder = Responder(bl, cfg["response_policy"], apply=apply, iface=iface)
    mt = RiskTier(min_tier.value)
    acted = 0
    for inc in sorted(engine.incidents, key=lambda i: (-TIER_RANK[i.risk_tier], i.first_time)):
        if TIER_RANK[inc.risk_tier] < TIER_RANK[mt]:
            continue
        actions = responder.respond(inc)
        if actions:
            acted += 1
            render_incident(inc, out)
            render_actions(actions, out)
            out.print("")
    mode = "[green]APPLY[/]" if apply else "[yellow]DRY-RUN[/]"
    out.print(f"{mode}  responded to {acted} incident(s); "
              f"{len(responder.log)} action(s) total.")
    if apply:
        out.print("[dim]Undo static pins later with the unpin command for each anchor IP.[/]")


@app.command("backtest")
def backtest(
    data: Annotated[Path, typer.Option("--data", "-d")] = get_settings().data_dir,
    alert_tier: Annotated[Tier, typer.Option("--alert-tier")] = Tier.MEDIUM,
    json_out: Annotated[Optional[Path], typer.Option("--json", "-o")] = None,
):
    """Measure detection rate, false positives, latency and mitigation vs labels."""
    utf8_stdout()
    from src.evaluation.backtest import run_backtest
    if not (Path(data) / "arp_dataset.pcap").exists():
        err.print(f"[red]No dataset in[/] {data}. Run [bold]python main.py gen-data[/] first.")
        raise typer.Exit(2)
    m = run_backtest(data, alert_tier.value)
    render_metrics(m, out)
    reports = get_settings().reports_dir
    reports.mkdir(exist_ok=True)
    (reports / "metrics.json").write_text(json.dumps(
        {k: v for k, v in m.items() if k != "incidents"}, indent=2))
    (reports / "incidents.json").write_text(json.dumps(m["incidents"], indent=2))
    out.print(f"[green]Wrote[/] {reports}/metrics.json and incidents.json")
    if json_out:
        json_out.write_text(json.dumps(m, indent=2))


@app.command("watch")
def watch(
    iface: Annotated[Optional[str], typer.Option("--iface", "-i")] = None,
    baseline: Annotated[Optional[Path], typer.Option("--baseline", "-b")] = None,
    prevent: Annotated[bool, typer.Option("--prevent", help="Enable the prevention tier.")] = False,
    apply: Annotated[bool, typer.Option("--apply", help="Run host-safe prevention (needs admin).")] = False,
    min_tier: Annotated[Tier, typer.Option("--min-tier")] = Tier.MEDIUM,
):
    """Live IDP: sniff, detect, score and (optionally) prevent in real time."""
    utf8_stdout()
    bl = _baseline(baseline)
    cfg = load_weights()
    engine = DetectionEngine(bl)
    responder = Responder(bl, cfg["response_policy"], apply=apply, iface=iface) if prevent else None
    mt = RiskTier(min_tier.value)
    seen = {"n": 0}

    def on_packet(ev):
        inc = engine.process(ev)
        if inc is None:
            return
        # emit when an incident first reaches the alert tier
        if TIER_RANK[inc.risk_tier] >= TIER_RANK[mt] and inc.risk_score not in (seen,):
            if inc.alert_time(mt) == ev.time and inc.escalations[-1][0] == ev.time:
                render_incident(inc, out)
                if responder:
                    render_actions(responder.respond(inc), out)
                out.print("")

    out.print(f"[cyan]Live IDP on {iface or 'default iface'}[/] "
              f"(prevent={'on' if prevent else 'off'}, apply={'on' if apply else 'off'}) "
              f"— Ctrl-C to stop\n")
    try:
        live(iface, on_packet)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        err.print("[red]Permission denied.[/] Run as Administrator/root (Npcap on Windows).")
        raise typer.Exit(2)
    out.print(f"\n[dim]Stopped.[/] {engine.summary()}")


@app.command("audit")
def audit(baseline: Annotated[Optional[Path], typer.Option("--baseline", "-b")] = None):
    """Audit this host's live OS ARP table against the trusted baseline."""
    utf8_stdout()
    import platform, re, subprocess
    bl = _baseline(baseline)
    sysname = platform.system()
    cmd = ["arp", "-a"] if sysname in ("Windows", "Darwin") else ["ip", "neigh"]
    try:
        text = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except Exception as e:
        err.print(f"[red]Could not read ARP table:[/] {e}")
        raise typer.Exit(2)
    ipre = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    macre = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
    t = Table(title=f"Local ARP table ({sysname})", expand=True)
    t.add_column("IP"); t.add_column("MAC"); t.add_column("Baseline check")
    flagged = 0
    for line in text.splitlines():
        ip = ipre.search(line); mac = macre.search(line)
        if not ip or not mac:
            continue
        ipv = ip.group(0); macv = mac.group(0).replace("-", ":").lower()
        exp = bl.expected_mac(ipv)
        if exp and exp != macv:
            note = Text(f"MISMATCH — expected {exp}", style="bold red"); flagged += 1
        elif bl.is_anchor(ipv):
            note = Text("anchor OK", style="green")
        else:
            note = Text("—", style="dim")
        t.add_row(ipv, macv, note)
    out.print(t)
    out.print(f"[{'red' if flagged else 'green'}]{flagged} anchor mismatch(es).[/]")
    if flagged:
        raise typer.Exit(1)


@app.command("weights")
def weights():
    """Show the scoring configuration: signal weights, tiers and context factors."""
    utf8_stdout()
    cfg = load_weights()
    t = Table(title="Detection signals", expand=False)
    t.add_column("signal", style="bold"); t.add_column("severity"); t.add_column("base pts", justify="right")
    t.add_column("unlowerable")
    for name, spec in cfg["signals"].items():
        t.add_row(name, spec["severity"], str(cfg["base_weight"][spec["severity"]]),
                  "yes" if spec.get("unlowerable") else "")
    out.print(t)
    ct = Table(title="Context factors", expand=False)
    ct.add_column("factor", style="bold"); ct.add_column("multiplier", justify="right")
    for k, v in cfg["context_factors"].items():
        ct.add_row(k, f"×{v}")
    out.print(ct)
    pt = Table(title="Response policy (min tier per action)", expand=False)
    pt.add_column("action", style="bold"); pt.add_column("from tier")
    for k, v in cfg["response_policy"].items():
        pt.add_row(k.replace("_from", ""), v)
    out.print(pt)


if __name__ == "__main__":
    app()
