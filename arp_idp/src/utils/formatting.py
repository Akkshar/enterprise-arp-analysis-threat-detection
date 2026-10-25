"""Rich terminal rendering for incidents, responses and backtest metrics.

Deliberately styled like rugscan's render_report: a Panel header per incident,
a flags table, and compact metric tables.
"""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.models.incident import Incident, RiskTier, Severity

TIER_STYLE = {
    RiskTier.INFO: "dim",
    RiskTier.LOW: "bold cyan",
    RiskTier.MEDIUM: "bold yellow",
    RiskTier.HIGH: "bold dark_orange",
    RiskTier.CRITICAL: "bold white on red",
}
SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "dark_orange",
    Severity.CRITICAL: "bold red",
}


def _incident_panel(inc: Incident) -> Panel:
    title = Text.assemble(
        (f"{inc.risk_tier.value}  ", TIER_STYLE[inc.risk_tier]),
        (f"{inc.risk_score:.1f} pts", "bold"),
    )
    body = Table.grid(padding=(0, 2))
    body.add_row("Time", inc.first_iso)
    body.add_row("Claimed IP", inc.claimed_ip)
    body.add_row("Offending MAC", inc.offending_mac)
    body.add_row("Baseline MAC", inc.baseline_mac or "—")
    if inc.port:
        body.add_row("Switch port", inc.port)
    body.add_row("Action", Text(inc.recommended_action, style="bold"))
    border = TIER_STYLE[inc.risk_tier].split(" on ")[-1] if "on" in TIER_STYLE[inc.risk_tier] \
        else TIER_STYLE[inc.risk_tier].replace("bold ", "")
    return Panel(body, title=title, border_style=border)


def _flags_table(inc: Incident) -> Table:
    t = Table(title="Detection flags", expand=True)
    t.add_column("Severity", width=9)
    t.add_column("Signal", style="bold")
    t.add_column("Points", justify="right", width=7)
    t.add_column("Detail", ratio=1)
    for fl in sorted(inc.flags, key=lambda f: -f.points):
        t.add_row(Text(fl.severity.value, style=SEVERITY_STYLE[fl.severity]),
                  fl.code, f"+{fl.points:g}", fl.detail)
    if not inc.flags:
        t.add_row("", "—", "", "No flags raised.")
    return t


def render_incident(inc: Incident, console: Console | None = None) -> None:
    console = console or Console()
    console.print(Group(_incident_panel(inc), _flags_table(inc)))


def render_incident_list(incidents: list[Incident], console: Console | None = None,
                         min_tier: RiskTier = RiskTier.LOW) -> None:
    from src.models.incident import TIER_RANK
    console = console or Console()
    shown = [i for i in incidents if TIER_RANK[i.risk_tier] >= TIER_RANK[min_tier]]
    shown.sort(key=lambda i: (-TIER_RANK[i.risk_tier], i.first_time))
    t = Table(title=f"Incidents (tier ≥ {min_tier.value})", expand=True)
    t.add_column("Time", width=9)
    t.add_column("Risk", width=10)
    t.add_column("Claimed IP")
    t.add_column("Offending MAC")
    t.add_column("Top signal")
    t.add_column("Pts", justify="right", width=6)
    for i in shown:
        tf = i.top_flag()
        t.add_row(i.first_iso.split("T")[-1],
                  Text(i.risk_tier.value, style=TIER_STYLE[i.risk_tier]),
                  i.claimed_ip, i.offending_mac, tf.code if tf else "—", f"{i.risk_score:g}")
    console.print(t)


def render_actions(actions, console: Console | None = None) -> None:
    console = console or Console()
    if not actions:
        return
    t = Table(title="Prevention actions", expand=True)
    t.add_column("Action", style="bold", width=12)
    t.add_column("Target", width=15)
    t.add_column("Status", width=10)
    t.add_column("Detail / command", ratio=1)
    for a in actions:
        status = ("[green]APPLIED[/]" if a.applied else
                  "[yellow]DRY-RUN[/]" if a.dry_run else "[cyan]EMITTED[/]")
        t.add_row(a.kind, a.target_ip, status, a.command or a.detail)
    console.print(t)


def render_metrics(m: dict, console: Console | None = None) -> None:
    console = console or Console()
    c = m["confusion"]
    head = Table.grid(padding=(0, 3))
    head.add_row(Text("Detection", style="bold"), f'{m["detection_rate"]*100:.1f}%')
    head.add_row(Text("False-positive", style="bold"), f'{m["false_positive_rate"]*100:.1f}%')
    head.add_row(Text("Latency mean/max", style="bold"),
                 f'{m["latency_ms"]["mean"]:.0f} / {m["latency_ms"]["max"]:.0f} ms')
    head.add_row(Text("Mitigation", style="bold"), f'{m["mitigation_effect"]*100:.1f}%')
    console.print(Panel(head, title="Backtest metrics", border_style="cyan"))

    t = Table(title=f'Per-episode  (alert tier ≥ {m["alert_tier"]}  ·  '
                    f'TP={c["TP"]} FN={c["FN"]} FP={c["FP"]} TN={c["TN"]})', expand=True)
    t.add_column("id", width=3, justify="right")
    t.add_column("episode")
    t.add_column("truth", width=8)
    t.add_column("top tier", width=10)
    t.add_column("verdict", width=8)
    vstyle = {"TP": "green", "TN": "green", "FP": "red", "FN": "red"}
    for r in m["per_episode"]:
        t.add_row(str(r["id"]), r["type"], r["label"], r["top_tier"],
                  Text(r["verdict"], style=vstyle.get(r["verdict"], "")))
    console.print(t)
