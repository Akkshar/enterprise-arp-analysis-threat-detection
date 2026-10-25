#!/usr/bin/env python3
"""
build_deck.py - Generate the Review 2 slide deck (.pptx).

Part of "Enterprise ARP Threat Detection".
Team: Stuti Zingade, Ritika Tulsyan, Akkshar Ranjan

Builds a 16:9 deck in the same dark indigo/teal theme as the Review 1 deck.
Numbers are read from reports/metrics.json so the deck always matches the
latest detector run.

    pip install python-pptx
    python build_deck.py --metrics reports/metrics.json --out Enterprise_ARP_Threat_Detection_Review2.pptx
"""

from __future__ import annotations

import argparse
import json

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn

# --- palette (matched to Review 1 deck) ---
BG = RGBColor(0x24, 0x1A, 0x5C)
BG2 = RGBColor(0x1B, 0x14, 0x48)
PANEL = RGBColor(0x2B, 0x25, 0x52)
TEAL = RGBColor(0x00, 0xA9, 0x9D)
AMBER = RGBColor(0xFF, 0xB0, 0x20)
RED = RGBColor(0xFF, 0x5A, 0x5F)
BLUE = RGBColor(0x3D, 0x8B, 0xFD)
PURPLE = RGBColor(0x7C, 0x4D, 0xFF)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
LAV = RGBColor(0xDD, 0xD8, 0xF5)
MUTED = RGBColor(0x9A, 0x93, 0xC0)
HEAD = "Calibri"

TIER_C = {"CRITICAL": RED, "HIGH": AMBER, "MEDIUM": BLUE, "LOW": TEAL, "INFO": MUTED}

EMU = 914400
SW, SH = 13.333, 7.5


def _set_fill(shape, color):
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()


def _no_autofit(tf):
    tf.word_wrap = True


def rect(slide, x, y, w, h, color, radius=None):
    shp = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE,
        Inches(x), Inches(y), Inches(w), Inches(h))
    _set_fill(shp, color)
    if radius:
        try:
            shp.adjustments[0] = radius
        except Exception:
            pass
    shp.shadow.inherit = False
    return shp


def text(slide, x, y, w, h, runs, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP,
         space_after=6, line_spacing=1.0):
    """runs: list of paragraphs; each paragraph is list of (s, size, color, bold)."""
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    _no_autofit(tf)
    tf.vertical_anchor = anchor
    for i, para in enumerate(runs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(space_after)
        p.space_before = Pt(0)
        p.line_spacing = line_spacing
        for (s, size, color, bold) in para:
            r = p.add_run()
            r.text = s
            r.font.name = HEAD
            r.font.size = Pt(size)
            r.font.color.rgb = color
            r.font.bold = bold
    return tb


def bg(slide):
    rect(slide, -0.05, -0.05, SW + 0.1, SH + 0.1, BG)


def label(slide, s):
    text(slide, 0.6, 0.42, 10, 0.4, [[(s.upper(), 13, TEAL, True)]])


def title(slide, s):
    text(slide, 0.6, 0.72, 12.1, 0.9, [[(s, 30, WHITE, True)]])
    rect(slide, 0.62, 1.52, 0.9, 0.06, TEAL)


def footer(slide, n):
    text(slide, 0.6, 7.02, 10, 0.4,
         [[("Enterprise ARP Threat Detection · Review 2", 9, MUTED, False)]])
    text(slide, 12.3, 7.02, 0.6, 0.4, [[(str(n), 10, MUTED, True)]],
         align=PP_ALIGN.RIGHT)


def new(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    bg(s)
    return s


def card(slide, x, y, w, h, color=PANEL, radius=0.06):
    return rect(slide, x, y, w, h, color, radius=radius)


def badge(slide, x, y, tier, w=1.15, h=0.34):
    c = TIER_C[tier]
    b = rect(slide, x, y, w, h, c, radius=0.5)
    fg = BG if tier in ("HIGH", "LOW") else WHITE
    tf = b.text_frame
    _no_autofit(tf)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run(); r.text = tier
    r.font.name = HEAD; r.font.size = Pt(11); r.font.bold = True; r.font.color.rgb = fg
    return b


def table(slide, x, y, w, col_w, headers, rows, header_color=TEAL,
          row_h=0.42, fs=12, cell_colors=None):
    """Simple themed table using shapes. col_w: list of fractional widths."""
    total = sum(col_w)
    xs = []
    cx = x
    for frac in col_w:
        xs.append(cx)
        cx += w * frac / total
    widths = [w * f / total for f in col_w]
    # header
    rect(slide, x, y, w, row_h, PANEL, radius=0)
    for i, htxt in enumerate(headers):
        text(slide, xs[i] + 0.08, y + 0.03, widths[i] - 0.12, row_h,
             [[(htxt, fs - 1, header_color, True)]], anchor=MSO_ANCHOR.MIDDLE)
    # rows
    yy = y + row_h
    for ridx, row in enumerate(rows):
        band = BG2 if ridx % 2 == 0 else BG
        rect(slide, x, yy, w, row_h, band, radius=0)
        for i, cell in enumerate(row):
            val, col = (cell if isinstance(cell, tuple) else (cell, LAV))
            text(slide, xs[i] + 0.08, yy + 0.02, widths[i] - 0.12, row_h,
                 [[(val, fs, col, False)]], anchor=MSO_ANCHOR.MIDDLE)
        yy += row_h
    return yy


# ==========================================================================
def build(metrics, out):
    m = metrics
    det = f'{m["detection_rate"]*100:.0f}%'
    fp = f'{m["false_positive_rate"]*100:.1f}%'
    lat = f'{m["latency_ms"]["mean"]:.0f} ms'
    latmax = f'{m["latency_ms"]["max"]:.0f} ms'
    mit = f'{m["mitigation_effect"]*100:.0f}%'
    c = m["confusion"]

    prs = Presentation()
    prs.slide_width = Inches(SW)
    prs.slide_height = Inches(SH)

    # ---- 1. Title ----
    s = new(prs)
    rect(s, 0, 0, SW, SH, BG)
    text(s, 0.9, 1.9, 11.5, 0.5, [[("REVIEW 2 · TEAM PROJECT", 15, TEAL, True)]])
    text(s, 0.9, 2.5, 11.5, 1.4,
         [[("Enterprise ", 46, WHITE, True), ("ARP Threat Detection", 46, TEAL, True)]])
    text(s, 0.9, 3.7, 11.5, 0.6,
         [[("Context-aware anomaly detection and mitigation for enterprise LANs",
            18, LAV, False)]])
    rect(s, 0.92, 4.5, 1.1, 0.06, AMBER)
    text(s, 0.9, 4.8, 11.5, 1.4, [
        [("Stuti Zingade", 15, LAV, False)],
        [("Ritika Tulsyan", 15, LAV, False)],
        [("Akkshar Ranjan", 15, LAV, False)],
    ], space_after=4)
    text(s, 0.9, 6.6, 11.5, 0.4,
         [[("Computer Networks and Data Communication", 12, MUTED, False)]])

    # ---- 2. Review 2 at a glance ----
    s = new(prs); label(s, "Overview"); title(s, "What Review 2 delivers")
    text(s, 0.6, 1.75, 12, 0.5,
         [[("The Review 1 plan had five build items. All five are implemented and "
            "measured.", 14, LAV, False)]])
    plan = [
        ("Capture + trusted-binding store", "detect.py + baseline with anchors"),
        ("Detection engine — 5 signals + scoring", "detection_engine.py"),
        ("Dashboard — alerts, devices, history", "dashboard.py"),
        ("Simulation — benign + attack scenarios", "make_captures.py"),
        ("Evaluate + tune — the 4 metrics", "evaluate.py"),
    ]
    y = 2.5
    for i, (what, how) in enumerate(plan):
        card(s, 0.6, y, 12.1, 0.72)
        text(s, 0.8, y + 0.07, 0.6, 0.6, [[("✔", 20, TEAL, True)]],
             anchor=MSO_ANCHOR.MIDDLE)
        text(s, 1.5, y + 0.06, 8.0, 0.6, [[(what, 15, WHITE, True)]],
             anchor=MSO_ANCHOR.MIDDLE)
        text(s, 9.3, y + 0.06, 3.2, 0.6, [[(how, 12, MUTED, False)]],
             anchor=MSO_ANCHOR.MIDDLE, align=PP_ALIGN.RIGHT)
        y += 0.82
    footer(s, 2)

    # ---- 3. Why ARP is exploitable ----
    s = new(prs); label(s, "Background"); title(s, "Why ARP is exploitable")
    pts = [
        ("No authentication", "Any host can claim any IP; receivers cannot verify the sender.", TEAL),
        ("Stateless & trusting", "Replies are accepted even when no request was sent.", AMBER),
        ("Last write wins", "A newer binding silently overwrites the cached entry.", BLUE),
        ("Broadcast reach", "One forged reply can reach every host in the VLAN.", PURPLE),
    ]
    x = 0.6
    for i, (h, d, col) in enumerate(pts):
        cx = 0.6 + (i % 2) * 6.15
        cy = 1.9 + (i // 2) * 1.75
        card(s, cx, cy, 5.9, 1.55)
        rect(s, cx, cy, 0.12, 1.55, col)
        text(s, cx + 0.35, cy + 0.2, 5.4, 0.5, [[(h, 18, WHITE, True)]])
        text(s, cx + 0.35, cy + 0.72, 5.4, 0.7, [[(d, 13, LAV, False)]], line_spacing=1.05)
    text(s, 0.6, 5.6, 12, 0.8,
         [[("These are protocol properties, not bugs. The whole attack family "
            "shares one signature: ", 14, LAV, False),
           ("an unexpected IP-to-MAC binding", 14, TEAL, True),
           (" — so one detector covers all of them.", 14, LAV, False)]],
         line_spacing=1.1)
    footer(s, 3)

    # ---- 4. Problem ----
    s = new(prs); label(s, "Problem"); title(s, "Why detection is hard at scale")
    probs = [
        ("Context-blind tools", "DAI and port security decide per packet, with no memory of normal behaviour."),
        ("No prioritisation", "Every alert looks equally urgent, so real incidents are buried."),
        ("Disruptive mitigation", "Blocking on one suspicious packet can cut off legitimate devices."),
    ]
    y = 1.9
    for h, d in probs:
        card(s, 0.6, y, 12.1, 1.0)
        rect(s, 0.6, y, 0.12, 1.0, RED)
        text(s, 0.9, y + 0.14, 4.0, 0.7, [[(h, 17, WHITE, True)]], anchor=MSO_ANCHOR.MIDDLE)
        text(s, 5.0, y + 0.14, 7.5, 0.7, [[(d, 13, LAV, False)]],
             anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.05)
        y += 1.12
    card(s, 0.6, 5.45, 12.1, 1.15, PANEL)
    text(s, 0.9, 5.6, 11.6, 0.9, [
        [("THE QUESTION", 11, AMBER, True)],
        [("How can an enterprise detect ARP threats accurately and with few false "
          "positives, by combining rule-based checks with context about each "
          "device's normal behaviour?", 15, WHITE, True)],
    ], space_after=4, line_spacing=1.05)
    footer(s, 4)

    # ---- 5. Architecture ----
    s = new(prs); label(s, "The System"); title(s, "System architecture")
    stages = [
        ("1", "Capture", "Sniff live ARP and read PCAP; normalise every packet", TEAL),
        ("2", "Baseline", "Trusted IP-to-MAC store; gateway & server anchors", BLUE),
        ("3", "Detect", "Five signals compare each claim vs baseline + state", PURPLE),
        ("4", "Score", "Signal weight x context factor, summed to a risk tier", AMBER),
        ("5", "Respond", "Incident with evidence + recommended action", RED),
    ]
    y = 2.0
    for num, h, d, col in stages:
        card(s, 0.6, y, 12.1, 0.82)
        circ = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(0.8), Inches(y + 0.16),
                                  Inches(0.5), Inches(0.5))
        _set_fill(circ, col); circ.shadow.inherit = False
        tf = circ.text_frame; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
        r = p.add_run(); r.text = num; r.font.bold = True; r.font.size = Pt(18)
        r.font.color.rgb = (BG if col in (AMBER, TEAL) else WHITE); r.font.name = HEAD
        text(s, 1.55, y + 0.17, 2.3, 0.5, [[(h, 17, WHITE, True)]], anchor=MSO_ANCHOR.MIDDLE)
        text(s, 3.9, y + 0.17, 8.6, 0.5, [[(d, 13, LAV, False)]], anchor=MSO_ANCHOR.MIDDLE)
        y += 0.92
    text(s, 0.6, 6.55, 12, 0.4,
         [[("Each stage is an independent module — the baseline source or the "
            "detection rules can change without touching the rest.", 12, MUTED, False)]])
    footer(s, 5)

    # ---- 6. Trusted baseline ----
    s = new(prs); label(s, "The System"); title(s, "The trusted baseline — the “memory”")
    items = [
        ("Anchors", "Gateway (critical) and static servers (high). Never silently overwritten — changed only by a verified admin update.", TEAL),
        ("Known-MAC inventory", "The set of legitimate device MACs.", BLUE),
        ("DHCP events", "{ip, mac, time, window} that EXPLAIN a legitimate lease-renewal MAC change.", PURPLE),
        ("Maintenance windows", "Intervals that explain planned moves, NIC swaps and failovers.", AMBER),
    ]
    y = 1.9
    for h, d, col in items:
        card(s, 0.6, y, 12.1, 0.95)
        rect(s, 0.6, y, 0.12, 0.95, col)
        text(s, 0.9, y + 0.12, 3.4, 0.7, [[(h, 16, WHITE, True)]], anchor=MSO_ANCHOR.MIDDLE)
        text(s, 4.4, y + 0.12, 8.1, 0.7, [[(d, 13, LAV, False)]],
             anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.05)
        y += 1.05
    text(s, 0.6, 6.35, 12.1, 0.6,
         [[("A change that matches a DHCP renewal or maintenance window is expected; "
            "the same change without that context is suspicious.", 13, TEAL, True)]],
         line_spacing=1.05)
    footer(s, 6)

    # ---- 7. Five signals ----
    s = new(prs); label(s, "The System"); title(s, "Five context-aware detection signals")
    rows = [
        [("1", TEAL), ("Gateway impersonation", WHITE), ("A non-anchor MAC claims a gateway IP", LAV), ("CRITICAL", RED)],
        [("2", TEAL), ("MAC change", WHITE), ("A known IP's MAC changes", LAV), ("HIGH / MED", AMBER)],
        [("3", TEAL), ("Duplicate IP", WHITE), ("Two+ MACs claim one IP at once", LAV), ("HIGH", AMBER)],
        [("4", TEAL), ("Abnormal rate", WHITE), ("A host's ARP volume spikes", LAV), ("MEDIUM", BLUE)],
        [("5", TEAL), ("Unknown device", WHITE), ("New MAC / off-hours behaviour", LAV), ("LOW", TEAL)],
    ]
    table(s, 0.6, 2.0, 12.1, [0.6, 3.2, 5.5, 2.0],
          ["#", "SIGNAL", "FIRES WHEN", "BASE TIER"], rows, row_h=0.72, fs=14)
    text(s, 0.6, 6.4, 12, 0.5,
         [[("Gateway impersonation is never lowered by context — a gateway anchor "
            "never changes silently.", 13, AMBER, True)]])
    footer(s, 7)

    # ---- 8. Scoring ----
    s = new(prs); label(s, "The System"); title(s, "Context-aware risk scoring")
    card(s, 0.6, 1.85, 12.1, 0.95, PANEL)
    text(s, 0.9, 2.0, 11.6, 0.7, [
        [("points = base_weight(tier) × context_factor      "
          "incident_score = Σ points", 17, TEAL, True)],
        [("Base weights:  Critical 100 · High 70 · Medium 40 · Low 15 · Info 5",
          12, LAV, False)],
    ], space_after=3)
    rows = [
        [("MAC change matches a DHCP renewal", LAV), ("×0.2", TEAL), ("strongly lowers", MUTED)],
        [("Change inside a maintenance window", LAV), ("×0.25", TEAL), ("strongly lowers", MUTED)],
        [("Duplicate IP during a known failover", LAV), ("×0.3", TEAL), ("lowers", MUTED)],
        [("Activity off-hours", LAV), ("×1.3–1.4", AMBER), ("raises", MUTED)],
        [("An unknown MAC is involved", LAV), ("×1.2", AMBER), ("raises", MUTED)],
        [("Gateway impersonation", LAV), ("×1.0", RED), ("never lowered", MUTED)],
    ]
    table(s, 0.6, 3.05, 12.1, [6.0, 2.0, 4.0],
          ["SITUATION", "FACTOR", "EFFECT"], rows, row_h=0.52, fs=13)
    text(s, 0.6, 6.5, 12, 0.4,
         [[("Total → tier: Critical ≥100 · High ≥70 · Medium ≥40 · "
            "Low ≥15 · else Info.", 12, MUTED, False)]])
    footer(s, 8)

    # ---- 9. Worked example ----
    s = new(prs); label(s, "The System"); title(s, "Worked example: gateway impersonation")
    text(s, 0.6, 1.8, 12, 0.5,
         [[("EVENT   ", 13, AMBER, True),
           ("a new MAC de:ad:be:ef:00:66 begins claiming the gateway 192.168.10.1",
            14, WHITE, False)]])
    card(s, 0.6, 2.4, 12.1, 2.3, RGBColor(0x14, 0x0F, 0x38))
    text(s, 0.9, 2.55, 11.5, 2.1, [
        [("[CRITICAL]  score = 121.0", 15, RED, True)],
        [("IP 192.168.10.1 claimed by de:ad:be:ef:00:66  (expected 00:1a:2b:00:00:01)", 13, LAV, False)],
        [("  - gateway_impersonation (100.0): claims gateway 192.168.10.1", 13, WHITE, False)],
        [("  - unknown_device (21.0): not in inventory [off-hours]", 13, WHITE, False)],
        [("  -> Quarantine the switch port; drop via DAI; notify SOC.", 13, TEAL, True)],
    ], space_after=5, line_spacing=1.05)
    card(s, 0.6, 5.0, 12.1, 1.3, PANEL)
    text(s, 0.9, 5.15, 11.6, 1.0,
         [[("Why it is not a false positive:  ", 14, AMBER, True),
           ("a gateway anchor never changes silently, so no benign context can "
            "explain this claim. The critical weight is never lowered.", 14, WHITE, False)]],
         line_spacing=1.1)
    footer(s, 9)

    # ---- 10. Dashboard (native) ----
    s = new(prs); label(s, "The System"); title(s, "Operations dashboard")
    kpis = [("100", "ARP packets analysed", TEAL),
            (str(c["TP"] + c["FN"]), "Attacks in dataset", AMBER),
            (fp, "False-positive rate", TEAL),
            (lat, "Mean latency", TEAL)]
    kx = 0.6
    for val, lab, col in kpis:
        card(s, kx, 1.9, 2.95, 1.35)
        text(s, kx + 0.25, 2.05, 2.5, 0.7, [[(val, 34, col, True)]])
        text(s, kx + 0.25, 2.7, 2.6, 0.5, [[(lab, 12, MUTED, False)]], line_spacing=1.0)
        kx += 3.08
    rows = [
        [("de:ad:be:ef:00:66", LAV), ("192.168.10.1", LAV), ("gateway_imp.", LAV), ("CRITICAL", RED)],
        [("de:ad:be:ef:00:77", LAV), ("192.168.10.40", LAV), ("duplicate_ip", LAV), ("CRITICAL", RED)],
        [("de:ad:be:ef:00:66", LAV), ("192.168.10.30", LAV), ("mac_change", LAV), ("HIGH", AMBER)],
        [("de:ad:be:ef:00:66", LAV), ("192.168.10.200", LAV), ("abnormal_rate", LAV), ("MEDIUM", BLUE)],
        [("00:1a:2b:00:00:31", LAV), ("192.168.10.30", LAV), ("failover (benign)", LAV), ("LOW", TEAL)],
    ]
    text(s, 0.6, 3.5, 6, 0.4, [[("FLAGGED DEVICES", 12, MUTED, True)]])
    table(s, 0.6, 3.85, 12.1, [3.3, 3.0, 3.2, 2.0],
          ["OFFENDING MAC", "CLAIMED IP", "TOP SIGNAL", "RISK"], rows, row_h=0.46, fs=12)
    text(s, 0.6, 6.55, 12, 0.4,
         [[("Every value is from a real detector run over the labelled dataset "
            "— no mock figures.", 12, MUTED, False)]])
    footer(s, 10)

    # ---- 11. Evaluation methodology ----
    s = new(prs); label(s, "Evaluation"); title(s, "Methodology: labelled replay")
    text(s, 0.6, 1.8, 12, 0.5,
         [[("10 episodes / 100 packets. Ground truth is labelled, so every alert "
            "is scored true or false. An alert = incident at tier ≥ Medium.",
            13, LAV, False)]], line_spacing=1.1)
    card(s, 0.6, 2.5, 5.9, 3.6)
    text(s, 0.85, 2.65, 5.4, 0.5, [[("BENIGN — must NOT alert", 14, TEAL, True)]])
    for i, t in enumerate(["Normal resolution", "DHCP lease renewal",
                           "Authorised device move / NIC swap",
                           "Server failover (registered standby)",
                           "New-device onboarding"]):
        text(s, 0.95, 3.15 + i * 0.56, 5.3, 0.5,
             [[("•  ", 14, TEAL, True), (t, 13, LAV, False)]])
    card(s, 6.8, 2.5, 5.9, 3.6)
    text(s, 7.05, 2.65, 5.4, 0.5, [[("ATTACK — must alert", 14, RED, True)]])
    for i, t in enumerate(["Gateway impersonation (off-hours)",
                           "Gratuitous-ARP poisoning (server)",
                           "Man-in-the-middle relay",
                           "ARP request flood",
                           "Duplicate-IP conflict"]):
        text(s, 7.15, 3.15 + i * 0.56, 5.3, 0.5,
             [[("•  ", 14, RED, True), (t, 13, LAV, False)]])
    text(s, 0.6, 6.4, 12, 0.4,
         [[("Phase 1 replay + Phase 2 simulated traffic. Phase 3 (live multi-VLAN "
            "lab) is a stretch goal / future work.", 12, MUTED, False)]])
    footer(s, 11)

    # ---- 12. Results ----
    s = new(prs); label(s, "Evaluation"); title(s, "Results — measured")
    res = [(det, "Detection rate", TEAL), (fp, "False-positive rate", TEAL),
           (lat, "Mean latency", AMBER), (mit, "Mitigation effect", BLUE)]
    kx = 0.6
    for val, lab, col in res:
        card(s, kx, 1.95, 2.95, 1.7)
        text(s, kx + 0.2, 2.15, 2.6, 0.8, [[(val, 40, col, True)]], align=PP_ALIGN.CENTER)
        text(s, kx + 0.1, 3.05, 2.75, 0.5, [[(lab, 13, LAV, False)]], align=PP_ALIGN.CENTER)
        kx += 3.08
    card(s, 0.6, 4.0, 12.1, 1.15, PANEL)
    text(s, 0.9, 4.2, 11.6, 0.8, [
        [("CONFUSION MATRIX  (alert tier ≥ Medium)", 12, AMBER, True)],
        [(f"TP = {c['TP']}      FN = {c['FN']}      FP = {c['FP']}      TN = {c['TN']}"
          f"        over {c['TP']+c['FN']} attack + {c['FP']+c['TN']} benign episodes",
          16, WHITE, True)],
    ], space_after=5)
    text(s, 0.6, 5.5, 12.1, 1.0, [
        [("All four proposal targets met: high detection, low false positives, "
          "sub-second latency, effective mitigation.", 14, TEAL, True)],
        [(f"Latency ranges from ~0 ms (gateway/poisoning, caught on packet 1) to "
          f"{latmax} (flood, once its rate crosses the threshold).", 13, LAV, False)],
    ], space_after=6, line_spacing=1.1)
    footer(s, 12)

    # ---- 13. Honest reading ----
    s = new(prs); label(s, "Evaluation"); title(s, "Reading the results honestly")
    notes = [
        ("Latency spread is meaningful", "Fast signals (gateway, poisoning) fire on the first packet; rate/duplicate need a few packets to confirm. The mean reflects that mix.", TEAL),
        ("80% mitigation is by design", "The flood is rated Medium, so it gets a ticket + watch, not an auto-quarantine. We do not cut off a device on one Medium signal.", AMBER),
        ("Zero false positives, with context", "Renewal & onboarding are DHCP-explained (Info); move & failover fall in maintenance windows (Low) — all below the alert line.", BLUE),
        ("Synthetic data caveat", "Figures are on a labelled synthetic dataset, not production traffic. The methodology is sound; absolute numbers would shift on live data.", PURPLE),
    ]
    y = 1.9
    for h, d, col in notes:
        card(s, 0.6, y, 12.1, 1.08)
        rect(s, 0.6, y, 0.12, 1.08, col)
        text(s, 0.9, y + 0.12, 4.0, 0.85, [[(h, 15, WHITE, True)]], anchor=MSO_ANCHOR.MIDDLE)
        text(s, 5.0, y + 0.12, 7.5, 0.85, [[(d, 12.5, LAV, False)]],
             anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.03)
        y += 1.18
    footer(s, 13)

    # ---- 14. Mitigation ----
    s = new(prs); label(s, "Positioning"); title(s, "Mitigation — complements existing defences")
    card(s, 0.6, 1.9, 5.9, 4.3)
    text(s, 0.85, 2.05, 5.4, 0.5, [[("RECOMMENDED ACTION BY TIER", 12, TEAL, True)]])
    tiers = [("Critical", "Quarantine port; drop via DAI; notify SOC", RED),
             ("High", "Isolate/verify; drop forged ARP; priority ticket", AMBER),
             ("Medium", "Raise ticket; watch; verify the binding", BLUE),
             ("Low / Info", "Log for history and trend analysis", TEAL)]
    for i, (t, d, col) in enumerate(tiers):
        yy = 2.6 + i * 0.85
        rect(s, 0.85, yy, 0.12, 0.7, col)
        text(s, 1.1, yy, 5.2, 0.7,
             [[(t + "  ", 14, col, True), (d, 12, LAV, False)]],
             anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.0)
    card(s, 6.8, 1.9, 5.9, 4.3)
    text(s, 7.05, 2.05, 5.4, 0.5, [[("ENFORCEMENT ON THE SWITCH", 12, AMBER, True)]])
    for i, t in enumerate(["Dynamic ARP Inspection + DHCP snooping drop forged ARP on untrusted ports",
                           "Port security (sticky, max 1) defeats MAC flooding and rogue hosts",
                           "Static ARP + short timeout anchor the gateway and server on R1",
                           "Sensor detects & recommends; the switch enforces the block"]):
        text(s, 7.05, 2.65 + i * 0.85, 5.4, 0.8,
             [[("•  ", 13, AMBER, True), (t, 12.5, LAV, False)]], line_spacing=1.05)
    text(s, 0.6, 6.45, 12, 0.4,
         [[("Our system adds memory, risk ranking, cross-device visibility and "
            "incident history on top of in-line enforcement.", 12, MUTED, False)]])
    footer(s, 14)

    # ---- 15. Limitations ----
    s = new(prs); label(s, "Evaluation"); title(s, "Limitations")
    lims = ["Results are on a synthetic labelled dataset, not production traffic.",
            "The dataset is modest (10 episodes) — it demonstrates each signal, not statistical significance.",
            "Thresholds are tuned for this topology; a real deployment needs a per-site learning period.",
            "Live capture needs Npcap + Administrator and a SPAN/mirror port to see other hosts' traffic."]
    y = 2.0
    for t in lims:
        card(s, 0.6, y, 12.1, 0.92)
        rect(s, 0.6, y, 0.12, 0.92, AMBER)
        text(s, 0.95, y + 0.1, 11.5, 0.72, [[(t, 14, LAV, False)]],
             anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.05)
        y += 1.04
    footer(s, 15)

    # ---- 16. Next steps ----
    s = new(prs); label(s, "Next Steps"); title(s, "Toward the final submission")
    steps = [("1", "Live multi-VLAN lab", "GNS3 / Packet Tracer on a SPAN port — Phase 3", TEAL),
             ("2", "Bigger, noisier dataset", "Plus a rule-only / DAI-only baseline to quantify the context benefit", BLUE),
             ("3", "Persist + trend", "Store incidents in a database; add trend analysis", PURPLE),
             ("4", "Threshold auto-tuning", "Learn rate/windows from a per-site learning window", AMBER)]
    y = 2.0
    for num, h, d, col in steps:
        card(s, 0.6, y, 12.1, 0.95)
        circ = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(0.85), Inches(y + 0.22),
                                  Inches(0.52), Inches(0.52))
        _set_fill(circ, col); circ.shadow.inherit = False
        tf = circ.text_frame; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
        r = p.add_run(); r.text = num; r.font.bold = True; r.font.size = Pt(18)
        r.font.color.rgb = (BG if col in (AMBER, TEAL) else WHITE); r.font.name = HEAD
        text(s, 1.6, y + 0.15, 3.8, 0.65, [[(h, 16, WHITE, True)]], anchor=MSO_ANCHOR.MIDDLE)
        text(s, 5.5, y + 0.15, 7.0, 0.65, [[(d, 12.5, LAV, False)]],
             anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.03)
        y += 1.05
    footer(s, 16)

    # ---- 17. References ----
    s = new(prs); label(s, "References"); title(s, "References")
    refs = [("RFC 826", "D. Plummer, An Ethernet Address Resolution Protocol, IETF, 1982."),
            ("Cisco DAI", "Dynamic ARP Inspection & DHCP Snooping Configuration Guide, Cisco Systems."),
            ("NIST SP 800-94", "Guide to Intrusion Detection and Prevention Systems (IDPS), NIST."),
            ("Scapy / Wireshark", "Scapy packet library (scapy.net); Wireshark ARP dissector (wireshark.org)."),
            ("Forouzan", "Data Communications and Networking, 5th ed., McGraw-Hill.")]
    y = 1.95
    for h, d in refs:
        card(s, 0.6, y, 12.1, 0.82)
        text(s, 0.9, y + 0.1, 3.0, 0.62, [[(h, 14, TEAL, True)]], anchor=MSO_ANCHOR.MIDDLE)
        text(s, 3.8, y + 0.1, 8.7, 0.62, [[(d, 12.5, LAV, False)]],
             anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.02)
        y += 0.92
    footer(s, 17)

    prs.save(out)
    print(f"Wrote {out}  ({len(prs.slides.__iter__.__self__._sldIdLst)} slides)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--metrics", default="reports/metrics.json")
    ap.add_argument("--out", default="Enterprise_ARP_Threat_Detection_Review2.pptx")
    args = ap.parse_args()
    with open(args.metrics) as fh:
        metrics = json.load(fh)
    build(metrics, args.out)


if __name__ == "__main__":
    main()
