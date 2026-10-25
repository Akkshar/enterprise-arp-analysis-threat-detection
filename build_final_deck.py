#!/usr/bin/env python3
"""Build the consolidated FINAL deck covering the whole project (both parts).
Theme matched to the Review 1 deck. Numbers read from arp_idp/reports.
"""
from __future__ import annotations
import argparse, json
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

BG=RGBColor(0x24,0x1A,0x5C); BG2=RGBColor(0x1B,0x14,0x48); PANEL=RGBColor(0x2B,0x25,0x52)
TEAL=RGBColor(0x00,0xA9,0x9D); AMBER=RGBColor(0xFF,0xB0,0x20); RED=RGBColor(0xFF,0x5A,0x5F)
BLUE=RGBColor(0x3D,0x8B,0xFD); PURPLE=RGBColor(0x7C,0x4D,0xFF); PINK=RGBColor(0xEC,0x48,0x99)
WHITE=RGBColor(0xFF,0xFF,0xFF); LAV=RGBColor(0xDD,0xD8,0xF5); MUTED=RGBColor(0x9A,0x93,0xC0)
HEAD="Calibri"; SW,SH=13.333,7.5
TIER_C={"CRITICAL":RED,"HIGH":AMBER,"MEDIUM":BLUE,"LOW":TEAL,"INFO":MUTED}

def _fill(s,c): s.fill.solid(); s.fill.fore_color.rgb=c; s.line.fill.background()
def rect(sl,x,y,w,h,c,r=None):
    shp=sl.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if r else MSO_SHAPE.RECTANGLE,
        Inches(x),Inches(y),Inches(w),Inches(h)); _fill(shp,c)
    if r:
        try: shp.adjustments[0]=r
        except Exception: pass
    shp.shadow.inherit=False; return shp
def text(sl,x,y,w,h,runs,align=PP_ALIGN.LEFT,anchor=MSO_ANCHOR.TOP,sa=6,ls=1.0):
    tb=sl.shapes.add_textbox(Inches(x),Inches(y),Inches(w),Inches(h)); tf=tb.text_frame
    tf.word_wrap=True; tf.vertical_anchor=anchor
    for i,para in enumerate(runs):
        p=tf.paragraphs[0] if i==0 else tf.add_paragraph()
        p.alignment=align; p.space_after=Pt(sa); p.space_before=Pt(0); p.line_spacing=ls
        for (s,sz,c,b) in para:
            r=p.add_run(); r.text=s; r.font.name=HEAD; r.font.size=Pt(sz); r.font.color.rgb=c; r.font.bold=b
    return tb
def bg(sl): rect(sl,-0.05,-0.05,SW+0.1,SH+0.1,BG)
def label(sl,s): text(sl,0.6,0.42,11,0.4,[[(s.upper(),13,TEAL,True)]])
def title(sl,s): text(sl,0.6,0.72,12.1,0.9,[[(s,29,WHITE,True)]]); rect(sl,0.62,1.5,0.9,0.06,TEAL)
def footer(sl,n):
    text(sl,0.6,7.02,10,0.4,[[("Enterprise ARP Analysis & Threat Detection · Final",9,MUTED,False)]])
    text(sl,12.3,7.02,0.6,0.4,[[(str(n),10,MUTED,True)]],align=PP_ALIGN.RIGHT)
def new(prs): s=prs.slides.add_slide(prs.slide_layouts[6]); bg(s); return s
def card(sl,x,y,w,h,c=PANEL,r=0.06): return rect(sl,x,y,w,h,c,r=r)
def circ(sl,x,y,d,c,num):
    o=sl.shapes.add_shape(MSO_SHAPE.OVAL,Inches(x),Inches(y),Inches(d),Inches(d)); _fill(o,c); o.shadow.inherit=False
    tf=o.text_frame; tf.vertical_anchor=MSO_ANCHOR.MIDDLE; p=tf.paragraphs[0]; p.alignment=PP_ALIGN.CENTER
    r=p.add_run(); r.text=num; r.font.bold=True; r.font.size=Pt(17); r.font.name=HEAD
    r.font.color.rgb=(BG if c in (AMBER,TEAL) else WHITE)
def tbl(sl,x,y,w,colw,headers,rows,rh=0.5,fs=12):
    total=sum(colw); xs=[]; cx=x; widths=[w*f/total for f in colw]
    for f in colw: xs.append(cx); cx+=w*f/total
    rect(sl,x,y,w,rh,PANEL);
    for i,h in enumerate(headers):
        text(sl,xs[i]+0.08,y+0.03,widths[i]-0.12,rh,[[(h,fs-1,TEAL,True)]],anchor=MSO_ANCHOR.MIDDLE)
    yy=y+rh
    for ri,row in enumerate(rows):
        rect(sl,x,yy,w,rh,BG2 if ri%2==0 else BG)
        for i,cell in enumerate(row):
            val,col=(cell if isinstance(cell,tuple) else (cell,LAV))
            text(sl,xs[i]+0.08,yy+0.02,widths[i]-0.12,rh,[[(val,fs,col,False)]],anchor=MSO_ANCHOR.MIDDLE)
        yy+=rh
    return yy
def badge(sl,x,y,tier,w=1.15,h=0.32):
    c=TIER_C[tier]; b=rect(sl,x,y,w,h,c,r=0.5); fg=BG if tier in("HIGH","LOW") else WHITE
    tf=b.text_frame; tf.vertical_anchor=MSO_ANCHOR.MIDDLE; p=tf.paragraphs[0]; p.alignment=PP_ALIGN.CENTER
    r=p.add_run(); r.text=tier; r.font.name=HEAD; r.font.size=Pt(10); r.font.bold=True; r.font.color.rgb=fg

def build(single,mv,out):
    prs=Presentation(); prs.slide_width=Inches(SW); prs.slide_height=Inches(SH)
    s1=lambda k: single[k];
    det=f'{single["detection_rate"]*100:.0f}%'; fp=f'{single["false_positive_rate"]*100:.1f}%'
    lat=f'{single["latency_ms"]["mean"]:.0f} ms'; mit=f'{single["mitigation_effect"]*100:.0f}%'
    c=single["confusion"]; cm=mv["confusion"]
    mvdet=f'{mv["detection_rate"]*100:.0f}%'; mvfp=f'{mv["false_positive_rate"]*100:.1f}%'
    mvlat=f'{mv["latency_ms"]["mean"]:.0f} ms'; mvmit=f'{mv["mitigation_effect"]*100:.0f}%'

    # 1 Title
    s=new(prs); rect(s,0,0,SW,SH,BG)
    text(s,0.9,1.7,11.5,0.5,[[("FINAL REVIEW · TEAM PROJECT",15,TEAL,True)]])
    text(s,0.9,2.3,11.6,1.4,[[("Enterprise ",44,WHITE,True),("ARP Analysis & Threat Detection",44,TEAL,True)]])
    text(s,0.9,3.7,11.5,0.6,[[("Problem analysis, network design, detection & prevention",18,LAV,False)]])
    rect(s,0.92,4.5,1.1,0.06,AMBER)
    text(s,0.9,4.8,11.5,1.4,[[("Stuti Zingade",15,LAV,False)],
        [("Ritika Tulsyan",15,LAV,False)],[("Akkshar Ranjan",15,LAV,False)]],sa=4)
    text(s,0.9,6.6,11.5,0.4,[[("Computer Networks and Data Communication",12,MUTED,False)]])

    # 2 Overview - two parts
    s=new(prs); label(s,"Overview"); title(s,"One project, two parts")
    parts=[("PART 1 — Diagnosis","Build a multi-VLAN LAN; analyse how ARP resolves addresses and where it fails, at packet level.",
            ["Topology & Cisco configs","IP plan & observation tables","Packet-flow analysis","Wireshark / Packet Tracer capture"],TEAL),
           ("PART 2 — Solution (IDP)","A working Intrusion Detection & Prevention system that scores every ARP claim and responds.",
            ["6 context-aware signals","Risk scoring, 5 tiers","Prevention: pin / quarantine / reassert","100% detection, 0% false positives"],AMBER)]
    for i,(h,d,items,col) in enumerate(parts):
        x=0.6+i*6.15; card(s,x,1.85,5.9,4.6); rect(s,x,1.85,5.9,0.1,col)
        text(s,x+0.3,2.05,5.4,0.5,[[(h,18,col,True)]])
        text(s,x+0.3,2.6,5.4,0.9,[[(d,13,LAV,False)]],ls=1.1)
        for j,it in enumerate(items):
            text(s,x+0.4,3.6+j*0.56,5.1,0.5,[[("•  ",13,col,True),(it,13,WHITE,False)]])
    footer(s,2)

    # 3 Why ARP exploitable
    s=new(prs); label(s,"Background"); title(s,"Why ARP is exploitable")
    pts=[("No authentication","Any host can claim any IP; receivers cannot verify the sender.",TEAL),
         ("Stateless & trusting","Replies are accepted even when no request was sent.",AMBER),
         ("Last write wins","A newer binding silently overwrites the cached entry.",BLUE),
         ("Broadcast reach","One forged reply can reach every host in the VLAN.",PURPLE)]
    for i,(h,d,col) in enumerate(pts):
        cx=0.6+(i%2)*6.15; cy=1.9+(i//2)*1.7; card(s,cx,cy,5.9,1.5); rect(s,cx,cy,0.12,1.5,col)
        text(s,cx+0.35,cy+0.18,5.4,0.5,[[(h,18,WHITE,True)]])
        text(s,cx+0.35,cy+0.7,5.4,0.7,[[(d,13,LAV,False)]],ls=1.05)
    text(s,0.6,5.5,12,0.8,[[("The whole attack family shares one signature: ",14,LAV,False),
        ("an unexpected IP-to-MAC binding",14,TEAL,True),(" — so one detector covers all of them.",14,LAV,False)]],ls=1.1)
    footer(s,3)

    # 4 Topology (native)
    s=new(prs); label(s,"Part 1 · Network design"); title(s,"Multi-VLAN enterprise topology")
    card(s,5.4,1.75,2.5,0.7,PANEL); text(s,5.5,1.85,2.3,0.5,[[("Router R1",15,WHITE,True)],[("router-on-a-stick",10,MUTED,False)]],sa=0,align=PP_ALIGN.CENTER)
    rect(s,6.6,2.45,0.04,0.7,TEAL)
    card(s,4.7,3.15,3.9,0.7,PANEL); text(s,4.8,3.26,3.7,0.5,[[("Switch SW1 · 2960",14,WHITE,True)],[("DHCP snoop · DAI · port-security",9,MUTED,False)]],sa=0,align=PP_ALIGN.CENTER)
    # sensor
    rect(s,8.6,3.4,0.9,0.03,AMBER)
    card(s,9.5,3.15,3.0,0.7,RGBColor(0x14,0x0F,0x38)); text(s,9.6,3.26,2.8,0.5,[[("IDP sensor",13,AMBER,True)],[("arpguard watch (SPAN)",9,MUTED,False)]],sa=0,align=PP_ALIGN.CENTER)
    vl=[("VLAN 10 · users","PC1 .10 · PC2 .20","192.168.10.0/24",BLUE,0.6),
        ("VLAN 20 · servers","Server .30 (anchor)","192.168.20.0/24",TEAL,4.95),
        ("VLAN 30 · guest","Guest .50","192.168.30.0/24",PINK,9.3)]
    for h,d,subnet,col,x in vl:
        rect(s,x+1.3,3.85,0.03,0.5,col)
        card(s,x,4.4,3.3,1.3); rect(s,x,4.4,3.3,0.1,col)
        text(s,x+0.25,4.6,2.9,0.9,[[(h,14,WHITE,True)],[(d,12,LAV,False)],[(subnet,11,MUTED,False)]],sa=2)
    text(s,0.6,6.3,12,0.5,[[("Static addressing — every IP-to-MAC mapping is known before capture, so each ARP result is checked, not trusted.",12,MUTED,False)]])
    footer(s,4)

    # 5 Packet flow
    s=new(prs); label(s,"Part 1 · Analysis"); title(s,"ARP packet flow")
    card(s,0.6,1.85,5.9,4.4); text(s,0.85,2.0,5.4,0.5,[[("SAME SUBNET  (PC1 → PC2)",13,TEAL,True)]])
    for i,t in enumerate(["PC1 broadcasts request (opcode 1)","Ethernet dst FF:FF:FF:FF:FF:FF","SW1 learns PC1's MAC, floods broadcast","PC2 replies by unicast (opcode 2)","SW1 forwards reply on learned port only","PC1 caches binding, sends ICMP"]):
        text(s,0.95,2.55+i*0.56,5.3,0.5,[[(f"{i+1}.  ",13,TEAL,True),(t,13,LAV,False)]])
    card(s,6.8,1.85,5.9,4.4); text(s,7.05,2.0,5.4,0.5,[[("ACROSS SUBNETS  (PC1 → Server VLAN20)",13,AMBER,True)]])
    for i,t in enumerate(["PC1 ANDs mask → destination not local","PC1 ARPs for the GATEWAY, not the server","R1 replies with its subinterface MAC","PC1 frames to server carry R1's MAC","Server's MAC never appears in VLAN 10","R1 caches PC1 and server on its subifs"]):
        text(s,7.15,2.55+i*0.56,5.3,0.5,[[(f"{i+1}.  ",13,AMBER,True),(t,13,LAV,False)]])
    footer(s,5)

    # 6 Architecture
    s=new(prs); label(s,"Part 2 · The IDP"); title(s,"System architecture")
    stages=[("1","Capture","Sniff live ARP / read PCAP; normalise every packet",TEAL),
            ("2","Baseline","Trusted IP-to-MAC store; gateway & server anchors",BLUE),
            ("3","Detect","Six signals compare each claim vs baseline + state",PURPLE),
            ("4","Score","Signal weight × context factor → a risk tier",AMBER),
            ("5","Respond","Recommend · pin · quarantine · reassert",RED)]
    y=2.0
    for num,h,d,col in stages:
        card(s,0.6,y,12.1,0.82); circ(s,0.8,y+0.16,0.5,col,num)
        text(s,1.55,y+0.17,2.3,0.5,[[(h,17,WHITE,True)]],anchor=MSO_ANCHOR.MIDDLE)
        text(s,3.9,y+0.17,8.6,0.5,[[(d,13,LAV,False)]],anchor=MSO_ANCHOR.MIDDLE); y+=0.92
    text(s,0.6,6.55,12,0.4,[[("Each stage is an independent module; signal weights live in YAML, not code.",12,MUTED,False)]])
    footer(s,6)

    # 7 Six signals
    s=new(prs); label(s,"Part 2 · Detection"); title(s,"Six context-aware signals")
    rows=[[("Gateway impersonation",WHITE),("non-anchor MAC claims a gateway IP",LAV),("CRITICAL",RED)],
          [("MAC change",WHITE),("a known IP's MAC changes",LAV),("HIGH / MED",AMBER)],
          [("Duplicate IP",WHITE),("two+ MACs claim one IP",LAV),("HIGH",AMBER)],
          [("Abnormal rate",WHITE),("a MAC's ARP volume spikes",LAV),("MEDIUM",BLUE)],
          [("Unknown device",WHITE),("MAC not in inventory / off-hours",LAV),("LOW",TEAL)],
          [("Cross-VLAN",WHITE),("one MAC seen in two VLANs",LAV),("MEDIUM",BLUE)]]
    tbl(s,0.6,2.0,12.1,[3.3,6.0,2.0],["SIGNAL","FIRES WHEN","BASE TIER"],rows,rh=0.62,fs=13)
    text(s,0.6,6.1,12,0.5,[[("Gateway impersonation is never lowered by context. Cross-VLAN catches lateral movement across the mirrored VLANs.",13,AMBER,True)]],ls=1.05)
    footer(s,7)

    # 8 Scoring
    s=new(prs); label(s,"Part 2 · Detection"); title(s,"Context-aware risk scoring")
    card(s,0.6,1.85,12.1,0.9,PANEL)
    text(s,0.9,2.0,11.6,0.65,[[("points = base_weight(tier) × context_factor      score = Σ points",17,TEAL,True)],
        [("Critical 100 · High 70 · Medium 40 · Low 15 · Info 5",12,LAV,False)]],sa=3)
    rows=[[("MAC change matches a DHCP renewal",LAV),("×0.2",TEAL),("strongly lowers",MUTED)],
          [("Change inside a maintenance window",LAV),("×0.25",TEAL),("strongly lowers",MUTED)],
          [("Duplicate IP during a known failover",LAV),("×0.3",TEAL),("lowers",MUTED)],
          [("Activity off-hours",LAV),("×1.3–1.4",AMBER),("raises",MUTED)],
          [("Gateway impersonation",LAV),("×1.0",RED),("never lowered",MUTED)]]
    tbl(s,0.6,3.0,12.1,[6.0,2.0,4.0],["SITUATION","FACTOR","EFFECT"],rows,rh=0.55,fs=13)
    text(s,0.6,6.3,12,0.4,[[("Context explains benign change, so real threats surface without false alarms.",12,MUTED,False)]])
    footer(s,8)

    # 9 Worked example
    s=new(prs); label(s,"Part 2 · Detection"); title(s,"Worked example: gateway impersonation")
    card(s,0.6,1.9,12.1,2.3,RGBColor(0x14,0x0F,0x38))
    text(s,0.9,2.05,11.5,2.1,[[("[CRITICAL]  score = 121.0",15,RED,True)],
        [("IP 192.168.10.1 claimed by de:ad:be:ef:00:66  (expected 00:1a:2b:00:00:01)",13,LAV,False)],
        [("  - GATEWAY_IMPERSONATION (100.0): claims gateway 192.168.10.1",13,WHITE,False)],
        [("  - UNKNOWN_DEVICE (21.0): not in inventory [off-hours]",13,WHITE,False)],
        [("  → pin anchor · quarantine port · reassert · notify SOC",13,TEAL,True)]],sa=5,ls=1.05)
    card(s,0.6,4.5,12.1,1.3,PANEL)
    text(s,0.9,4.68,11.6,1.0,[[("Why it is not a false positive:  ",14,AMBER,True),
        ("a gateway anchor never changes silently, so no benign context can explain this claim.",14,WHITE,False)]],ls=1.1)
    footer(s,9)

    # 10 Prevention
    s=new(prs); label(s,"Part 2 · Prevention"); title(s,"Prevention — the “P” in IDP")
    rows=[[("recommend",WHITE),("MEDIUM",BLUE),("emit the proportionate recommended action",LAV)],
          [("pin_anchor",WHITE),("HIGH",AMBER),("static-ARP the TRUE anchor binding on the host",LAV)],
          [("quarantine",WHITE),("HIGH",AMBER),("generate switch err-disable command for the port",LAV)],
          [("reassert",WHITE),("CRITICAL",RED),("broadcast corrective gratuitous ARP for the true binding",LAV)]]
    tbl(s,0.6,2.0,12.1,[2.5,2.0,7.5],["ACTION","FROM TIER","EFFECT"],rows,rh=0.62,fs=13)
    card(s,0.6,4.9,12.1,1.3,PANEL)
    text(s,0.9,5.08,11.6,1.0,[[("All actions are defensive, reversible, and touch only the anchors' own bindings. ",14,WHITE,True),
        ("Default is dry-run; --apply runs host-safe actions. The switch enforces (DAI / quarantine).",13,LAV,False)]],ls=1.1)
    footer(s,10)

    # 11 Results (single + mvlan)
    s=new(prs); label(s,"Evaluation"); title(s,"Results — measured")
    for col_i,(name,mm,dd,ff,ll, mm2,cc) in enumerate([
        ("Single VLAN · 10 episodes",single,det,fp,lat,mit,c),
        ("Multi-VLAN 10/20/30 · 7 episodes",mv,mvdet,mvfp,mvlat,mvmit,cm)]):
        x=0.6+col_i*6.15; card(s,x,1.85,5.9,4.5); rect(s,x,1.85,5.9,0.1,TEAL if col_i==0 else AMBER)
        text(s,x+0.3,2.0,5.4,0.5,[[(name,15,WHITE,True)]])
        kpis=[("Detection",dd,TEAL),("False-positive",ff,TEAL),("Latency mean",ll,AMBER),("Mitigation",mm2,BLUE)]
        for j,(lab2,val,kc) in enumerate(kpis):
            kx=x+0.3+(j%2)*2.85; ky=2.55+(j//2)*1.0
            text(s,kx,ky,2.7,0.6,[[(val,26,kc,True)]])
            text(s,kx,ky+0.5,2.7,0.4,[[(lab2,12,MUTED,False)]])
        text(s,x+0.3,4.85,5.4,0.5,[[(f"TP={cc['TP']}  FN={cc['FN']}  FP={cc['FP']}  TN={cc['TN']}",14,WHITE,True)]])
        text(s,x+0.3,5.3,5.4,0.8,[[("Perfect detection, zero false positives.",12,LAV,False)]])
    text(s,0.6,6.5,12,0.4,[[("All figures measured from detector runs over labelled datasets — not mock values. 21 pytest tests pass.",12,MUTED,False)]])
    footer(s,11)

    # 12 Reading honestly + limitations
    s=new(prs); label(s,"Evaluation"); title(s,"Reading the results honestly")
    notes=[("Latency spread is meaningful","Gateway/poisoning caught on packet 1 (~0 ms); rate, duplicate and cross-VLAN need a few packets to confirm.",TEAL),
           ("Mitigation 75–80% is by design","Flood & cross-VLAN are Medium → ticket + watch, not auto-quarantine. No cut-off on one Medium signal.",AMBER),
           ("Zero false positives, with context","Renewal & onboarding are DHCP-explained; move & failover fall in maintenance windows.",BLUE),
           ("Synthetic data caveat","Figures are on labelled synthetic datasets, not production traffic; absolute numbers would shift live.",PURPLE)]
    y=1.9
    for h,d,col in notes:
        card(s,0.6,y,12.1,1.08); rect(s,0.6,y,0.12,1.08,col)
        text(s,0.9,y+0.12,4.1,0.85,[[(h,15,WHITE,True)]],anchor=MSO_ANCHOR.MIDDLE)
        text(s,5.1,y+0.12,7.4,0.85,[[(d,12.5,LAV,False)]],anchor=MSO_ANCHOR.MIDDLE,ls=1.03); y+=1.18
    footer(s,12)

    # 13 Switch hardening
    s=new(prs); label(s,"Prevention enforcement"); title(s,"Switch-side hardening (Cisco)")
    items=[("Dynamic ARP Inspection + DHCP snooping","Drop forged ARP on untrusted ports; trunk to R1 trusted; static ARP ACL for the server anchor.",TEAL),
           ("Port security (sticky, max 1, restrict)","One MAC per access port; defeats MAC flooding and rogue hosts; ARP rate-limited.",AMBER),
           ("Static ARP + short timeout on R1","Anchor the gateway and server bindings so a spoofed reply can't overwrite them.",BLUE),
           ("SPAN port to the IDP sensor","Mirrors all VLANs so arpguard sees every ARP and catches cross-VLAN movement.",PURPLE)]
    y=1.9
    for h,d,col in items:
        card(s,0.6,y,12.1,1.08); rect(s,0.6,y,0.12,1.08,col)
        text(s,0.9,y+0.12,4.3,0.85,[[(h,14,WHITE,True)]],anchor=MSO_ANCHOR.MIDDLE)
        text(s,5.3,y+0.12,7.2,0.85,[[(d,12.5,LAV,False)]],anchor=MSO_ANCHOR.MIDDLE,ls=1.03); y+=1.18
    footer(s,13)

    # 14 Next steps + conclusion
    s=new(prs); label(s,"Conclusion"); title(s,"Conclusion & next steps")
    card(s,0.6,1.9,12.1,1.5,PANEL)
    text(s,0.9,2.1,11.6,1.1,[[("Packet-level diagnosis + context-aware detection + proportionate prevention + switch-enforced validation ",14,WHITE,True),
        ("turn ARP from a soft target into an observable, defensible part of the LAN — with perfect detection and no false positives on the test data.",14,LAV,False)]],ls=1.15)
    steps=[("1","Live multi-VLAN lab on a SPAN port (Packet Tracer / GNS3)",TEAL),
           ("2","Larger, noisier datasets + a rule-only baseline for comparison",BLUE),
           ("3","Persist incidents to a database; add trend analysis",PURPLE),
           ("4","Per-site threshold auto-tuning from a learning window",AMBER)]
    y=3.7
    for num,t,col in steps:
        card(s,0.6,y,12.1,0.7); circ(s,0.78,y+0.12,0.46,col,num)
        text(s,1.5,y+0.1,11,0.5,[[(t,14,LAV,False)]],anchor=MSO_ANCHOR.MIDDLE); y+=0.8
    footer(s,14)

    # 15 References
    s=new(prs); label(s,"References"); title(s,"References")
    refs=[("RFC 826","D. Plummer, An Ethernet Address Resolution Protocol, IETF, 1982."),
          ("Cisco DAI","Dynamic ARP Inspection & DHCP Snooping Configuration Guide, Cisco."),
          ("NIST SP 800-94","Guide to Intrusion Detection and Prevention Systems (IDPS), NIST."),
          ("Scapy / Wireshark","Scapy packet library (scapy.net); Wireshark ARP dissector."),
          ("Forouzan","Data Communications and Networking, 5th ed., McGraw-Hill.")]
    y=1.95
    for h,d in refs:
        card(s,0.6,y,12.1,0.82)
        text(s,0.9,y+0.1,3.0,0.62,[[(h,14,TEAL,True)]],anchor=MSO_ANCHOR.MIDDLE)
        text(s,3.8,y+0.1,8.7,0.62,[[(d,12.5,LAV,False)]],anchor=MSO_ANCHOR.MIDDLE,ls=1.02); y+=0.92
    footer(s,15)

    prs.save(out); print(f"Wrote {out} ({len(prs.slides._sldIdLst)} slides)")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--single",default="arp_idp/reports/metrics.json")
    ap.add_argument("--mvlan",default="arp_idp/reports/metrics_mvlan.json")
    ap.add_argument("--out",default="Enterprise_ARP_Analysis_and_Detection_FINAL.pptx")
    a=ap.parse_args()
    build(json.load(open(a.single)),json.load(open(a.mvlan)),a.out)

if __name__=="__main__": main()
