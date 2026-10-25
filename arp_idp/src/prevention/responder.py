"""Prevention / response tier - the "P" in IDP.

Given an incident, decides proportionate, DEFENSIVE actions and (optionally)
applies the host-safe ones. All actions are reversible and restorative; the
responder never attacks and never touches anything but the trusted anchors'
own bindings.

Policy (from signal_weights.yaml) maps a minimum tier to each action:
  * recommend      - always emit the textual recommendation
  * pin_anchor     - add a static ARP entry for the TRUE anchor binding on this
                     host, so a poisoned reply cannot overwrite it
  * quarantine     - GENERATE the switch IOS commands to err-disable the port
                     (enforcement stays on the switch; we only produce them)
  * reassert       - broadcast a corrective gratuitous ARP re-announcing the
                     TRUE anchor binding to heal victims' caches

By default every action is a DRY-RUN (described, not executed). Pass
apply=True to run the host-safe actions (pin_anchor / reassert); switch
commands are always emitted as text for an operator to apply.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass, field, asdict

from src.detection.baseline import TrustedBaseline
from src.models.incident import Incident, RiskTier, TIER_RANK


@dataclass
class ResponseAction:
    kind: str                       # recommend | pin_anchor | quarantine | reassert
    target_ip: str
    detail: str
    command: str = ""               # the concrete command (host or switch)
    applied: bool = False           # did we actually execute it?
    dry_run: bool = True

    def to_dict(self):
        return asdict(self)


class Responder:
    def __init__(self, baseline: TrustedBaseline, policy: dict,
                 apply: bool = False, iface: str | None = None):
        self.bl = baseline
        self.policy = policy
        self.apply = apply
        self.iface = iface
        self.log: list[ResponseAction] = []

    def _meets(self, tier: RiskTier, key: str) -> bool:
        need = self.policy.get(key)
        return need is not None and TIER_RANK[tier] >= TIER_RANK[RiskTier(need)]

    # -- concrete host commands -----------------------------------------
    def _pin_cmd(self, ip: str, mac: str) -> str:
        if platform.system() == "Windows":
            return f'netsh interface ip add neighbors "{self.iface or "<iface>"}" {ip} {mac.replace(":", "-")}'
        if platform.system() == "Linux":
            return f"ip neigh replace {ip} lladdr {mac} dev {self.iface or '<iface>'} nud permanent"
        return f"arp -s {ip} {mac}"   # macOS / generic

    def _run(self, cmd: str) -> bool:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            return r.returncode == 0
        except Exception:
            return False

    # -- main entry ------------------------------------------------------
    def respond(self, inc: Incident) -> list[ResponseAction]:
        actions: list[ResponseAction] = []
        tier = inc.risk_tier
        role = self.bl.anchor_role(inc.claimed_ip)
        true_mac = self.bl.expected_mac(inc.claimed_ip)

        # 1) recommendation (always, at/above policy)
        if self._meets(tier, "recommend_from"):
            actions.append(ResponseAction("recommend", inc.claimed_ip,
                                          inc.recommended_action, dry_run=True))

        # 2) pin anchor (host-safe) - only for anchors with a known true MAC
        if role and true_mac and self._meets(tier, "pin_anchor_from"):
            cmd = self._pin_cmd(inc.claimed_ip, true_mac)
            applied = False
            if self.apply:
                applied = self._run(cmd)
            actions.append(ResponseAction(
                "pin_anchor", inc.claimed_ip,
                f"Pin {role} {inc.claimed_ip} -> {true_mac} (static ARP, reversible)",
                command=cmd, applied=applied, dry_run=not self.apply))

        # 3) switch quarantine - always generate commands only
        if self._meets(tier, "quarantine_from"):
            port = inc.port or "<access-port>"
            cmd = (f"interface {port} ; shutdown   "
                   f"! err-disable the port carrying {inc.offending_mac}")
            actions.append(ResponseAction(
                "quarantine", inc.claimed_ip,
                f"Quarantine port {port} (offending MAC {inc.offending_mac})",
                command=cmd, applied=False, dry_run=True))

        # 4) corrective re-assert (host-safe active defence)
        if role and true_mac and self._meets(tier, "reassert_from"):
            cmd = f"gratuitous ARP: {inc.claimed_ip} is-at {true_mac} (broadcast)"
            applied = False
            if self.apply:
                applied = self._reassert(inc.claimed_ip, true_mac)
            actions.append(ResponseAction(
                "reassert", inc.claimed_ip,
                f"Re-announce true {role} binding {inc.claimed_ip} -> {true_mac} to heal caches",
                command=cmd, applied=applied, dry_run=not self.apply))

        self.log.extend(actions)
        return actions

    def _reassert(self, ip: str, mac: str) -> bool:
        try:
            from scapy.all import ARP, Ether, sendp
            pkt = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                   / ARP(op=2, hwsrc=mac, psrc=ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip))
            sendp(pkt, iface=self.iface, count=2, verbose=False)
            return True
        except Exception:
            return False

    def unpin(self, ip: str) -> str:
        """Command to remove a static ARP pin (for cleanup after the lab)."""
        if platform.system() == "Windows":
            return f'netsh interface ip delete neighbors "{self.iface or "<iface>"}" {ip}'
        if platform.system() == "Linux":
            return f"ip neigh del {ip} dev {self.iface or '<iface>'}"
        return f"arp -d {ip}"
