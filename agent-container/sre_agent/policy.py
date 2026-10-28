"""Policy engine: deterministic decision on the investigator's proposal (section 6–7 of the design).

Inputs: the Investigation object, the catalogue, authoritative state (chaos flags, incident still active), taint
flags from the tool-result interceptor, the Jev advisory verdict and the policy mode. Output: a Decision with the
approval requirement, a plan hash (approval token), the exact request the executor will send and the reasons.
Default-deny: anything not resolvable to an implemented, non-forbidden catalogue action becomes `none`.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field

from . import catalogue, jev_gate

APPROVAL_TTL_S = int(os.getenv("SRE_AGENT_APPROVAL_TTL_S", "600"))


@dataclass
class Decision:
    action: str                              # catalogue enum, "no_action", "inconclusive" or "none"
    tier: str
    requirement: str                         # auto | ask | never | none
    reasons: list[str] = field(default_factory=list)
    plan_hash: str = ""
    request_preview: dict = field(default_factory=dict)   # exactly what the executor will send
    verification: dict = field(default_factory=dict)
    corroboration: dict = field(default_factory=dict)
    jev: dict = field(default_factory=dict)
    approval_expires_at: float = 0.0
    mode: str = "ask"
    real_world: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def request_preview(action: catalogue.Action, chaos_url: str) -> dict:
    if action.kind == "chaos.flag_off":
        return {"method": "POST", "url": f"{chaos_url}/flags/{action.target}", "json": {"enabled": False}}
    if action.kind == "k8s.rollout_undo":
        return {"command": ["kubectl", "-n", "tuktukpay", "--as", "system:serviceaccount:tuktukpay:sre-executor",
                            "rollout", "undo", f"deployment/{action.target}"]}
    return {"note": "not implemented in the prototype"}


def plan_hash(action_name: str, preview: dict, case_id: str) -> str:
    return hashlib.sha256(json.dumps({"a": action_name, "p": preview, "c": case_id}, sort_keys=True).encode()).hexdigest()[:12]


def decide(case_id: str, investigation: dict, *, flags_state: dict | None, incident_active: bool | None,
           tainted: list[str], mode: str, chaos_url: str, jev_summary: str) -> Decision:
    proposed = (investigation.get("proposed_action") or {})
    name = proposed.get("type", "inconclusive") if isinstance(proposed, dict) else str(proposed)
    if name in ("inconclusive", "", None):
        return Decision("inconclusive", "-", "none", ["investigator returned inconclusive; evidence is posted for a human"], mode=mode)
    action = catalogue.ACTIONS.get(name)
    if action is None:
        return Decision("none", "-", "never", [f"'{name}' is not in the catalogue (default deny)"], mode=mode)
    if action.tier == "forbidden":
        return Decision(action.name, "forbidden", "never", [f"{action.target}: {action.notes}"], mode=mode, real_world=action.real_world)
    if not action.implemented:
        return Decision(action.name, action.tier, "never", ["action is in the catalogue but not implemented in the prototype"], mode=mode, real_world=action.real_world)
    if action.kind == "no_action":
        return Decision("no_action", "automatic", "none", ["no remediation: notify and close"], mode=mode, real_world=action.real_world)

    reasons, corroboration = [], {}
    requirement = "ask"
    if action.tier == "auto_eligible" and mode == "auto-demo":
        requirement = "auto"
    # authoritative-state corroboration (never log text)
    if action.kind == "chaos.flag_off":
        enabled = (flags_state or {}).get(action.target, {}).get("enabled") if flags_state is not None else None
        corroboration["flag_enabled"] = enabled
        if enabled is not True:
            requirement, _ = "ask", reasons.append("flag is not enabled in authoritative state (GET /flags): no auto")
    corroboration["incident_active"] = incident_active
    if incident_active is not True:
        requirement = "ask" if requirement == "auto" else requirement
        reasons.append("incident not confirmed active: no auto")
    if tainted:
        requirement = "ask" if requirement == "auto" else requirement
        reasons.append(f"tool results flagged by the injection interceptor ({', '.join(tainted)}): human review")
    jev = jev_gate.evaluate(jev_summary)
    if jev.verdict != "allow" and requirement == "auto":
        requirement = "ask"
        reasons.append(f"Jev advisory verdict {jev.verdict} ({jev.reason}): human review")
    if jev.mode != "real" and requirement == "auto":
        requirement = "ask"
        reasons.append(f"gate.mode={jev.mode}: recommend-only")
    if investigation.get("confidence", 0) < 0.6 and requirement == "auto":
        requirement = "ask"
        reasons.append("confidence below 0.6: human review")
    if not reasons:
        reasons.append("auto-eligible action, state corroborated, Jev allow, policy auto-demo" if requirement == "auto" else "policy mode ask")
    preview = request_preview(action, chaos_url)
    return Decision(action.name, action.tier, requirement, reasons, plan_hash(action.name, preview, case_id), preview,
                    asdict(action.verification), corroboration, asdict(jev), time.time() + APPROVAL_TTL_S, mode, action.real_world)
