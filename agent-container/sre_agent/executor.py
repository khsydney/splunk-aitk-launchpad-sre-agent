"""Executor (section 3.1): performs exactly one typed catalogue action under its own identity and verifies it with
the catalogue's fixed queries. Builds every request from the enum — never from model text. Only `chaos.flag_off`
(body always {"enabled": false}) and `k8s.rollout_undo` (with the template-diff precondition) are implemented."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field

import httpx

from . import catalogue
from .audit import emit

CHAOS_URL = os.getenv("CHAOS_URL", "").rstrip("/")
KUBE_CONTEXT = os.getenv("KUBE_CONTEXT", "tuktukpay-eks")
EXECUTOR_SA = "system:serviceaccount:tuktukpay:sre-executor"


@dataclass
class Outcome:
    action: str
    executed: bool
    immediate_ok: bool | None = None
    outcome_ok: bool | None = None
    detail: list[str] = field(default_factory=list)
    idempotency_key: str = ""
    verification_value: object = None
    seconds: float = 0.0

    def to_dict(self):
        return asdict(self)


def read_flags(chaos_url: str = CHAOS_URL) -> dict | None:
    try:
        return httpx.get(f"{chaos_url}/flags", timeout=10).json()
    except Exception:  # noqa: BLE001
        return None


def _rollout_undo_precondition(dep: str) -> tuple[bool, str]:
    """True only when the previous ReplicaSet's template differs from the current one (otherwise undo changes nothing)."""
    try:
        out = subprocess.run(["kubectl", "--context", KUBE_CONTEXT, "-n", "tuktukpay", "get", "rs", "-l", f"app={dep}", "-o", "json"],
                             capture_output=True, text=True, timeout=30, check=True).stdout
        items = json.loads(out)["items"]
        hashes = {i["metadata"]["labels"].get("pod-template-hash"): i["spec"]["template"] for i in items}
        templates = [json.dumps(t, sort_keys=True) for t in hashes.values()]
        return (len(set(templates)) > 1, f"{len(items)} ReplicaSets, {len(set(templates))} distinct templates")
    except Exception as e:  # noqa: BLE001
        return False, f"precondition check failed: {e}"[:200]


def execute(decision: dict, case_id: str, approver: str, mcp=None, splunk=None, dry_run: bool = False) -> Outcome:
    t0 = time.time()
    action = catalogue.ACTIONS[decision["action"]]
    key = f"{case_id}:{decision['plan_hash']}:{uuid.uuid4().hex[:6]}"
    out = Outcome(action.name, False, idempotency_key=key)
    emit("remediation.executing", case_id=case_id, action=action.name, plan_hash=decision["plan_hash"], approver=approver, dry_run=dry_run, request=decision["request_preview"])
    t_fix = None
    if action.kind == "chaos.flag_off":
        if action.target not in catalogue.FAULT_FLAGS:
            out.detail.append("refused: not a fault flag")
            return out
        url = f"{CHAOS_URL}/flags/{action.target}"
        pre = read_flags()   # re-corroborate immediately before acting: the approval may be minutes old
        pre_enabled = (pre or {}).get(action.target, {}).get("enabled")
        if pre_enabled is not True:
            out.detail.append(f"refused: state changed since the proposal (flag enabled={pre_enabled}); nothing to revert")
            emit("remediation.refused", case_id=case_id, action=action.name, reason="state_changed", pre_state=pre_enabled)
            return out
        if dry_run:
            out.detail.append(f"dry-run: would POST {url} {{'enabled': false}} (pre-state enabled=True confirmed)")
        else:
            r = httpx.post(url, json={"enabled": False}, headers={"Idempotency-Key": key, "X-SRE-Case": case_id}, timeout=15)
            t_fix = time.time()
            out.executed = r.status_code < 300
            out.detail.append(f"POST {url} -> {r.status_code}")
            time.sleep(3)   # services poll the flags every 2 s
            flags = read_flags()
            out.immediate_ok = bool(flags) and flags.get(action.target, {}).get("enabled") is False
            out.detail.append(f"layer-1 state check: flag enabled={flags.get(action.target, {}).get('enabled') if flags else 'unknown'}")
            emit("remediation.state", case_id=case_id, action=action.name, pre_state={"enabled": pre_enabled}, post_state={"enabled": (flags or {}).get(action.target, {}).get("enabled")})
    elif action.kind == "k8s.rollout_undo":
        ok, why = _rollout_undo_precondition(action.target)
        out.detail.append(f"precondition: {why}")
        if not ok:
            out.detail.append("refused: rollout undo would change nothing (or precondition unknown)")
            emit("remediation.refused", case_id=case_id, action=action.name, reason=why)
            return out
        cmd = ["kubectl", "--context", KUBE_CONTEXT, "-n", "tuktukpay", "--as", EXECUTOR_SA, "rollout", "undo", f"deployment/{action.target}"]
        if dry_run:
            out.detail.append("dry-run: " + " ".join(cmd))
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            t_fix = time.time()
            out.executed = r.returncode == 0
            out.immediate_ok = out.executed
            out.detail.append((r.stdout or r.stderr).strip()[:300])
    else:
        out.detail.append("not implemented in the prototype")
        return out
    emit("remediation.executed", case_id=case_id, action=action.name, executed=out.executed, immediate_ok=out.immediate_ok, idempotency_key=key, dry_run=dry_run)
    if out.executed and not dry_run:
        out.outcome_ok, out.verification_value, note = verify(action.verification, mcp, splunk, t_fix or time.time())
        out.detail.append(note)
        emit("remediation.verified", case_id=case_id, action=action.name, outcome_ok=out.outcome_ok, value=out.verification_value, query=action.verification.outcome_query[:200])
    out.seconds = time.time() - t0
    return out


def verify(v: catalogue.Verification, mcp, splunk, t_fix: float, grace_s: int = 30, window_s: int = 30) -> tuple[bool | None, object, str]:
    """Layer-2 outcome check. The observation window starts AFTER the fix plus a grace period (so pre-fix events are
    never counted), two consecutive polls must satisfy the condition, and the deadline is t_fix + timeout."""
    if v.outcome_kind == "none":
        return None, None, "no outcome query defined"
    deadline = t_fix + v.timeout_s
    passes, last = 0, None
    time.sleep(max(0.0, (t_fix + grace_s + window_s) - time.time()))
    while time.time() < deadline:
        start = int(time.time() - window_s)
        try:
            if v.outcome_kind == "spl" and splunk:
                r = splunk.splunk_run_query(v.outcome_query.format(earliest=start), earliest_time=str(start))
                last = int((r["results"] or [{"count": 0}])[0].get("count", 0))
            elif v.outcome_kind == "signalflow" and mcp:
                s = mcp.signalflow(v.outcome_query, str(start), "now", 10000)["series"]
                pts = [p for ser in s for p in ser["points"] if p[1] is not None and p[0] / 1000 >= t_fix + grace_s]
                last = pts[-1][1] if pts else None
            else:
                return None, None, "verification client not available"
        except Exception as e:  # noqa: BLE001
            last = f"error: {e}"[:120]
        ok = (v.outcome_condition == "zero" and last == 0) or (
            isinstance(v.outcome_condition, str) and v.outcome_condition.startswith("below:") and isinstance(last, (int, float)) and last < float(v.outcome_condition[6:]))
        passes = passes + 1 if ok else 0
        if passes >= 2:
            return True, last, f"verified: {v.description} (two consecutive clean {window_s}s windows after the fix)"
        time.sleep(15)
    return False, last, f"not verified within {v.timeout_s}s after the fix: {v.description} (last value {last}); the change stays in place, case escalated"
