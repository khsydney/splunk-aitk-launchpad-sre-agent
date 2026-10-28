"""Glue: run one case through evidence → investigation → policy; approve → execute → verify. Fail closed: any
exception during investigation or execution moves the case to `escalated` with the error recorded."""

from __future__ import annotations

import os
import time

from . import case as cs
from . import cancel, catalogue, policy
from .audit import emit, sha
from .evidence import collect
from .executor import CHAOS_URL, execute, read_flags
from .investigator import investigate
from .toolset import ToolSet


def jev_summary(c: dict, inv: dict, bundle_text: str) -> str:
    svc = inv.get("root_cause_service")
    act = (inv.get("proposed_action") or {}).get("type", "")
    return (f"Incident detectors: {[i.get('detector') for i in c['incidents']]}. Root-cause service claimed: {svc}. "
            f"Proposed action: {act} in namespace tuktukpay. Evidence excerpt (first 6000 chars):\n{bundle_text[:6000]}")


def _page_team(root_cause_service, detectors) -> str:
    """Owner of the root-cause service; when there is none (governance, stale alert), the owner of the alerting service."""
    if root_cause_service in catalogue.OWNERS:
        return catalogue.owner_of(root_cause_service)
    from .evidence import affected_services
    svcs = affected_services(detectors)
    return catalogue.owner_of(svcs[0]) if svcs else catalogue.owner_of(None)


def live_incident_active(c: dict) -> bool | None:
    """Re-read authoritative incident state at decision time. None (never True) when it cannot be read or when the
    case has no real incident ids (an --act scenario)."""
    ids = {i.get("incident_id") for i in c["incidents"] if not str(i.get("incident_id", "")).startswith("manual-")}
    if not ids:
        return None
    try:
        from .trigger import fetch_open_incidents, ours
        live = {i["incident_id"]: i.get("anomaly_state") for i in ours(fetch_open_incidents())}
        return any(live.get(x) == "ANOMALOUS" for x in ids)
    except Exception:  # noqa: BLE001
        return None


def run_investigation(c: dict, mcp, splunk, provider: str | None, mode: str, marker_mode: bool = True, window: str = "-15m", keep: dict | None = None) -> dict:
    from .audit import CURRENT_CASE
    CURRENT_CASE.set(c["id"])   # raw MCP calls made for this case are attributed to it (sre.mcp.call)
    cancel.clear(c["id"])
    cs.transition(c, "investigating")
    try:
        try:   # suggestions only (never merged by code); a failure here must not stop the investigation
            from . import ties, topology
            graph = topology.current_graph()
            ties.record_ties(c, graph)
            c["topology"] = graph.summary(ties.case_services(c))   # every case, also console ones that skip the trigger
        except Exception as e:  # noqa: BLE001
            emit("sre.case.ties_failed", case_id=c["id"], error=f"{type(e).__name__}: {e}"[:300])
        detectors = [i.get("detector", "") for i in c["incidents"]]
        bundle = collect(mcp, splunk, detectors, window, marker_mode)
        if keep is not None:
            keep["bundle"] = bundle.as_text()   # in memory only, for follow-up questions in the console
            keep["sections"] = dict(bundle.sections)   # and for the eval scorer (evidence ids -> text)
        from .tools import preview_envelope
        for name, text in bundle.sections.items():
            pv = preview_envelope(text) if name != "collector_errors" else {"summary": "errors", "preview": text[:700]}
            emit("sre.rca.evidence", case_id=c["id"], section=name, summary=pv["summary"], preview=pv["preview"], chars=len(text))
        toolset = ToolSet(mcp, splunk, marker_mode)
        res = investigate(c, bundle.as_text(), toolset, provider)
        from .investigator import ESCALATE_MODEL, should_escalate
        tree_method = os.getenv("SRE_AGENT_METHOD", "loop") == "tree"   # the tree's planner is already the strong model
        why = should_escalate(res.investigation) if (provider or os.getenv("SRE_AGENT_PROVIDER", "mock")) != "mock" and not tree_method else ""
        if why and ESCALATE_MODEL and ESCALATE_MODEL != res.stats.model.replace("global.anthropic.", ""):
            cancel.check(c["id"], f"before the re-run with {ESCALATE_MODEL}")
            emit("sre.case.escalated_model", case_id=c["id"], from_model=res.stats.model, to_model=ESCALATE_MODEL, reason=why,
                 first_cost_usd=round(res.stats.cost_usd, 4), first_action=(res.investigation.get("proposed_action") or {}).get("type"))
            first, first_toolset = res, toolset
            toolset = ToolSet(mcp, splunk, marker_mode)
            try:
                res = investigate(c, bundle.as_text(), toolset, provider, model=ESCALATE_MODEL)
                res.stats.cost_usd += first.stats.cost_usd
                res.stats.provider = f"{res.stats.provider} (escalated from {first.stats.model}: {why})"
            except cancel.Stopped as e:
                if e.stats is not None:
                    e.stats.cost_usd += first.stats.cost_usd
                raise
            except Exception as e:  # noqa: BLE001 — a failed re-run must not throw away the first answer
                err = f"{type(e).__name__}: {e}"[:300]
                emit("sre.case.escalation_failed", case_id=c["id"], to_model=ESCALATE_MODEL, error=err, kept_model=first.stats.model)
                res, toolset = first, first_toolset
                res.investigation["escalation_error"] = f"re-run with {ESCALATE_MODEL} failed ({err}); showing the first answer ({why})"
                res.stats.provider = f"{res.stats.provider} (escalation to {ESCALATE_MODEL} failed: {type(e).__name__})"
        if keep is not None:
            keep["tool_outputs"] = {**keep.get("tool_outputs", {}), **toolset.outputs}   # in memory only (eval scorer)
        tainted = sorted(set(bundle.tainted + toolset.tainted))
        flags = read_flags(CHAOS_URL) if CHAOS_URL else None
        incident_active = live_incident_active(c)
        d = policy.decide(c["id"], res.investigation, flags_state=flags, incident_active=incident_active, tainted=tainted,
                          mode=mode, chaos_url=CHAOS_URL, jev_summary=jev_summary(c, res.investigation, bundle.as_text()))
        c["investigation"] = res.investigation
        c["decision"] = d.to_dict()
        from .audit import FAILURES
        c["stats"] = {**res.stats.__dict__, "audit_write_failures": FAILURES["count"], "bundle_tool_calls": bundle.tool_calls, "investigator_tool_calls": toolset.calls,
                      "spl_calls": toolset.spl_calls, "tainted": tainted, "collector_errors": bundle.errors, "incident_active": incident_active}
        c["transcript"] = toolset.log + res.transcript
        emit("sre.case.investigated", case_id=c["id"], provider=res.stats.provider, model=res.stats.model, requests=res.stats.requests,
             input_tokens=res.stats.input_tokens, output_tokens=res.stats.output_tokens, cache_read_tokens=res.stats.cache_read_tokens,
             cost_usd=round(res.stats.cost_usd, 4), price_known=res.stats.price_known, budget_hit=res.stats.budget_hit, seconds=round(res.stats.seconds, 1),
             root_cause_service=res.investigation.get("root_cause_service"), failure_mode=res.investigation.get("failure_mode"),
             confidence=res.investigation.get("confidence"), proposed_action=(res.investigation.get("proposed_action") or {}).get("type"),
             narrative_sha=sha(res.investigation.get("narrative", "")), tainted=tainted, incident_active=incident_active,
             # the model's (redacted-input) output, for the control tower's case view; the audit index is admin-only
             narrative=str(res.investigation.get("narrative", ""))[:1500],
             rationale=str((res.investigation.get("proposed_action") or {}).get("rationale", ""))[:600],
             hypotheses=[{"statement": str(h.get("statement", ""))[:300], "status": h.get("status"), "independent": h.get("independent")}
                         for h in (res.investigation.get("hypotheses") or [])][:6],
             detectors=[i.get("detector") for i in c["incidents"]],
             incidents_joined=[dict(i["joined"], detector=i.get("detector")) for i in c["incidents"] if i.get("joined")],
             ties=[dict(t) for t in (c.get("ties") or {}).values() if t.get("status") == "suggested"],
             topology=c.get("topology"),
             # structured write-up (tuktukpay-d6, 21 Oct): rendered by the console and the control tower page
             summary=str(res.investigation.get("summary", ""))[:400],
             impact=str(res.investigation.get("impact", ""))[:600],
             started_at=str(res.investigation.get("started_at", ""))[:40],
             cause_chain=[str(x)[:240] for x in (res.investigation.get("cause_chain") or [])][:8],
             tree_text=str(res.investigation.get("tree_text", ""))[:4000],
             evidence=[{"signal": str(e.get("signal", ""))[:10], "finding": str(e.get("finding", ""))[:300], "evidence_id": str(e.get("evidence_id", ""))[:80]}
                       for e in (res.investigation.get("evidence") or []) if isinstance(e, dict)][:10],
             ruled_out=[str(x)[:240] for x in (res.investigation.get("ruled_out") or [])][:8],
             evidence_gap=str(res.investigation.get("evidence_gap") or "")[:300],
             page_team=_page_team(res.investigation.get("root_cause_service"), detectors),
             escalation_error=str(res.investigation.get("escalation_error") or "")[:400])
    except cancel.Stopped as e:   # operator stop: nothing proposed, nothing executed
        return stopped(c, e)
    except Exception as e:  # noqa: BLE001 — fail closed: never leave a case in `investigating`
        emit("sre.case.error", case_id=c["id"], stage="investigation", error=f"{type(e).__name__}: {e}"[:300])
        cs.transition(c, "escalated", reason=f"investigation error: {type(e).__name__}: {e}"[:300])
        raise
    if d.action == "inconclusive":
        cs.transition(c, "inconclusive", reason=d.reasons)
    elif d.requirement == "none":
        cs.transition(c, "proposed", action=d.action, requirement=d.requirement)
        cs.transition(c, "closed", reason="no_action")
    elif d.requirement == "never":
        cs.transition(c, "proposed", action=d.action, requirement=d.requirement, reasons=d.reasons)
        cs.transition(c, "escalated", reason=d.reasons)
    else:
        cs.transition(c, "proposed", action=d.action, requirement=d.requirement, plan_hash=d.plan_hash)
        emit("remediation.proposed", case_id=c["id"], action=d.action, tier=d.tier, requirement=d.requirement, plan_hash=d.plan_hash,
             request=d.request_preview, verification=d.verification.get("description"), jev=d.jev.get("verdict"), jev_mode=d.jev.get("mode"), reasons=d.reasons,
             real_world=d.real_world)
        if d.requirement == "auto":
            emit("approval.decided", case_id=c["id"], decision="approve", approver="policy:auto-demo", plan_hash=d.plan_hash)
            cs.transition(c, "remediating", approver="policy:auto-demo", plan_hash=d.plan_hash)
            cs.save(c)
            return _execute_remediating(c, "policy:auto-demo", mcp, splunk)
        cs.transition(c, "awaiting_approval", plan_hash=d.plan_hash, expires_at=d.approval_expires_at)
        emit("approval.requested", case_id=c["id"], action=d.action, plan_hash=d.plan_hash, request=d.request_preview, expires_at=d.approval_expires_at)
    cs.save(c)
    return c


def stopped(c: dict, e: cancel.Stopped) -> dict:
    st = e.stats
    spent = round(getattr(st, "cost_usd", 0.0) or 0.0, 4)
    calls = getattr(st, "requests", 0) or 0
    reason = f"stopped by {e.by} during {e.stage}, after {calls} model call(s), ${spent:.4f} spent; nothing proposed or executed"
    emit("sre.case.stopped", case_id=c["id"], by=e.by, stage=e.stage, model_calls=calls, cost_usd=spent)
    c["stats"] = {"stopped": True, "stopped_by": e.by, "stage": e.stage, "requests": calls, "cost_usd": spent}
    cs.transition(c, "closed", reason=reason)
    cancel.clear(c["id"])
    return c


def approve_and_execute(c: dict, plan_hash: str, approver: str, mcp, splunk, dry_run: bool = False) -> dict:
    from .audit import CURRENT_CASE
    CURRENT_CASE.set(c["id"])
    d = c["decision"]
    if c["state"] not in ("awaiting_approval", "remediating"):
        raise ValueError(f"case is {c['state']}, nothing to approve")
    if plan_hash != d["plan_hash"]:
        raise ValueError("plan hash does not match the proposed plan (a re-plan invalidates approvals)")
    if dry_run:
        out = execute(d, c["id"], approver, mcp, splunk, dry_run=True)   # never consumes the approval or moves the case
        c["outcome"] = {**out.to_dict(), "dry_run": True}
        emit("remediation.dry_run", case_id=c["id"], action=d["action"], plan_hash=plan_hash, approver=approver, detail=out.detail)
        cs.save(c)
        return c
    if time.time() > d["approval_expires_at"]:
        cs.transition(c, "escalated", reason="approval expired (expiry means no)")
        raise ValueError("approval expired")
    if c["state"] == "awaiting_approval":
        emit("approval.decided", case_id=c["id"], decision="approve", approver=approver, plan_hash=plan_hash)
        cs.transition(c, "remediating", approver=approver, plan_hash=plan_hash)
    return _execute_remediating(c, approver, mcp, splunk)


def _execute_remediating(c: dict, approver: str, mcp, splunk) -> dict:
    d = c["decision"]
    if c.get("outcome") and not c["outcome"].get("dry_run"):
        raise ValueError("execution already started for this plan; open a new case")
    c["outcome"] = {"executed": None, "started": time.time()}   # write-ahead marker: a crash here cannot cause a silent second run
    cs.save(c)
    try:
        out = execute(d, c["id"], approver, mcp, splunk)
    except Exception as e:  # noqa: BLE001
        emit("sre.case.error", case_id=c["id"], stage="execution", error=f"{type(e).__name__}: {e}"[:300])
        c["outcome"] = {"executed": None, "error": f"{type(e).__name__}: {e}"[:300]}
        cs.transition(c, "escalated", reason=f"execution error: {type(e).__name__}"[:300])
        return c
    c["outcome"] = out.to_dict()
    if not out.executed:
        cs.transition(c, "escalated", reason="action refused or not executed", detail=out.detail)
        return c
    cs.transition(c, "verifying", immediate_ok=out.immediate_ok)
    if out.outcome_ok:
        cs.transition(c, "mitigated_awaiting_clear", detail=out.detail)
    elif out.outcome_ok is None:
        cs.transition(c, "mitigated_awaiting_clear", detail=out.detail + ["no outcome query; detector clear decides"])
    else:
        cs.transition(c, "verification_failed", detail=out.detail)
        cs.transition(c, "escalated", reason="verification failed; the change stays in place (no automatic reversal exists), human needed")
    return c


def reject(c: dict, approver: str, reason: str) -> dict:
    emit("approval.decided", case_id=c["id"], decision="reject", approver=approver, reason=reason)
    return cs.transition(c, "closed", reason=f"rejected by {approver}: {reason}")


def close(c: dict, operator: str, reason: str) -> dict:
    return cs.transition(c, "closed", reason=f"closed by {operator}: {reason}")
