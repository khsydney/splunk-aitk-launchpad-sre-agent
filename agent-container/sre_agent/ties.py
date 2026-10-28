"""Possible ties between cases (design section 5.1): when a case starts, code looks for other cases from the last
TIE_LOOKBACK_S whose services sit on one call path of the service map with this case's, and records each as a
suggestion on both cases with its direction, path and time gap. Code never merges: an operator merges or dismisses a
tie in the console, and the investigator sees the ties in its prompt."""

from __future__ import annotations

import calendar
import os
import re
import time

from . import case as cs
from . import topology
from .audit import emit
from .evidence import affected_services

TIE_LOOKBACK_S = int(os.getenv("SRE_AGENT_TIE_LOOKBACK_S", "1800"))
REVERSE = {"likely_cause_of": "likely_symptom_of", "likely_symptom_of": "likely_cause_of", "same_service": "same_service"}
BUSY = ("open", "investigating", "remediating", "verifying")
CASE_ID = re.compile(r"C-\d{8}-[0-9a-f]{4}")


def incident_services(inc: dict) -> list[str]:
    """Services an incident names: from the detector name, else from its Kubernetes / APM dimensions."""
    return list(dict.fromkeys(affected_services([inc.get("detector", "")]) + topology.services_from_dimensions(inc.get("dimensions") or {})))


def case_services(c: dict) -> list[str]:
    return list(dict.fromkeys(s for x in c.get("incidents", []) for s in (x.get("services") or incident_services(x))))


def opened_epoch(c: dict) -> float:
    return float(c.get("opened_epoch") or calendar.timegm(time.strptime(c["opened_at"], "%Y-%m-%dT%H:%M:%SZ")))


def relation(mine, theirs, graph: topology.Graph) -> tuple[list[str] | None, str | None]:
    """Call path between two service sets and what it means for `mine`: `likely_cause_of` when mine is downstream."""
    p = graph.related(mine, theirs)
    if not p:
        return None, None
    return p, "same_service" if len(p) == 1 else "likely_cause_of" if p[-1] in mine and p[0] in theirs else "likely_symptom_of"


def collapse(ts: list[dict]) -> list[dict]:
    """One tie per alert set: earlier cases of the same detectors (re-fires, re-runs) collapse into the newest."""
    best: dict = {}
    for t in ts:
        k = tuple(sorted(str(d) for d in t.get("detectors") or []))
        if k not in best or (t.get("gap_s") or 0) < (best[k].get("gap_s") or 0):
            best[k] = t
    return list(best.values())


def view(c: dict, incidents: list[dict] | None, graph: topology.Graph, case_of=None) -> dict:
    """What the console shows, computed at request time so states are current: suggested case ties (collapsed, each
    with its current case state and whether that detector is still firing) and open alerts on a related service that
    no active case owns (`case_of(incident_id)` → that alert's newest case or None)."""
    if c["state"] == "closed" or c.get("merged_into"):
        return {"cases": [], "alerts": [], "graph": graph.source}   # nothing to merge into a closed case
    live = incidents or []
    firing = {i.get("detector") for i in live}
    own = {i.get("detector") for i in c.get("incidents", [])}
    out_cases = []
    for t in collapse([t for t in (c.get("ties") or {}).values() if t.get("status") == "suggested"]):
        if set(t.get("detectors") or []) <= own:
            continue   # an earlier firing of alerts this case already covers
        try:
            o = cs.load(t["case_id"])
        except (OSError, ValueError):
            continue
        out_cases.append(dict(t, state=o["state"], alert_firing=any(d in firing for d in t.get("detectors") or [])))
    mine, have = case_services(c), {i.get("incident_id") for i in c.get("incidents", [])}
    out_alerts = []
    for i in live if mine and c["state"] != "closed" else []:
        if i.get("incident_id") in have:
            continue
        owner = case_of(i["incident_id"]) if case_of else None
        if owner and owner.get("state") in cs.ACTIVE_STATES:
            continue   # another active case already owns it: that case shows up as a case tie instead
        p, rel = relation(mine, incident_services(i), graph)
        if p:
            out_alerts.append({"incident_id": i["incident_id"], "detector": i.get("detector"), "since": i.get("since"),
                               "relation": rel, "path": p, "hops": len(p) - 1})
    return {"cases": out_cases, "alerts": out_alerts, "graph": graph.source}


def attach(case_id: str, inc: dict, graph: topology.Graph, by: str) -> tuple[int, dict]:
    """Operator adds an open alert to this case (from the tie box). Refused while the case is being worked on."""
    if not CASE_ID.fullmatch(case_id):
        return 400, {"error": "case ids look like C-10261403-ab12"}
    try:
        c = cs.load(case_id)
    except (OSError, ValueError):
        return 404, {"error": "no such case"}
    if c["state"] in BUSY or c["state"] == "closed":
        return 409, {"error": f"case {case_id} is {c['state'].replace('_', ' ')}; alerts can be added once it has concluded and before it closes"}
    if inc["incident_id"] in {i.get("incident_id") for i in c["incidents"]}:
        return 200, {"ok": True, "case_id": case_id}
    svcs = incident_services(inc)
    p, rel = relation(case_services(c), svcs, graph)
    c["incidents"].append(dict(inc, services=svcs, joined={"rule": "added", "path": p or [], "hops": len(p) - 1 if p else None,
                                                           "graph": graph.source, "by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
    if c.get("investigation"):
        c.setdefault("unreviewed_alerts", []).append(inc.get("detector"))
    c["topology"] = graph.summary(case_services(c))
    cs.save(c)
    emit("sre.case.incident_added", case_id=case_id, detector=inc.get("detector"), incident_id=inc["incident_id"], by=by, path=p or [])
    return 200, {"ok": True, "case_id": case_id, "note": "re-run the RCA (root cause analysis) to investigate the added alert" if c.get("investigation") else ""}


def find_ties(c: dict, cases: list[dict], graph: topology.Graph) -> list[dict]:
    """Other cases (any state, opened within TIE_LOOKBACK_S of this one) on one call path with this case. Skips cases
    of the same alert (a re-run) and merged cases."""
    mine = case_services(c)
    if not mine or c.get("source") == "eval":   # eval replays must not see each other (one state dir, seconds apart)
        return []
    my_ids = {i.get("incident_id") for i in c.get("incidents", [])}
    out = []
    for o in cases:
        if o["id"] == c["id"] or o.get("merged_into") or o.get("source") == "eval" or my_ids & {i.get("incident_id") for i in o.get("incidents", [])}:
            continue
        gap = opened_epoch(c) - opened_epoch(o)
        theirs = case_services(o)
        if abs(gap) > TIE_LOOKBACK_S or not theirs:
            continue
        p, rel = relation(mine, theirs, graph)
        if not p:
            continue
        out.append({"case_id": o["id"], "relation": rel, "path": p, "hops": len(p) - 1, "gap_s": round(gap), "graph": graph.source,
                    "state": o["state"], "detectors": [x.get("detector") for x in o.get("incidents", [])]})
    return out


def _mirror(t: dict, c: dict) -> dict:
    return dict(t, case_id=c["id"], relation=REVERSE[t["relation"]], gap_s=-t["gap_s"], state=c["state"],
                detectors=[x.get("detector") for x in c.get("incidents", [])])


def record_ties(c: dict, graph: topology.Graph) -> list[dict]:
    """Store the ties on this case and, mirrored, on each other case (re-read just before writing). An operator's
    earlier verdict (dismissed / merged) is kept."""
    found = find_ties(c, cs.list_cases(), graph)
    for t in found:
        prev = (c.get("ties") or {}).get(t["case_id"]) or {}
        c.setdefault("ties", {})[t["case_id"]] = dict(t, status=prev.get("status", "suggested"))
        o = cs.load(t["case_id"])
        oprev = (o.get("ties") or {}).get(c["id"]) or {}
        o.setdefault("ties", {})[c["id"]] = dict(_mirror(t, c), status=oprev.get("status", "suggested"))
        cs.save(o)
        if not prev:
            emit("sre.case.tie_suggested", case_id=c["id"], other_case=t["case_id"], relation=t["relation"], path=t["path"],
                 gap_s=t["gap_s"], other_detectors=t["detectors"], other_state=t["state"])
    if found:
        cs.save(c)
    return found


def dismiss(case_id: str, other_id: str, by: str) -> tuple[int, dict]:
    if not (CASE_ID.fullmatch(case_id) and CASE_ID.fullmatch(other_id)):
        return 400, {"error": "case ids look like C-10261403-ab12"}
    try:
        c, o = cs.load(case_id), cs.load(other_id)
    except (OSError, ValueError):
        return 404, {"error": "no such case"}
    if other_id not in (c.get("ties") or {}):
        return 404, {"error": f"case {case_id} has no tie to {other_id}"}
    for x, y in ((c, other_id), (o, case_id)):
        if y in (x.get("ties") or {}):
            x["ties"][y]["status"] = "dismissed"
            cs.save(x)
    emit("sre.case.tie_dismissed", case_id=case_id, other_case=other_id, by=by)
    emit("sre.case.tie_dismissed", case_id=other_id, other_case=case_id, by=by)
    return 200, {"ok": True}


def merge(target_id: str, source_id: str, by: str) -> tuple[int, dict]:
    """Operator merge: the source case's alerts move into the target case and the source case closes. Refused while
    either case is being worked on, and for a source whose proposal is waiting for approval (decide that first)."""
    if not (CASE_ID.fullmatch(target_id) and CASE_ID.fullmatch(source_id)):
        return 400, {"error": "case ids look like C-10261403-ab12"}
    if target_id == source_id:
        return 400, {"error": "a case cannot be merged into itself"}
    try:
        t, s = cs.load(target_id), cs.load(source_id)
    except (OSError, ValueError):
        return 404, {"error": "no such case"}
    tie = (t.get("ties") or {}).get(source_id)
    if not tie:
        return 404, {"error": f"case {target_id} has no tie to {source_id}"}
    if tie.get("status") == "merged" or s.get("merged_into") == target_id:   # a second click: nothing to do
        return 200, {"ok": True, "case_id": target_id, "note": "already merged"}
    for x in (t, s):
        if x["state"] in BUSY:
            return 409, {"error": f"case {x['id']} is still being worked on ({x['state'].replace('_', ' ')}); wait for it to finish"}
    if t["state"] == "closed":
        return 409, {"error": f"case {target_id} is closed; merge the other way round"}
    if s["state"] == "awaiting_approval":
        return 409, {"error": f"case {source_id} has a proposal waiting for approval; approve or reject it first"}
    have = {i.get("incident_id") for i in t["incidents"]}
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for i in s["incidents"]:
        if i.get("incident_id") not in have:
            t["incidents"].append(dict(i, joined={"rule": "merged", "path": tie["path"], "hops": tie["hops"], "gap_s": -tie["gap_s"],
                                                  "graph": tie["graph"], "from_case": source_id, "by": by, "at": at}))
            if t.get("investigation"):   # the brief predates these alerts: the console asks for a re-run
                t.setdefault("unreviewed_alerts", []).append(i.get("detector"))
    t["ties"][source_id]["status"] = "merged"
    t.setdefault("merged_from", []).append(source_id)
    cs.save(t)
    s.update(merged_into=target_id, merged_by=by, merged_at=at)
    if target_id in (s.get("ties") or {}):
        s["ties"][target_id]["status"] = "merged"
    cs.save(s)
    if s["state"] == "proposed":
        cs.transition(s, "escalated", reason=f"merged into {target_id} before an approval was requested")
    if s["state"] != "closed":
        cs.transition(s, "closed", reason=f"merged into {target_id} by {by}")
    emit("sre.case.merged", case_id=target_id, merged_case=source_id, by=by, relation=tie["relation"], path=tie["path"])
    emit("sre.case.merged_away", case_id=source_id, into=target_id, by=by)   # so a console showing the source case redraws
    return 200, {"ok": True, "case_id": target_id,
                 "note": "re-run the RCA (root cause analysis) to investigate the merged alerts together" if t.get("investigation") else ""}
