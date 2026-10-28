"""Trigger (section 5.1): one read-only REST poll of open incidents, filtered to OUR detectors, de-duplicated on
(detectorId, dimensions hash), confirmed on two consecutive polls, cooled down per key, correlated into cases."""

from __future__ import annotations

import calendar
import hashlib
import json
import os
import pathlib
import time

import httpx

from .audit import emit
from .case import list_cases, new_case, save
from . import topology
from .ties import case_services, incident_services

REALM = os.getenv("SPLUNK_REALM", "us1").strip()
if not __import__("re").fullmatch(r"[a-z]{2}\d", REALM):
    raise SystemExit("SPLUNK_REALM must look like us1 / au0 (check for an inline comment or a stray value in .env)")
API = os.getenv("SPLUNK_O11Y_API_URL", f"https://api.{REALM}.signalfx.com")
PREFIX = os.getenv("SRE_AGENT_DETECTOR_PREFIX", "TukTukPay [tuktukpay-demo]")
ENV = os.getenv("DEPLOYMENT_ENVIRONMENT", "tuktukpay-demo")
COOLDOWN_S = int(os.getenv("SRE_AGENT_COOLDOWN_S", "900"))
CORRELATION_S = int(os.getenv("SRE_AGENT_CORRELATION_S", "180"))
MAX_OPEN_CASES = int(os.getenv("SRE_AGENT_MAX_OPEN_CASES", "2"))
IGNORED_STATES = {"STOPPED", "MANUALLY_RESOLVED", "CLEARED"}
STATE_FILE = pathlib.Path(os.getenv("SRE_AGENT_STATE_DIR", os.path.expanduser("~/.local/share/tuktukpay-sre-agent"))) / "trigger.json"


def fetch_open_incidents(token: str | None = None) -> list[dict]:
    """One read-only call. The shared org has >10,000 open incidents, so the server-side `query` filter on the
    detector-name prefix (verified: `detectorName:TukTukPay*`, 0.9 s) replaces paging; `ours()` still filters on the
    exact prefix because other kits' detectors (`tuktukpay-team01`) share the first word."""
    token = token or os.environ["SPLUNK_O11Y_TOKEN"]
    word = PREFIX.split(" ")[0]
    out, offset, limit = [], 0, 1000
    with httpx.Client(timeout=60) as c:
        while True:
            r = c.get(f"{API}/v2/incident", params={"includeResolved": "false", "limit": limit, "offset": offset, "query": f"detectorName:{word}*"},
                      headers={"X-SF-TOKEN": token})
            if r.status_code >= 500:   # tolerate a bad page: keep what we have (the next poll retries)
                break
            r.raise_for_status()
            page = r.json()
            out.extend(page)
            if len(page) < limit or offset >= 5000:
                break
            offset += limit
    return out


def ours(incidents: list[dict]) -> list[dict]:
    res = []
    for i in incidents:
        if not str(i.get("detectorName", "")).startswith(PREFIX) or i.get("anomalyState") in IGNORED_STATES:
            continue
        ev = (i.get("events") or [{}])[0]
        dims = {k: (v.get("key") if isinstance(v, dict) else v) for k, v in (ev.get("inputs") or {}).items()}
        key = hashlib.sha256(json.dumps([i.get("detectorId"), dims], sort_keys=True, default=str).encode()).hexdigest()[:16]
        res.append({"key": key, "detector": i["detectorName"], "detector_id": i.get("detectorId"), "incident_id": i["incidentId"],
                    "severity": i.get("severity"), "anomaly_state": i.get("anomalyState"),
                    "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime((ev.get("timestamp") or 0) / 1000)) if ev.get("timestamp") else None,
                    "dimensions": dims})
    return res


def _load_state() -> dict:
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {"seen": {}, "woken": {}}


def _save_state(s: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(s, indent=1))


def poll_once(now: float | None = None, incidents: list[dict] | None = None, graph: topology.Graph | None = None) -> list[dict]:
    """Returns the cases opened or extended by this poll. `incidents` and `graph` may be injected for tests; without a
    graph the cached service map (or the static one) is used. An alert joins an open case of the last CORRELATION_S
    when its services and the case's are on one caller → callee path of at most topology.MAX_HOPS hops."""
    now = now or time.time()
    graph = graph or topology.current_graph()
    st = _load_state()
    current = ours(incidents if incidents is not None else fetch_open_incidents())
    keys_now = {i["key"] for i in current}
    st["seen"] = {k: v for k, v in st["seen"].items() if k in keys_now}   # forget keys that disappeared
    st["woken"] = {k: v for k, v in st["woken"].items() if now - v < COOLDOWN_S}   # cool-down map does not grow forever
    touched = []
    open_cases = [c for c in list_cases(open_only=True)]
    for inc in current:
        k = inc["key"]
        st["seen"][k] = st["seen"].get(k, 0) + 1
        if st["seen"][k] < 2:
            emit("sre.trigger.suppressed", reason="first_sight", detector=inc["detector"], incident_id=inc["incident_id"])
            continue
        last = st["woken"].get(k, 0)
        if now - last < COOLDOWN_S:
            emit("sre.trigger.suppressed", reason="cooldown", detector=inc["detector"], incident_id=inc["incident_id"])
            continue
        attached = False
        inc_svcs = incident_services(inc)
        inc["services"] = inc_svcs
        for c in open_cases:
            opened = c.get("opened_epoch") or calendar.timegm(time.strptime(c["opened_at"], "%Y-%m-%dT%H:%M:%SZ"))
            case_svcs = case_services(c)
            if not inc_svcs or not case_svcs:
                link = {"rule": "unscoped", "path": [], "hops": None}   # no service named anywhere: joins as before
            else:
                p = graph.related(inc_svcs, case_svcs)
                link = {"rule": "same_service" if len(p) == 1 else "call_path", "path": p, "hops": len(p) - 1} if p else None
            if (c["state"] in ("open", "investigating") and c["environment"] == ENV and now - opened <= CORRELATION_S and link
                    and inc["incident_id"] not in [x.get("incident_id") for x in c["incidents"]]):
                inc["joined"] = dict(link, gap_s=round(now - opened), graph=graph.source)
                c["incidents"].append(inc)
                c["topology"] = graph.summary(case_svcs + inc_svcs)
                save(c)
                emit("sre.case.incident_attached", case_id=c["id"], detector=inc["detector"], incident_id=inc["incident_id"],
                     rule=link["rule"], path=link["path"], gap_s=inc["joined"]["gap_s"])
                attached, st["woken"][k] = True, now
                touched.append(c)
                break
        if attached:
            continue
        if len(open_cases) >= MAX_OPEN_CASES:
            emit("sre.trigger.suppressed", reason="max_open_cases", detector=inc["detector"], incident_id=inc["incident_id"])
            continue
        c = new_case(ENV, [inc], source="poll")
        c["topology"] = graph.summary(inc_svcs)
        save(c)
        open_cases.append(c)
        touched.append(c)
        st["woken"][k] = now
    _save_state(st)
    return touched
