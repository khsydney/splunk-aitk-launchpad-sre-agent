"""Agent console: a chat-style web UI (user interface) served by the agent itself on the operator's laptop.

Open alerts → "Triage" → every step streams live (evidence, the model's reasoning summaries, each tool call with its
purpose and result, the conclusion) → follow-up questions → Approve / Reject the proposed action. The same events
still go to the audit index, so the control tower's AI SRE agent page keeps the history.

Security: binds 127.0.0.1 only; a random token printed at start is required to load the page, open a stream and
call any API (application programming interface) endpoint, so another web page in the browser cannot drive the agent;
the approver recorded is the OS (operating system) user via the console. Standard library only.
"""

from __future__ import annotations

import getpass
import json
import os
import queue
import secrets
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import cancel
from . import case as cs
from .audit import emit, subscribe

TOKEN = secrets.token_urlsafe(24)
EVENTS: dict[str, list[dict]] = {}          # case_id → every event seen (replayed to late subscribers)
LISTENERS: dict[str, list[queue.Queue]] = {}
BUNDLES: dict[str, str] = {}                # case_id → evidence bundle text (memory only)
HISTORY: dict[str, list[dict]] = {}         # case_id → follow-up Q&A
LOCK = threading.Lock()
SETTINGS = {"provider": None, "policy": "ask"}
HIDDEN = {"sre.llm.call"}
CHATTING: set[str] = set()                  # case ids with a follow-up question running
RERUN_WORDS = {"rerun", "re-run", "re run", "rerun rca", "re-run rca", "rerun the rca", "re-run the rca", "run again", "investigate again"}
INCIDENTS = {"at": 0.0, "data": None, "error": None}   # refreshed in the background so the page never waits on the API


STATUS = {"at": 0.0, "data": None, "error": None}


def _view_state() -> dict:
    """What the operator cleared from the sidebar (persists across console restarts; nothing is deleted)."""
    p = cs.STATE_DIR.parent / "console-view.json"
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {"cases_cleared_at": 0, "alerts_hidden": []}


def _save_view_state(v: dict) -> None:
    p = cs.STATE_DIR.parent / "console-view.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(v))


def _status_once() -> dict:
    """Numbers for the status strip: approval rate (5 min), checkout-api p90, payment-router error rate, fault flags on."""
    import httpx
    from . import catalogue
    from .o11y_mcp import O11yMCP
    mcp = O11yMCP()
    out = {}
    sf = mcp.signalflow(f"data('tuktukpay.payments.count', filter={catalogue.ENV_FILTER}, rollup='delta').sum(by=['payment.outcome']).publish()", "-5m", "now", 60000)
    tot = {x["dims"].get("payment.outcome", "?"): sum(v for _, v in x["points"] if v) for x in sf["series"]}
    n = sum(tot.values())
    out["approval_pct"] = round(100 * tot.get("approved", 0) / n, 1) if n else None
    out["payments_5m"] = int(n)
    svc = {x["service"]: x for x in mcp.services_summary(os.getenv("DEPLOYMENT_ENVIRONMENT", "tuktukpay-demo"), "-5m")}
    out["checkout_p90_ms"] = round(svc.get("checkout-api", {}).get("p90_ms") or 0)
    out["router_error_pct"] = round(100 * (svc.get("payment-router", {}).get("error_rate") or 0), 1)
    out["unhealthy"] = sorted(k for k, v in svc.items() if v.get("health") not in ("Ok", None))
    chaos = os.getenv("CHAOS_URL", "").rstrip("/")
    if chaos:
        try:
            flags = httpx.get(f"{chaos}/flags", timeout=8).json()
            out["faults_on"] = sorted(k for k, v in flags.items() if isinstance(v, dict) and v.get("enabled") and k in catalogue.FAULT_FLAGS)
            out["load_on"] = sorted(k for k, v in flags.items() if isinstance(v, dict) and v.get("enabled") and k in catalogue.FORBIDDEN_FLAGS)
        except Exception:  # noqa: BLE001
            out["faults_on"] = out["load_on"] = None
    return out


def _refresh_status_forever(every_s: int = 30) -> None:
    from . import topology
    from .o11y_mcp import O11yMCP
    while True:
        try:
            STATUS.update(data=_status_once(), error=None, at=time.time())
        except Exception as e:  # noqa: BLE001
            STATUS.update(error=f"{type(e).__name__}: {e}"[:300], at=time.time())
        try:   # service map for alert ties; cached CACHE_S, so this calls the gateway only every 10 min
            topology.fetch_graph(O11yMCP())
        except Exception:  # noqa: BLE001 — investigations fall back to the static map
            pass
        time.sleep(every_s)


def _refresh_incidents_forever(every_s: int = 20) -> None:
    from .trigger import fetch_open_incidents, ours
    while True:
        try:
            INCIDENTS.update(data=ours(fetch_open_incidents()), error=None, at=time.time())
        except Exception as e:  # noqa: BLE001
            INCIDENTS.update(error=f"{type(e).__name__}: {e}"[:300], at=time.time())
        time.sleep(every_s)


def _on_event(rec: dict) -> None:
    cid = rec.get("case_id")
    if not cid or rec.get("event") in HIDDEN:
        return
    with LOCK:
        EVENTS.setdefault(cid, []).append(rec)
        for q in LISTENERS.get(cid, []):
            q.put(rec)


subscribe(_on_event)


def _clients():
    from .o11y_mcp import O11yMCP
    from .splunk_platform import SplunkPlatform
    return O11yMCP(), SplunkPlatform()


# symptom words → services, so an operator question gets the same per-service evidence (dependencies, exemplar and
# error traces) as an alert; service names typed literally are always picked up too
SYMPTOM_SERVICES = [
    (("card", "acquir", "issuer", "declin", "approval", "timeout", "bin "), ("payment-router", "acquirer-sim")),
    (("checkout", "slow", "latency", "payment fail"), ("checkout-api", "payment-router")),
    (("agent", "mandate", "kya", "amp"), ("checkout-api", "wallet-sim")),
    (("copilot", "token", "llm", "assistant"), ("merchant-copilot",)),
    (("ledger", "settle", "reconcil"), ("ledger",)),
    (("webhook", "callback", "notification"), ("webhook-dispatcher",)),
    (("risk", "fraud"), ("risk-engine",)),
    (("pod", "restart", "crash", "oom", "memory"), ("ledger", "wallet-sim")),
]


def _services_for(question: str) -> list[str]:
    from .catalogue import DEPLOYMENTS
    q = question.lower()
    out = [d for d in DEPLOYMENTS if d in q]
    for words, svcs in SYMPTOM_SERVICES:
        if any(w in q for w in words):
            out += [x for x in svcs if x not in out]
    return out[:3]


def _latest_case_for(incident_id: str, within_s: int = 86400) -> dict | None:
    """Newest case (any state, last 24 h) that covers this incident — Triage opens it instead of re-running the RCA."""
    best = None
    for c in cs.list_cases():
        if any(i.get("incident_id") == incident_id for i in c.get("incidents", [])) and time.time() - float(c.get("opened_epoch") or 0) < within_s:
            if best is None or float(c.get("opened_epoch") or 0) > float(best.get("opened_epoch") or 0):
                best = c
    return best


def _active_case_for(incident_id: str) -> str | None:
    for c in cs.list_cases(open_only=True):
        if c.get("source") == "console" and c["state"] in ("open", "investigating") and any(i.get("incident_id") == incident_id for i in c.get("incidents", [])):
            return c["id"]
    return None


def _start_investigation(incidents: list[dict], force: bool = False) -> str:
    existing = _active_case_for(incidents[0]["incident_id"])
    if existing:   # never two concurrent investigations of one alert, even on Re-run
        return existing
    c = cs.new_case(os.getenv("DEPLOYMENT_ENVIRONMENT", "tuktukpay-demo"), incidents, source="console")

    def run():
        from .engine import run_investigation
        emit("sre.console.starting", case_id=c["id"], note="connecting to Observability Cloud and Splunk")
        try:
            mcp, splunk = _clients()
        except Exception as e:  # noqa: BLE001 — never leave the case silently in `open`
            emit("sre.console.error", case_id=c["id"], error=f"could not start: {type(e).__name__}: {e}"[:300])
            cs.transition(cs.load(c["id"]), "escalated", reason=f"could not connect: {type(e).__name__}"[:200])
            emit("sre.console.done", case_id=c["id"], state="escalated")
            return
        try:
            keep: dict = {}
            run_investigation(c, mcp, splunk, SETTINGS["provider"], SETTINGS["policy"], keep=keep)
            BUNDLES[c["id"]] = keep.get("bundle", "")
        except Exception as e:  # noqa: BLE001 — engine already escalated the case; tell the stream
            emit("sre.console.error", case_id=c["id"], error=f"{type(e).__name__}: {e}"[:300])
        emit("sre.console.done", case_id=c["id"], state=cs.load(c["id"])["state"])
    threading.Thread(target=run, daemon=True).start()
    return c["id"]


def _context(c: dict) -> str:
    return json.dumps({"incidents": c.get("incidents"), "investigation": c.get("investigation"), "decision": {k: (c.get("decision") or {}).get(k) for k in ("action", "requirement", "reasons", "real_world")},
                       "state": c.get("state"), "tool_calls_made": [{k: t.get(k) for k in ("tool", "args", "ok")} for t in (c.get("transcript") or [])][:20]},
                      default=str) + "\n\nEvidence bundle:\n" + BUNDLES.get(c["id"], "(not in memory: the case was investigated outside this console session)")


def _ask(cid: str, question: str) -> None:
    def run():
        from .audit import CURRENT_CASE
        from .investigator import followup
        from .toolset import ToolSet
        CURRENT_CASE.set(cid)
        try:
            c = cs.load(cid)
            mcp, splunk = _clients()
            out = followup(c, _context(c), question, ToolSet(mcp, splunk), HISTORY.get(cid), SETTINGS["provider"])
            if not out.get("stopped"):
                HISTORY.setdefault(cid, []).append({"q": question, "a": out["answer"]})
        except Exception as e:  # noqa: BLE001
            emit("sre.console.error", case_id=cid, error=f"{type(e).__name__}: {e}"[:300])
        finally:
            CHATTING.discard(cid)
            cancel.clear(cid)
            emit("sre.chat.done", case_id=cid)
    cancel.clear(cid)
    CHATTING.add(cid)
    emit("sre.chat.question", case_id=cid, question=question[:1000], by=getpass.getuser())
    threading.Thread(target=run, daemon=True).start()


def _rerun(prev: dict) -> tuple[int, dict]:
    if prev["state"] in ("open", "investigating"):
        return 409, {"error": "this case is still being investigated"}
    emit("sre.case.rerun_requested", case_id=prev["id"], by=getpass.getuser())
    new_id = _start_investigation([dict(i) for i in prev.get("incidents", [])], force=True)
    return 200, {"case_id": new_id, "previous": prev["id"]}


def _stop(cid: str) -> tuple[int, dict]:
    """Ask a running investigation or follow-up of this case to stop at its next checkpoint."""
    try:
        state = cs.load(cid)["state"]
    except (OSError, ValueError):
        return 404, {"error": "no such case"}
    by = f"{getpass.getuser()}@console"
    if state in ("remediating", "verifying"):
        return 409, {"error": "an approved action is executing or being verified; it is not stopped halfway (a half-applied change is worse)"}
    if state in ("open", "investigating") or cid in CHATTING:
        cancel.request(cid, by)
        emit("sre.case.stop_requested", case_id=cid, by=by, what="investigation" if state in ("open", "investigating") else "follow-up")
        return 200, {"ok": True}
    return 409, {"error": f"nothing is running for this case (state {state})"}


def _close(cid: str, reason: str) -> tuple[int, dict]:
    """Close a case from the console with a reason. A proposal awaiting approval is rejected first (so the audit trail
    records approval.decided=reject); running work must be stopped first; an executing action cannot be closed."""
    try:
        c = cs.load(cid)
    except (OSError, ValueError):
        return 404, {"error": "no such case"}
    by = f"{getpass.getuser()}@console"
    reason = (reason or "closed in the console")[:300]
    st = c["state"]
    if st == "closed":
        return 200, {"ok": True, "state": "closed"}
    if st in ("open", "investigating") or cid in CHATTING:
        return 409, {"error": "the agent is still working on this case; press Stop first, then close it"}
    if st in ("remediating", "verifying"):
        return 409, {"error": "an approved action is executing or being verified; the case closes when verification ends"}
    if st == "awaiting_approval":
        from .engine import reject
        reject(c, by, reason)
    else:
        if st == "proposed":
            cs.transition(c, "escalated", reason="closed before an approval was requested")
            c = cs.load(cid)
        cs.transition(c, "closed", reason=f"closed by {by}: {reason}")
    emit("sre.case.closed_by_operator", case_id=cid, by=by, from_state=st, reason=reason)
    return 200, {"ok": True, "state": cs.load(cid)["state"]}


def _approve(cid: str, plan_hash: str) -> None:
    def run():
        from .engine import approve_and_execute
        try:
            mcp, splunk = _clients()
            approve_and_execute(cs.load(cid), plan_hash, f"{getpass.getuser()}@console", mcp, splunk)
        except Exception as e:  # noqa: BLE001
            emit("sre.console.error", case_id=cid, error=f"{type(e).__name__}: {e}"[:300])
        emit("sre.console.done", case_id=cid, state=cs.load(cid)["state"])
    threading.Thread(target=run, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    server_version = "sre-agent-console"

    def log_message(self, fmt, *a):  # request log only when SRE_CONSOLE_DEBUG=1 (never logs the query string token)
        if os.getenv("SRE_CONSOLE_DEBUG") == "1":
            print("console:", self.command, self.path.split("?")[0], fmt % a if a else fmt, flush=True)

    # ---- helpers
    def _authed(self, qs) -> bool:
        tok = self.headers.get("X-Console-Token") or (qs.get("t") or [""])[0]
        return secrets.compare_digest(tok, TOKEN)

    def _send(self, code: int, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (json.dumps(body, default=str).encode() if ctype == "application/json" else str(body).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "json" in ctype or "html" in ctype else ""))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 20000:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    # ---- routes
    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            if not self._authed(qs):
                return self._send(403, "Open the URL printed by `sre_agent console` (it carries the access token).", "text/plain")
            from .console_page import page
            return self._send(200, page(TOKEN).encode(), "text/html")
        if not self._authed(qs):
            return self._send(403, {"error": "missing or wrong console token"})
        if u.path == "/api/incidents":
            for _ in range(150):   # first call after start: wait up to 15 s for the background refresh
                if INCIDENTS["data"] is not None or INCIDENTS["error"]:
                    break
                time.sleep(0.1)
            if INCIDENTS["data"] is None:
                return self._send(502 if INCIDENTS["error"] else 503, {"error": INCIDENTS["error"] or "still loading open incidents"})
            rows, hidden = [], set(_view_state().get("alerts_hidden") or [])
            for i in INCIDENTS["data"]:
                if i["incident_id"] in hidden:
                    continue
                c = _latest_case_for(i["incident_id"])
                rows.append(dict(i, case_id=c["id"] if c else None, case_state=c["state"] if c else None))
            return self._send(200, {"incidents": rows, "hidden": len(INCIDENTS["data"]) - len(rows), "age_s": round(time.time() - INCIDENTS["at"], 1), "error": INCIDENTS["error"]})
        if u.path == "/api/status":
            return self._send(200, {"status": STATUS["data"], "age_s": round(time.time() - STATUS["at"], 1) if STATUS["at"] else None, "error": STATUS["error"],
                                    "open_alerts": len(INCIDENTS["data"] or [])})
        if u.path == "/api/cases":
            cut = float(_view_state().get("cases_cleared_at") or 0)
            every = cs.list_cases()
            shown = [c for c in every if c["state"] in cs.ACTIVE_STATES or float(c.get("opened_epoch") or 0) >= cut]   # pending work never hides
            rows = [{k: c.get(k) for k in ("id", "state", "opened_at", "source")} | {"detectors": [i.get("detector") for i in c.get("incidents", [])],
                     "action": ((c.get("decision") or {}).get("action")), "merged_into": c.get("merged_into"), "merged_from": c.get("merged_from") or []} for c in shown][-30:][::-1]
            return self._send(200, {"cases": rows, "hidden": len(every) - len(shown), "settings": SETTINGS})
        if u.path.startswith("/api/ties/"):
            from . import ties, topology
            try:
                c = cs.load(u.path.rsplit("/", 1)[1])
            except (OSError, ValueError):
                return self._send(404, {"error": "no such case"})
            return self._send(200, ties.view(c, INCIDENTS["data"], topology.current_graph(), _latest_case_for))
        if u.path.startswith("/api/case/"):
            try:
                c = cs.load(u.path.rsplit("/", 1)[1])
                from .engine import _page_team
                return self._send(200, dict(c, page_team=_page_team((c.get("investigation") or {}).get("root_cause_service"), [i.get("detector", "") for i in c.get("incidents", [])])))
            except (OSError, ValueError):
                return self._send(404, {"error": "no such case"})
        if u.path.startswith("/api/stream/"):
            return self._stream(u.path.rsplit("/", 1)[1])
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if not self._authed(parse_qs(u.query)):
            return self._send(403, {"error": "missing or wrong console token"})
        b = self._body()
        if u.path == "/api/investigate" and str(b.get("question", "")).strip():
            q = str(b["question"]).strip()[:500]
            svcs = _services_for(q)
            qid = "manual-q-" + secrets.token_hex(4)   # "manual-" → no live incident to corroborate, so never auto-remediated
            hint = f" [services in scope: {', '.join(svcs)}]" if svcs else ""
            return self._send(200, {"case_id": _start_investigation([{"detector": f"Reported symptom (operator question): {q}{hint}", "incident_id": qid,
                                                                       "severity": "Question", "anomaly_state": "REPORTED", "since": None}])})
        if u.path == "/api/investigate":
            from .trigger import fetch_open_incidents, ours
            live = INCIDENTS["data"] if INCIDENTS["data"] is not None else ours(fetch_open_incidents())
            pick = [i for i in live if i["incident_id"] == b.get("incident_id")]
            if not pick:
                return self._send(404, {"error": "that incident is no longer open"})
            prior = _latest_case_for(pick[0]["incident_id"])
            if prior and not b.get("rerun"):   # Triage on an investigated alert opens its case; re-running is explicit
                return self._send(200, {"case_id": prior["id"], "existing": True})
            return self._send(200, {"case_id": _start_investigation(pick)})
        if u.path == "/api/rerun":
            try:
                prev = cs.load(b.get("case_id", ""))
            except (OSError, ValueError):
                return self._send(404, {"error": "no such case"})
            return self._send(*_rerun(prev))
        if u.path == "/api/stop":
            return self._send(*_stop(str(b.get("case_id", ""))))
        if u.path == "/api/page":
            try:
                c = cs.load(b.get("case_id", ""))
            except (OSError, ValueError):
                return self._send(404, {"error": "no such case"})
            from .engine import _page_team
            inv = c.get("investigation") or {}
            team = _page_team(inv.get("root_cause_service"), [i.get("detector", "") for i in c.get("incidents", [])])
            emit("sre.case.paged", case_id=c["id"], team=team, by=getpass.getuser(), summary=str(inv.get("summary") or inv.get("narrative") or "")[:400],
                 note="simulated page: no paging integration (PagerDuty / Slack / ServiceNow) is connected in the kit; recorded in the audit trail")
            return self._send(200, {"ok": True, "team": team})
        if u.path == "/api/close":
            return self._send(*_close(str(b.get("case_id", "")), str(b.get("reason") or "").strip()))
        if u.path == "/api/ack":
            try:
                c = cs.load(b.get("case_id", ""))
            except (OSError, ValueError):
                return self._send(404, {"error": "no such case"})
            note = str(b.get("note") or "acknowledged in the console")[:300]
            emit("sre.case.acknowledged", case_id=c["id"], by=getpass.getuser(), note=note)
            if c["state"] not in ("closed", "open", "investigating", "remediating", "verifying"):
                cs.transition(c, "closed", reason=f"acknowledged by {getpass.getuser()}@console: {note}")
            return self._send(200, {"ok": True, "state": cs.load(c["id"])["state"]})
        if u.path == "/api/ask":
            if not b.get("case_id") or not str(b.get("question", "")).strip():
                return self._send(400, {"error": "case_id and question are required"})
            try:
                st = cs.load(b["case_id"]).get("state")
            except (OSError, ValueError):
                return self._send(404, {"error": "no such case"})
            if st in ("open", "investigating"):
                emit("sre.console.error", case_id=b["case_id"], error="The investigation is still running; ask again when the conclusion appears.")
                return self._send(409, {"error": "investigation still running"})
            if b["case_id"] in CHATTING:
                return self._send(409, {"error": "a follow-up question is still running; wait for it or press Stop"})
            q = str(b["question"]).strip()
            if q.lower().strip(" .!?") in RERUN_WORDS:   # typed "rerun" means the Re-run button, not a question to the model
                code, out = _rerun(cs.load(b["case_id"]))
                return self._send(code, out)
            _ask(b["case_id"], q)
            return self._send(200, {"ok": True})
        if u.path in ("/api/clear", "/api/unclear"):
            what, v = str(b.get("what", "")), _view_state()
            if what not in ("cases", "alerts"):
                return self._send(400, {"error": "what must be cases or alerts"})
            if what == "cases":
                v["cases_cleared_at"] = time.time() if u.path == "/api/clear" else 0
            else:
                v["alerts_hidden"] = [i["incident_id"] for i in (INCIDENTS["data"] or [])] if u.path == "/api/clear" else []
            _save_view_state(v)
            emit("sre.console.view_cleared" if u.path == "/api/clear" else "sre.console.view_restored", what=what, by=getpass.getuser())
            return self._send(200, {"ok": True})
        if u.path == "/api/tie/attach":
            from . import ties, topology
            pick = [i for i in (INCIDENTS["data"] or []) if i["incident_id"] == b.get("incident_id")]
            if not pick:
                return self._send(404, {"error": "that alert is no longer open"})
            owner = _latest_case_for(pick[0]["incident_id"])
            if owner and owner["id"] != b.get("case_id") and owner["state"] in cs.ACTIVE_STATES:
                return self._send(409, {"error": f"that alert already belongs to active case {owner['id']}"})
            return self._send(*ties.attach(str(b.get("case_id", "")), pick[0], topology.current_graph(), f"{getpass.getuser()}@console"))
        if u.path in ("/api/tie/merge", "/api/tie/dismiss"):
            from . import ties
            cid, other = str(b.get("case_id", "")), str(b.get("other_case_id", ""))
            for x in (cid, other):
                if x and (x in CHATTING):
                    return self._send(409, {"error": f"a follow-up question is still running on case {x}; wait for it or press Stop"})
            by = f"{getpass.getuser()}@console"
            return self._send(*(ties.merge(cid, other, by) if u.path.endswith("merge") else ties.dismiss(cid, other, by)))
        if u.path == "/api/approve":
            _approve(b.get("case_id", ""), b.get("plan_hash", ""))
            return self._send(200, {"ok": True})
        if u.path == "/api/reject":
            from .engine import reject
            try:
                reject(cs.load(b.get("case_id", "")), f"{getpass.getuser()}@console", str(b.get("reason") or "rejected in the console")[:300])
                return self._send(200, {"ok": True})
            except Exception as e:  # noqa: BLE001
                return self._send(409, {"error": str(e)[:300]})
        return self._send(404, {"error": "not found"})

    def _stream(self, cid: str):
        q: queue.Queue = queue.Queue()
        with LOCK:
            backlog = list(EVENTS.get(cid, []))
            LISTENERS.setdefault(cid, []).append(q)
        # a case that started before this console session (no `opened` event seen here): load its stored result first,
        # then whatever happened to it in this session (e.g. a rejection), so the brief is never stuck on "Investigating…"
        if not any(r.get("event") == "sre.case.opened" for r in backlog):
            try:
                c = cs.load(cid)
                from .engine import _page_team
                backlog = [{"event": "sre.console.history", "case_id": cid, "case": c,
                            "page_team": _page_team((c.get("investigation") or {}).get("root_cause_service"), [i.get("detector", "") for i in c.get("incidents", [])])}] + backlog
            except (OSError, ValueError):
                pass
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            for rec in backlog:
                self.wfile.write(f"data: {json.dumps(rec, default=str)}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    rec = q.get(timeout=15)
                    self.wfile.write(f"data: {json.dumps(rec, default=str)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with LOCK:
                if q in LISTENERS.get(cid, []):
                    LISTENERS[cid].remove(q)


def _sweep_abandoned(max_age_s: int = 300) -> list[str]:
    """Console cases left in `open` (the run never started: the console stopped or a connection hung) are closed
    with a reason, so they do not count toward the poller's open-case cap."""
    closed = []
    for c in cs.list_cases(open_only=True):
        if c.get("source") != "console" or time.time() - float(c.get("opened_epoch") or 0) <= max_age_s:
            continue
        if c["state"] == "open":
            cs.transition(c, "closed", reason="abandoned: the console stopped before the investigation started")
            closed.append(c["id"])
        elif c["state"] == "investigating":   # the console stopped mid-run: no result, a human decides
            cs.transition(c, "escalated", reason="abandoned: the console stopped during the investigation (no result)")
            closed.append(c["id"])
    return closed


def serve(port: int, provider: str | None, policy: str) -> None:
    SETTINGS.update(provider=provider or os.getenv("SRE_AGENT_PROVIDER", "mock"), policy=policy)
    swept = _sweep_abandoned()
    if swept:
        print("closed abandoned console cases:", ", ".join(swept), flush=True)
    threading.Thread(target=_refresh_incidents_forever, daemon=True).start()
    threading.Thread(target=_refresh_status_forever, daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Agent console (provider={SETTINGS['provider']}, policy={policy}) — open:\n  http://127.0.0.1:{port}/?t={TOKEN}\nCtrl-C to stop.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
