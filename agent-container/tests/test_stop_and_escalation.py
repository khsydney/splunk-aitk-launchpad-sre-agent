import json
import os
import threading
import urllib.error
import urllib.request
from types import SimpleNamespace as NS

import pytest

os.environ["SRE_AGENT_QUIET"] = "1"
os.environ["MOCK_JEV"] = "1"

from sre_agent import audit, cancel, engine, investigator  # noqa: E402
from sre_agent import case as cs  # noqa: E402
from sre_agent.investigator import Result, RunStats  # noqa: E402

INC = [{"detector": "TukTukPay [tuktukpay-demo] payment-router error rate above 5%", "incident_id": "manual-x"}]


class Splunk:
    """Answers every query; can ask for a stop on its Nth call (simulates the operator pressing Stop mid-run)."""
    def __init__(self, stop_on=None, cid=None):
        self.n, self.stop_on, self.cid = 0, stop_on, cid

    def splunk_run_query(self, q, earliest_time="-15m", **_):
        self.n += 1
        if self.stop_on and self.n == self.stop_on:
            cancel.request(self.cid, "tester@console")
        return {"query": q, "results": [{"source": "payment-router", "event": "acquirer.timeout", "count": "5"}], "result_count": 1}


class MCP:
    def services_summary(self, *a, **k):
        return []

    def signalflow(self, *a, **k):
        return {"series": []}

    def call(self, *a, **k):
        return NS(json=lambda: {}, text="{}", is_error=False)


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "STATE_DIR", tmp_path / "cases")
    monkeypatch.setattr(engine, "CHAOS_URL", "")
    seen = []
    monkeypatch.setattr(audit, "_SUBSCRIBERS", [seen.append])
    return seen


def test_stop_during_evidence_closes_case_without_a_proposal(sandbox):
    c = cs.new_case("tuktukpay-demo", INC, source="console")
    c = engine.run_investigation(c, MCP(), Splunk(stop_on=1, cid=c["id"]), "mock", "ask")
    assert c["state"] == "closed" and c.get("decision") is None
    assert "stopped by tester@console during evidence collection" in c["history"][-1]["reason"]
    ev = [e for e in sandbox if e["event"] == "sre.case.stopped"]
    assert ev and ev[0]["by"] == "tester@console" and cancel.requested(c["id"]) is None   # cleared afterwards


def test_stale_stop_request_does_not_kill_a_new_run(sandbox):
    c = cs.new_case("tuktukpay-demo", INC, source="console")
    cancel.request(c["id"], "old")
    c = engine.run_investigation(c, MCP(), Splunk(), "mock", "ask")
    assert c["state"] != "closed" or "stopped" not in str(c["history"][-1].get("reason"))


def _usage():
    return NS(input_tokens=1000, output_tokens=100, cache_read_input_tokens=0, cache_creation_input_tokens=0)


class Client:
    def __init__(self, responses, on_call=None):
        self.responses, self.on_call, self.n = list(responses), on_call, 0
        self.messages = NS(create=self.create)

    def create(self, **kw):
        self.n += 1
        if self.on_call:
            self.on_call(self.n)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _tool_turn():
    return NS(stop_reason="tool_use", model="m", usage=_usage(),
              content=[NS(type="tool_use", id="t1", name="services_summary", input={"why": "w", "window": "-15m"})])


def test_stop_between_model_calls_reports_spend(monkeypatch):
    from sre_agent.toolset import ToolSet
    cid = "C-stop-1"
    cancel.clear(cid)
    cl = Client([_tool_turn(), _tool_turn()], on_call=lambda n: cancel.request(cid, "op") if n == 1 else None)
    monkeypatch.setattr(investigator, "_client", lambda p: cl)
    with pytest.raises(cancel.Stopped) as ex:
        investigator.investigate({"id": cid, "incidents": []}, "bundle", ToolSet(MCP(), None), "anthropic", model="claude-sonnet-5-5")
    assert cl.n == 1 and ex.value.stats.requests == 1 and ex.value.stats.cost_usd > 0
    assert ex.value.stage.startswith("tool call services_summary")   # stopped before the tool ran
    cancel.clear(cid)


class Err403(Exception):
    status_code = 403


def test_one_retry_on_403(monkeypatch):
    monkeypatch.setattr(investigator, "RETRY_403_AFTER_S", 0)
    ok = NS(stop_reason="end_turn", model="m", usage=_usage(), content=[NS(type="text", text="{}")])
    cl = Client([Err403("Request not allowed"), ok])
    assert investigator._create(cl, "C-1", model="m") is ok and cl.n == 2
    cl = Client([Err403("no"), Err403("no again")])
    with pytest.raises(Err403):
        investigator._create(cl, "C-1", model="m")


def test_failed_escalation_keeps_first_answer(sandbox, monkeypatch):
    first = {"root_cause_service": "acquirer-sim", "failure_mode": "dependency_degraded", "confidence": 0.5, "hypotheses": [],
             "proposed_action": {"type": "inconclusive", "rationale": "thin evidence"}, "blast_radius": "x", "narrative": "first answer"}
    calls = []

    def fake_investigate(c, bundle, toolset, provider, model=None, effort=None):
        calls.append(model)
        if model:   # the escalation re-run
            raise Err403("Request not allowed")
        return Result(dict(first), RunStats(provider="anthropic", model="claude-sonnet-5-5", cost_usd=0.05, requests=1))
    monkeypatch.setattr(engine, "investigate", fake_investigate)
    c = cs.new_case("tuktukpay-demo", INC, source="console")
    c = engine.run_investigation(c, MCP(), Splunk(), "anthropic", "ask")
    assert calls == [None, "claude-opus-5-5"]
    assert c["investigation"]["narrative"] == "first answer" and "failed" in c["investigation"]["escalation_error"]
    assert c["state"] == "inconclusive"   # the first answer decides, not an error escalation
    assert [e for e in sandbox if e["event"] == "sre.case.escalation_failed"]
    inv_ev = [e for e in sandbox if e["event"] == "sre.case.investigated"][0]
    assert "claude-opus-5-5" in inv_ev["escalation_error"]


def _post(base, path, body):
    from sre_agent import console
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"X-Console-Token": console.TOKEN, "Content-Type": "application/json"})
    try:
        return 200, json.loads(urllib.request.urlopen(req, timeout=5).read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_console_stop_and_typed_rerun(sandbox, monkeypatch):
    from http.server import ThreadingHTTPServer
    from sre_agent import console
    started = []
    monkeypatch.setattr(console, "_start_investigation", lambda incs, force=False: started.append(incs) or "C-new")
    running = cs.new_case("tuktukpay-demo", INC, source="console"); cs.transition(running, "investigating")
    executing = cs.new_case("tuktukpay-demo", INC, source="console")
    for st in ("investigating", "proposed", "awaiting_approval", "remediating"):
        cs.transition(executing, st)
    done = cs.new_case("tuktukpay-demo", INC, source="console")
    for st in ("investigating", "inconclusive"):
        cs.transition(done, st)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        assert _post(base, "/api/stop", {"case_id": running["id"]})[0] == 200
        assert cancel.requested(running["id"]).endswith("@console")
        code, body = _post(base, "/api/stop", {"case_id": executing["id"]})
        assert code == 409 and "not stopped halfway" in body["error"] and not cancel.requested(executing["id"])
        assert _post(base, "/api/stop", {"case_id": done["id"]})[0] == 409            # nothing running
        req = urllib.request.Request(base + "/api/stop", data=b'{"case_id":"x"}', method="POST")
        with pytest.raises(urllib.error.HTTPError):                                 # token still required
            urllib.request.urlopen(req, timeout=5)
        code, body = _post(base, "/api/ask", {"case_id": done["id"], "question": "Rerun"})
        assert code == 200 and body["case_id"] == "C-new" and started                # typed rerun = the Re-run button
        page = urllib.request.urlopen(base + "/?t=" + console.TOKEN, timeout=5).read().decode()
        assert 'id="stop"' in page and "renderEnd" in page
    finally:
        srv.shutdown()
        cancel.clear(running["id"])


def test_console_close_case(sandbox):
    from http.server import ThreadingHTTPServer
    from sre_agent import console

    def case_in(*states):
        c = cs.new_case("tuktukpay-demo", INC, source="console")
        for st in states:
            cs.transition(c, st)
        return c
    pending = case_in("investigating", "proposed", "awaiting_approval")
    escalated = case_in("investigating", "escalated")
    running = case_in("investigating")
    executing = case_in("investigating", "proposed", "awaiting_approval", "remediating")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        assert _post(base, "/api/close", {"case_id": pending["id"], "reason": "stale alert"}) == (200, {"ok": True, "state": "closed"})
        rej = [e for e in sandbox if e["event"] == "approval.decided" and e["case_id"] == pending["id"]]
        assert rej and rej[0]["decision"] == "reject" and rej[0]["reason"] == "stale alert"     # pending proposal rejected on record
        assert _post(base, "/api/close", {"case_id": escalated["id"]})[1]["state"] == "closed"
        assert "closed by" in cs.load(escalated["id"])["history"][-1]["reason"]
        assert _post(base, "/api/close", {"case_id": running["id"]})[0] == 409                 # press Stop first
        assert _post(base, "/api/close", {"case_id": executing["id"]})[0] == 409               # never mid-execution
        assert [e for e in sandbox if e["event"] == "sre.case.closed_by_operator"]
    finally:
        srv.shutdown()


def test_stream_loads_stored_result_for_a_case_from_before_this_session(sandbox, monkeypatch):
    from http.server import ThreadingHTTPServer
    from sre_agent import console
    c = cs.new_case("tuktukpay-demo", INC, source="console")
    cs.transition(c, "investigating"); cs.transition(c, "inconclusive")
    c = cs.load(c["id"]); c["investigation"] = {"summary": "stored answer"}; cs.save(c)
    monkeypatch.setitem(console.EVENTS, c["id"], [{"event": "approval.decided", "case_id": c["id"], "decision": "reject"}])   # only this seen here
    srv = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/api/stream/{c['id']}?t={console.TOKEN}", timeout=5)
        first = []
        while len(first) < 2:
            line = r.readline().decode()
            if line.startswith("data: "):
                first.append(json.loads(line[6:]))
        assert first[0]["event"] == "sre.console.history" and first[0]["case"]["investigation"]["summary"] == "stored answer"
        assert first[1]["event"] == "approval.decided"
    finally:
        srv.shutdown()
