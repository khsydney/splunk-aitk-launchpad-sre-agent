import pytest
import json
import os
import threading
import time
import urllib.error
import urllib.request

os.environ["SRE_AGENT_QUIET"] = "1"

from sre_agent import audit, catalogue  # noqa: E402
from sre_agent import case as cs  # noqa: E402


def test_mcp_call_events_only_inside_a_case():
    seen = []
    audit.subscribe(seen.append)
    audit.mcp_call("o11y-mcp-gateway", "o11y_x", {"params": {"a": 1}}, time.time(), True, 10)
    assert not [e for e in seen if e["event"] == "sre.mcp.call"]          # no case in context → nothing emitted
    tok = audit.CURRENT_CASE.set("C-test")
    try:
        audit.mcp_call("splunk-mcp-server", "splunk_run_query", {"query": "search index=tuktukpay | stats count"}, time.time() - 0.2, True, 42)
    finally:
        audit.CURRENT_CASE.reset(tok)
    ev = [e for e in seen if e["event"] == "sre.mcp.call"]
    assert ev and ev[-1]["case_id"] == "C-test" and ev[-1]["ms"] >= 150 and "splunk_run_query" == ev[-1]["tool"] and "t" in ev[-1]


def test_owner_map():
    assert catalogue.owner_of("payment-router") == "Acquiring & Routing"
    assert catalogue.owner_of("ledger") == "Ledger & Settlement"
    assert "no owner" in catalogue.owner_of("mystery")


def test_console_requires_token(tmp_path, monkeypatch):
    from http.server import ThreadingHTTPServer
    from sre_agent import console
    monkeypatch.setattr(cs, "STATE_DIR", tmp_path / "cases")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        for path in ("/", "/api/cases", "/api/status"):
            try:
                urllib.request.urlopen(base + path, timeout=5)
                raise AssertionError(path + " served without the token")
            except urllib.error.HTTPError as e:
                assert e.code == 403
        req = urllib.request.Request(base + "/api/investigate", data=b'{"question":"x"}', method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("POST accepted without the token")
        except urllib.error.HTTPError as e:
            assert e.code == 403
        ok = urllib.request.urlopen(urllib.request.Request(base + "/api/cases", headers={"X-Console-Token": console.TOKEN}), timeout=5)
        assert json.loads(ok.read())["cases"] == []
        page = urllib.request.urlopen(base + "/?t=" + console.TOKEN, timeout=5).read().decode()
        assert "War-room brief" in page and console.TOKEN in page
    finally:
        srv.shutdown()


def test_sweep_escalates_cases_abandoned_mid_investigation(tmp_path, monkeypatch):
    from sre_agent import console
    monkeypatch.setattr(cs, "STATE_DIR", tmp_path / "cases")
    c = cs.new_case("tuktukpay-demo", [{"detector": "d", "incident_id": "I9"}], source="console")
    cs.transition(c, "investigating")
    c = cs.load(c["id"]); c["opened_epoch"] = time.time() - 3600; cs.save(c)
    assert console._sweep_abandoned() == [c["id"]] and cs.load(c["id"])["state"] == "escalated"


def _post(base, path, body):
    from sre_agent import console
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"X-Console-Token": console.TOKEN, "Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


def test_triage_opens_existing_case_and_actions(tmp_path, monkeypatch):
    from http.server import ThreadingHTTPServer
    from sre_agent import console
    monkeypatch.setattr(cs, "STATE_DIR", tmp_path / "cases")
    inc = {"detector": "TukTukPay [tuktukpay-demo] copilot guardrail blocked an action", "incident_id": "INC-1", "anomaly_state": "ANOMALOUS"}
    c = cs.new_case("tuktukpay-demo", [inc], source="console")
    cs.transition(c, "investigating"); cs.transition(c, "proposed"); c = cs.load(c["id"])
    c["investigation"] = {"root_cause_service": "merchant-copilot", "summary": "stale alert"}; cs.save(c)
    monkeypatch.setitem(console.INCIDENTS, "data", [inc])
    seen = []
    audit.subscribe(seen.append)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        r = _post(base, "/api/investigate", {"incident_id": "INC-1"})
        assert r == {"case_id": c["id"], "existing": True}                     # no second RCA
        listed = json.loads(urllib.request.urlopen(urllib.request.Request(base + "/api/incidents", headers={"X-Console-Token": console.TOKEN}), timeout=5).read())
        assert listed["incidents"][0]["case_id"] == c["id"]
        assert _post(base, "/api/page", {"case_id": c["id"]})["team"] == "AI Platform"
        assert any(e["event"] == "sre.case.paged" and e["case_id"] == c["id"] for e in seen)
        assert _post(base, "/api/ack", {"case_id": c["id"]})["state"] == "closed"
    finally:
        srv.shutdown()


def test_expected_actions_per_act():
    from sre_agent.acts import ACTS, expected_actions
    assert expected_actions(ACTS["act1"]) == {"chaos.flag_off:acquirer_kbank_timeout"}
    assert expected_actions(ACTS["act4"]) == {"no_action"}            # governance working: explain and close
    assert expected_actions(ACTS["act6"]) == {"chaos.flag_off:ledger_memory_leak", "k8s.rollout_undo:ledger"}
    assert expected_actions(ACTS["act7"]) == {"chaos.flag_off:wallet_crash_loop", "k8s.rollout_undo:wallet-sim"}
    from sre_agent import catalogue
    for a in ACTS.values():   # every expected action exists in the catalogue
        for t in expected_actions(a):
            assert t in catalogue.ACTIONS, t


def test_clear_hides_finished_cases_and_current_alerts_until_show(tmp_path, monkeypatch):
    from http.server import ThreadingHTTPServer
    from sre_agent import console
    monkeypatch.setattr(cs, "STATE_DIR", tmp_path / "cases")
    done = cs.new_case("tuktukpay-demo", [{"detector": "x", "incident_id": "A"}]); cs.transition(done, "closed", reason="test")
    pending = cs.new_case("tuktukpay-demo", [{"detector": "y", "incident_id": "B"}]); cs.transition(pending, "investigating"); cs.transition(pending, "proposed")
    monkeypatch.setitem(console.INCIDENTS, "data", [{"detector": "z", "incident_id": "INC-9", "anomaly_state": "ANOMALOUS"}])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), console.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    get = lambda p: json.loads(urllib.request.urlopen(urllib.request.Request(base + p, headers={"X-Console-Token": console.TOKEN}), timeout=5).read())
    try:
        assert _post(base, "/api/clear", {"what": "cases"}) == {"ok": True} and _post(base, "/api/clear", {"what": "alerts"}) == {"ok": True}
        cases, alerts = get("/api/cases"), get("/api/incidents")
        assert [c["id"] for c in cases["cases"]] == [pending["id"]] and cases["hidden"] == 1      # pending work never hides
        assert alerts["incidents"] == [] and alerts["hidden"] == 1
        monkeypatch.setitem(console.INCIDENTS, "data", console.INCIDENTS["data"] + [{"detector": "z", "incident_id": "INC-10", "anomaly_state": "ANOMALOUS"}])
        assert [i["incident_id"] for i in get("/api/incidents")["incidents"]] == ["INC-10"]           # a new firing shows
        _post(base, "/api/unclear", {"what": "cases"})
        assert get("/api/cases")["hidden"] == 0
        with pytest.raises(urllib.error.HTTPError):
            _post(base, "/api/clear", {"what": "x"})
    finally:
        srv.shutdown()
