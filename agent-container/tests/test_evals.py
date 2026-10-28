import json
import os
import pathlib

import pytest

os.environ["SRE_AGENT_QUIET"] = "1"
os.environ["MOCK_JEV"] = "1"

from sre_agent import audit, engine, evals, recorder  # noqa: E402
from sre_agent import case as cs  # noqa: E402
from sre_agent.acts import EVAL_CASES  # noqa: E402
from sre_agent.o11y_mcp import O11yMCP, ToolResult  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "evals" / "cases"


class LiveMCP:
    """Stands in for the gateway: answers every tool, with private details the recorder must strip."""
    services_summary = O11yMCP.services_summary
    signalflow = O11yMCP.signalflow

    def call(self, name, params):
        if name == "o11y_get_apm_services_summary":
            body = {"services": [{"service": {"name": "payment-router", "link": {"url": "https://app.us1.signalfx.com/#/apm"}},
                                  "requestCount": {"value": 100}, "errorCount": {"value": 30}}]}
        elif name == "o11y_execute_signalflow_program":
            body = {"metadata": {"t1": {"payment.acquirer": "acq-kbank", "k8s.node.name": "ip-10-1-2-3.ap-southeast-1.compute.internal"}},
                    "timeseries": {"1000": {"t1": 5.0}, "2000": {"t1": 9.0}}}
        elif name == "o11y_get_apm_exemplar_traces":
            body = {"items": [{"item": {"traceId": "ab" * 8, "initiatingService": "checkout-api"}}]}
        elif name == "o11y_get_apm_trace_tool":
            body = {"spans": [{"traceID": "ab" * 8, "serviceName": "payment-router", "operationName": "route", "duration": 2500000,
                               "tags": [{"key": "error", "value": "true"}, {"key": "peer.service", "value": "acquirer-sim"},
                                        {"key": "net.peer.ip", "value": "198.51.100.7"}]}]}
        else:
            body = {"image": "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/tuktukpay/x", "lb": "abc-123.elb.ap-southeast-1.amazonaws.com"}
        return ToolResult(name=name, text=json.dumps(body))


class LiveSplunk:
    def splunk_run_query(self, query, earliest_time="-15m", latest_time="now", wait_s=90, max_results=200):
        rows = [{"source": "payment-router", "event": "acquirer.timeout", "count": "42", "host": "198.51.100.1"},
                {"source": "payment-router", "event": "route.failover", "count": "40"}]
        return {"query": query, "results": rows[:max_results], "result_count": len(rows)}


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "_client", None)
    monkeypatch.setattr(audit, "QUIET", True)
    monkeypatch.setattr(engine, "CHAOS_URL", "")
    monkeypatch.setattr(cs, "STATE_DIR", tmp_path / "cases")
    monkeypatch.setattr(evals, "_quiet_sandbox", lambda: str(tmp_path))
    return tmp_path


def _record(tmp_path, name="act1", window="-15m"):
    mcp, splunk = LiveMCP(), LiveSplunk()
    rec = recorder.Recorder(mcp, splunk)
    evals._investigate(EVAL_CASES[name], mcp, splunk, "mock", window)
    evals.probe(mcp, splunk, window)
    fx = rec.fixture({"case": name, "window": window, "recorded_run": {}})
    d = tmp_path / "fx"
    d.mkdir(exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps(fx))
    return d, fx


def test_recording_is_sanitised(sandbox):
    _, fx = _record(sandbox)
    text = json.dumps(fx)
    assert recorder.leaks(text) == [], recorder.leaks(text)
    assert "[ACCOUNT]" in text and "[HOST]" in text and "[IP]" in text
    traces = [c for c in fx["calls"] if c.get("tool") == "o11y_get_apm_trace_tool"]
    assert traces and "net.peer.ip" not in traces[0]["text"]        # shrunk to the tags compact_trace reads
    assert all(json.loads(c["text"]) is not None for c in fx["calls"] if c["kind"] == "mcp")   # still valid JSON


def test_replay_with_mock_scores_act1_pass(sandbox):
    d, _ = _record(sandbox)
    row = evals.run_case("act1", "mock", d)
    assert row["error"] == "" and row["misses"] == 0, row
    assert row["rc_ok"] and row["action_ok"] and row["pass"]
    assert row["action"] == "chaos.flag_off:acquirer_kbank_timeout" and row["evidence"] in ("yes", "no")
    assert "PASS" in evals.table([row])


def test_unrecorded_call_is_a_miss_not_a_crash(sandbox):
    d, fx = _record(sandbox)
    rep = recorder.ReplaySplunk(fx)
    with pytest.raises(recorder.NotRecorded):
        rep.splunk_run_query("search index=tuktukpay | stats count by nothing", "-15m")
    assert len(rep.misses) == 1


def test_scoring_rules():
    act1, act4, base = EVAL_CASES["act1"], EVAL_CASES["act4"], EVAL_CASES["baseline"]
    inv = lambda rc, a: {"root_cause_service": rc, "proposed_action": {"type": a}}  # noqa: E731
    assert evals.score(act1, inv("acquirer-sim", "chaos.flag_off:acquirer_kbank_timeout"), {})["pass"]
    assert not evals.score(act1, inv("payment-router", "chaos.flag_off:acquirer_kbank_timeout"), {})["pass"]   # alerting != root cause
    assert not evals.score(act1, inv("acquirer-sim", "no_action"), {})["pass"]
    assert evals.score(act4, inv("none", "no_action"), {})["pass"]
    assert evals.score(base, inv("none", "inconclusive"), {})["pass"] and evals.score(base, inv("none", "no_action"), {})["pass"]
    assert not evals.score(base, inv("ledger", "chaos.flag_off:ledger_db_slow"), {})["pass"]
    cited = {"root_cause_service": "acquirer-sim", "proposed_action": {"type": "chaos.flag_off:acquirer_kbank_timeout"},
             "evidence": [{"evidence_id": "spl_x"}]}
    assert evals.score(act1, cited, {"sections": {"spl_x": "... acquirer.timeout 42 ..."}})["evidence"] == "yes"
    assert evals.score(act1, cited, {"sections": {"spl_x": "nothing"}})["evidence"] == "no"


def test_every_eval_case_has_ground_truth():
    for a in EVAL_CASES.values():
        assert a.root_cause_services, a.name


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.json")) or [None])
def test_committed_fixtures_hold_nothing_private(path):
    if path is None:
        pytest.skip("no fixtures recorded yet")
    text = path.read_text()
    assert recorder.leaks(text) == [], f"{path.name}: {recorder.leaks(text)}"
    fx = json.loads(text)
    assert fx["case"] in EVAL_CASES and fx["calls"]
