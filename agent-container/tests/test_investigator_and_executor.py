import json
import os
import time
from types import SimpleNamespace as NS

import pytest

os.environ["SRE_AGENT_QUIET"] = "1"
os.environ["MOCK_JEV"] = "1"

from sre_agent import catalogue, executor, investigator  # noqa: E402
from sre_agent.cost import estimate_cost  # noqa: E402
from sre_agent.toolset import ToolSet  # noqa: E402


class FakeSplunk:
    def __init__(self, counts=None):
        self.counts = list(counts or [0])
        self.calls = []

    def splunk_run_query(self, q, earliest_time="-15m", **_):
        self.calls.append((q, earliest_time))
        c = self.counts.pop(0) if len(self.counts) > 1 else self.counts[0]
        return {"query": q, "results": [{"count": str(c), "source": "payment-router", "event": "acquirer.timeout"}], "result_count": 1}


def _usage(i=1000, o=100, cr=0, cw=0):
    return NS(input_tokens=i, output_tokens=o, cache_read_input_tokens=cr, cache_creation_input_tokens=cw)


def _block_text(t):
    return NS(type="text", text=t)


def _block_tool(id_, name, inp):
    return NS(type="tool_use", id=id_, name=name, input=inp)


INV = {"root_cause_service": "acquirer-sim", "failure_mode": "dependency_degraded", "confidence": 1.7, "hypotheses": [],
       "proposed_action": {"type": "chaos.flag_off:acquirer_kbank_timeout", "rationale": "r"}, "blast_radius": "x", "narrative": "n",
       "summary": "s", "impact": "i", "started_at": "unknown", "cause_chain": ["c"], "ruled_out": [],
       "evidence": [{"signal": "metric", "finding": "f", "evidence_id": "payments_by_outcome_acquirer"},
                    {"signal": "log", "finding": "f", "evidence_id": "spl_events_by_service"}]}


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    class messages:  # noqa: N801
        pass

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return self.responses.pop(0)


def _client(responses):
    c = FakeClient(responses)
    c.messages = NS(create=c.create)
    return c


def test_investigator_tool_round_trip_and_cost(monkeypatch):
    responses = [
        NS(content=[_block_tool("tu1", "spl_template", {"name": "events_by_service", "window": "-15m"})], stop_reason="tool_use", model="claude-opus-5-5", usage=_usage(5000, 200, 0, 4000)),
        NS(content=[_block_text(json.dumps(INV))], stop_reason="end_turn", model="claude-opus-5-5", usage=_usage(500, 300, 4000, 0)),
    ]
    client = _client(responses)
    monkeypatch.setattr(investigator, "_client", lambda provider: client)
    ts = ToolSet(mcp=None, splunk=FakeSplunk([3]))
    r = investigator.investigate({"id": "C-t", "incidents": []}, "bundle", ts, provider="anthropic", model="claude-opus-5-5")
    assert r.stats.requests == 2 and r.investigation["proposed_action"]["type"].endswith("acquirer_kbank_timeout")
    assert r.investigation["confidence"] == 1.0                       # clamped
    second = client.requests[1]["messages"]
    assert second[1]["role"] == "assistant" and second[2]["content"][0]["type"] == "tool_result" and second[2]["content"][0]["tool_use_id"] == "tu1"
    first = client.requests[0]
    assert first["system"][0]["cache_control"] == {"type": "ephemeral"} and first["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert all(t["strict"] for t in first["tools"]) and "minimum" not in json.dumps(first["output_config"])
    assert r.stats.cache_read_tokens == 4000 and r.stats.cache_write_tokens == 4000
    assert r.stats.cost_usd == estimate_cost("claude-opus-5-5", 5500, 500, 4000, 4000) and r.stats.price_known


def test_investigator_refusal_and_unparsable_are_inconclusive(monkeypatch):
    for resp in (NS(content=[], stop_reason="refusal", model="m", usage=_usage()),
                 NS(content=[_block_text("sorry, no json")], stop_reason="end_turn", model="m", usage=_usage())):
        monkeypatch.setattr(investigator, "_client", lambda provider, resp=resp: _client([resp]))
        r = investigator.investigate({"id": "C-t", "incidents": []}, "b", ToolSet(mcp=None, splunk=FakeSplunk()), provider="anthropic", model="claude-sonnet-5-5")
        assert r.investigation["proposed_action"]["type"] == "inconclusive"


def test_investigator_budget_forbids_further_tool_calls(monkeypatch):
    monkeypatch.setattr(investigator, "MAX_INPUT_TOKENS", 100)
    responses = [
        NS(content=[_block_tool("tu1", "spl_template", {"name": "events_by_service", "window": "-15m"})], stop_reason="tool_use", model="m", usage=_usage(500, 10)),
        NS(content=[_block_text(json.dumps(INV))], stop_reason="end_turn", model="m", usage=_usage(10, 10)),
    ]
    client = _client(responses)
    monkeypatch.setattr(investigator, "_client", lambda provider: client)
    r = investigator.investigate({"id": "C-t", "incidents": []}, "b", ToolSet(mcp=None, splunk=FakeSplunk()), provider="anthropic", model="claude-sonnet-5-5")
    assert r.stats.budget_hit == "tokens" and client.requests[1]["tools"] and client.requests[1]["tool_choice"] == {"type": "none"}
    assert "tool_choice" not in client.requests[0]
    assert any(b.get("type") == "text" and "Budget exhausted" in b["text"] for b in client.requests[1]["messages"][-1]["content"])


def test_cost_table_and_unknown_model():
    assert estimate_cost("claude-opus-5-5", 1_000_000, 0) == 4.0 and estimate_cost("claude-haiku-5-5", 0, 1_000_000) == 0.5
    from sre_agent.cost import price_row
    assert price_row("claude-opus-5-5")[0][0] == 4.0 and price_row("mystery")[1] is False


def test_verify_window_starts_after_fix_and_needs_two_passes(monkeypatch):
    monkeypatch.setattr(executor.time, "sleep", lambda s: None)
    v = catalogue.ACTIONS["chaos.flag_off:acquirer_kbank_timeout"].verification
    sp = FakeSplunk([5, 0, 0])
    ok, last, note = executor.verify(v, None, sp, t_fix=time.time() - 100, grace_s=30, window_s=30)
    assert ok is True and last == 0 and len(sp.calls) == 3
    assert all(str(int(time.time()) - 31) <= e <= str(int(time.time())) for _, e in sp.calls)   # epoch starts after the fix


def test_execute_refuses_when_state_changed(monkeypatch):
    monkeypatch.setattr(executor, "read_flags", lambda url=None: {"acquirer_kbank_timeout": {"enabled": False}})
    d = {"action": "chaos.flag_off:acquirer_kbank_timeout", "plan_hash": "h", "request_preview": {}}
    out = executor.execute(d, "C-x", "tester", None, None)
    assert not out.executed and any("state changed" in x for x in out.detail)


def test_should_escalate_rules():
    good = dict(INV, confidence=0.9, hypotheses=[{"statement": "s", "status": "validated", "evidence_ids": [], "independent": False}])
    assert investigator.should_escalate(good) == ""
    assert "inconclusive" in investigator.should_escalate(dict(good, proposed_action={"type": "inconclusive", "rationale": ""}))
    assert "confidence" in investigator.should_escalate(dict(good, confidence=0.5))
    assert "alternative" in investigator.should_escalate(dict(good, confidence=0.8, hypotheses=[{"statement": "s", "status": "inconclusive", "evidence_ids": [], "independent": False}]))
    assert investigator.DEFAULT_MODEL == "claude-sonnet-5-5"


def test_evidence_gap_uses_ids_not_labels():
    log_only = dict(INV, evidence=[{"signal": "metric", "finding": "mislabelled", "evidence_id": "spl_errors_by_type"}])
    assert "metric or trace" in investigator.evidence_gap(log_only)
    assert investigator.evidence_gap(INV) == ""
    tool_log = [{"id": "tu9", "tool": "metric_series"}]
    assert investigator.evidence_gap(dict(INV, evidence=[{"signal": "log", "finding": "f", "evidence_id": "spl_x"},
                                                         {"signal": "metric", "finding": "f", "evidence_id": "tu9"}]), tool_log) == ""
    assert investigator.evidence_gap(dict(INV, evidence=[], proposed_action={"type": "no_action", "rationale": ""})) == ""
    assert "log" in investigator.should_escalate(dict(INV, confidence=0.9, evidence_gap="root cause not supported by a log signal"))


def test_evidence_gap_gets_one_corrective_round(monkeypatch):
    weak = dict(INV, evidence=[{"signal": "log", "finding": "f", "evidence_id": "spl_events_by_service"}])
    responses = [NS(content=[_block_text(json.dumps(weak))], stop_reason="end_turn", model="m", usage=_usage()),
                 NS(content=[_block_text(json.dumps(weak))], stop_reason="end_turn", model="m", usage=_usage())]
    client = _client(responses)
    monkeypatch.setattr(investigator, "_client", lambda provider: client)
    r = investigator.investigate({"id": "C-t", "incidents": []}, "b", ToolSet(mcp=None, splunk=FakeSplunk()), provider="anthropic", model="claude-sonnet-5-5")
    assert len(client.requests) == 2 and "Check by code" in client.requests[1]["messages"][-1]["content"]
    assert "metric or trace" in r.investigation["evidence_gap"]          # still weak after one round: kept, escalation reads it


def test_case_message_carries_real_world_actions(monkeypatch):
    client = _client([NS(content=[_block_text(json.dumps(INV))], stop_reason="end_turn", model="m", usage=_usage())])
    monkeypatch.setattr(investigator, "_client", lambda provider: client)
    investigator.investigate({"id": "C-t", "incidents": []}, "b", ToolSet(mcp=None, splunk=FakeSplunk()), provider="anthropic", model="claude-sonnet-5-5")
    first = client.requests[0]["messages"][0]["content"]
    assert "route BIN 457173 / THB off acq-kbank" in first
    assert {"summary", "impact", "started_at", "cause_chain", "evidence", "ruled_out"} <= set(investigator.INVESTIGATION_SCHEMA["required"])


def test_markers_hidden_by_default(monkeypatch):
    from sre_agent import evidence
    assert evidence.MARKERS == "hide" and not evidence.markers_shown(True)
    ts = ToolSet(mcp=None, splunk=FakeSplunk())
    assert ts.marker_mode is False and "hidden" in ts.dispatch("t1", "spl_template", {"why": "w", "name": "config_changes", "window": "-15m"})
    monkeypatch.setattr(evidence, "MARKERS", "show")
    assert evidence.markers_shown(True) and not evidence.markers_shown(False)


def test_compact_trace_keeps_errors_and_slowest():
    from sre_agent.evidence import compact_trace
    spans = [{"traceID": "ab" * 16, "serviceName": f"s{i}", "operationName": "op", "duration": i * 1000, "tags": []} for i in range(30)]
    spans.append({"traceID": "ab" * 16, "serviceName": "payment-router", "operationName": "acq", "duration": 5,
                  "tags": [{"key": "error", "value": True}, {"key": "payment.acquirer", "value": "acq-kbank"}, {"key": "noise", "value": "x"}]})
    t = compact_trace({"spans": spans}, top=5)
    assert t["span_count"] == 31 and len(t["spans"]) == 5
    assert t["spans"][0]["service"] == "payment-router" and t["spans"][0]["payment.acquirer"] == "acq-kbank" and "noise" not in t["spans"][0]
    assert t["spans"][1]["duration_ms"] == 29.0


def test_affected_services_reads_operator_scope():
    from sre_agent.evidence import affected_services
    q = "Reported symptom (operator question): checkout slow [services in scope: ledger, risk-engine, checkout-api]"
    assert affected_services([q])[:3] == ["ledger", "risk-engine", "checkout-api"]
    assert affected_services(["TukTukPay [tuktukpay-demo] payment-router error rate above 5%"]) == ["payment-router"]
    assert affected_services(["x [services in scope: bad name!, risk-engine]"]) == ["risk-engine"]   # malformed hint ignored; name match still applies
    assert affected_services(["x [services in scope: bad name, ledger]"]) == ["ledger"]               # invalid entries dropped one by one
