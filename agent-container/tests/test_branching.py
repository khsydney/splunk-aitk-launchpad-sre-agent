import json
import os
import threading
import time
from types import SimpleNamespace as NS

os.environ["SRE_AGENT_QUIET"] = "1"
os.environ["MOCK_JEV"] = "1"

from sre_agent import branching, investigator  # noqa: E402
from sre_agent.toolset import ToolSet  # noqa: E402

from test_investigator_and_executor import INV, FakeSplunk, _usage  # noqa: E402

OPENED = time.time()
FRESH = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(OPENED - 60))
STALE = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(OPENED - 3600))
METRIC, LOG = "payments_by_outcome_acquirer", "spl_events_by_service"   # bundle sections: metric and log signals


def verdict(v, last_seen, ev, children=()):
    return {"verdict": v, "finding": "f", "component": "acquirer-sim/acq-kbank", "last_seen_utc": last_seen,
            "evidence": [{"signal": "metric" if e == METRIC else "log", "finding": "x", "evidence_id": e} for e in ev], "children": list(children)}


VERDICTS = {
    "H1": verdict("invalidated", FRESH, [METRIC]),
    "H2": verdict("validated", FRESH, [METRIC, LOG], children=["acq-kbank times out for BIN 457173"]),
    "H3": verdict("validated", STALE, [METRIC, LOG]),            # leftover from an earlier act: code must invalidate
    "H4": verdict("validated", "ongoing", [METRIC]),              # one signal only: code must downgrade
    "H2.1": verdict("validated", "ongoing", [METRIC, LOG]),
}


class TreeClient:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.messages = NS(create=self.create)

    def create(self, **kw):
        with self.lock:
            self.requests.append(kw)
        first = kw["messages"][0]["content"]
        if first.startswith("PLAN."):
            body = {"hypotheses": [{"statement": s, "test_plan": "t"} for s in
                                   ("payment-router itself", "a dependency is failing", "earlier release", "saturation")]}
        elif first.startswith("DECIDE."):
            assert "stale" in first and "not corroborated" in first   # the planner sees the code checks
            body = INV
        else:
            nid = first.split("Test hypothesis ")[1].split(":")[0]
            body = VERDICTS[nid]
        return NS(content=[NS(type="text", text=json.dumps(body))], stop_reason="end_turn", model=kw["model"], usage=_usage(1000, 100))


def test_tree_checks_deepens_and_decides(monkeypatch):
    client = TreeClient()
    monkeypatch.setattr(branching, "_client", lambda provider: client)
    case = {"id": "C-tree", "incidents": [{"detector": "payment-router error rate"}], "opened_epoch": OPENED, "opened_at": "now"}
    ts = ToolSet(mcp=None, splunk=FakeSplunk())
    r = branching.investigate_tree(case, "bundle", ts, "anthropic")
    nodes = {n["id"]: n for n in r.investigation["tree"]}
    assert nodes["H1"]["status"] == "invalidated"
    assert nodes["H2"]["status"] == "validated" and nodes["H2.1"]["status"] == "validated" and nodes["H2.1"]["depth"] == 2
    assert nodes["H3"]["status"] == "invalidated" and "stale" in nodes["H3"]["checks"][-1]
    assert nodes["H4"]["status"] == "inconclusive" and "log signal" in nodes["H4"]["checks"][-1]
    assert "H3.1" not in nodes and "H4.1" not in nodes            # only code-validated branches are deepened
    assert r.stats.requests == 1 + 4 + 1 + 1                      # plan, 4 workers, 1 child, decide
    assert r.stats.cost_usd > 0 and "sub-agents" in r.stats.model
    text = branching.render_tree(r.investigation["tree"])
    assert "H2.1" in text and "✗ invalidated (stale" in text


def test_investigate_routes_to_tree_only_when_asked(monkeypatch):
    called = {}
    monkeypatch.setattr(branching, "investigate_tree", lambda *a, **k: called.setdefault("tree", True) or "tree")
    monkeypatch.setenv("SRE_AGENT_METHOD", "tree")
    assert investigator.investigate({"id": "C", "incidents": []}, "b", ToolSet(mcp=None, splunk=FakeSplunk()), provider="anthropic") is True
    monkeypatch.setenv("SRE_AGENT_METHOD", "tree")   # an explicit model (escalation re-run) keeps the single loop
    monkeypatch.setattr(investigator, "_client", lambda provider: (_ for _ in ()).throw(RuntimeError("loop path")))
    try:
        investigator.investigate({"id": "C", "incidents": []}, "b", ToolSet(mcp=None, splunk=FakeSplunk()), provider="anthropic", model="claude-opus-5-5")
    except RuntimeError as e:
        assert "loop path" in str(e)


def test_worker_budget_and_spl_gate():
    ts = branching.WorkerToolSet(mcp=None, splunk=FakeSplunk([1]))
    outs = [ts.dispatch(f"t{i}", "spl_template", {"name": "events_by_service", "window": "-15m"}) for i in range(3)]
    assert "SPL budget exhausted" in outs[2]
    for i in range(3):
        ts.dispatch(f"m{i}", "metric_series", {"metric": "bad metric", "by": [], "rollup": "sum", "window": "-15m", "resolution_ms": 60000})
    assert "tool budget exhausted" in ts.dispatch("x", "spl_template", {"name": "events_by_service", "window": "-15m"})
