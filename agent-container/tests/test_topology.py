import json
import os
import pathlib
import time

import pytest

os.environ["SRE_AGENT_QUIET"] = "1"
os.environ["MOCK_JEV"] = "1"

from sre_agent import case as cs  # noqa: E402
from sre_agent import ties, topology  # noqa: E402
from sre_agent.o11y_mcp import ToolResult  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "evals" / "cases"
PFX = "TukTukPay [tuktukpay-demo] "


# ------------------------------------------------------------------ graph
def test_static_graph_follows_calls_within_the_hop_limit():
    g = topology.static_graph()
    assert g.path("checkout-api", "acquirer-sim", 2) == ["checkout-api", "payment-router", "acquirer-sim"]
    assert g.path("checkout-api", "acquirer-sim", 1) is None
    assert g.path("acquirer-sim", "checkout-api", 2) is None          # edges are directed


def test_related_works_in_either_direction_but_not_for_siblings():
    g = topology.static_graph()
    assert g.related(["wallet-sim"], ["checkout-api"], 2) == ["checkout-api", "wallet-sim"]
    assert g.related(["ledger"], ["ledger"], 2) == ["ledger"]
    assert g.related(["ledger"], ["wallet-sim"], 2) is None           # both called by checkout-api: siblings
    assert g.related(["merchant-copilot"], ["checkout-api"], 2) is None
    assert g.related(["ledger"], ["webhook-dispatcher"], 2) is None   # the queue is not a failure path


def test_downstream_most_are_the_root_cause_candidates():
    g = topology.static_graph()
    assert g.downstream_most(["checkout-api", "payment-router", "acquirer-sim"]) == ["acquirer-sim"]
    assert g.downstream_most(["ledger", "webhook-dispatcher"]) == ["ledger", "webhook-dispatcher"]


class FixtureMCP:
    """Answers o11y_get_apm_service_dependencies from the recorded fixtures, whatever the window."""
    def __init__(self, fail: bool = False):
        self.n, self.fail, self.by = 0, fail, {}
        for f in sorted(FIXTURES.glob("*.json")):
            for c in json.loads(f.read_text())["calls"]:
                if c.get("tool") == "o11y_get_apm_service_dependencies" and not c.get("is_error"):
                    self.by[c["params"]["service_name"]] = c["text"]

    def call(self, name, params):
        self.n += 1
        if self.fail or params["service_name"] not in self.by:
            raise RuntimeError("gateway down")
        return ToolResult(name=name, text=self.by[params["service_name"]])


@pytest.fixture
def fresh_cache(monkeypatch):
    monkeypatch.setattr(topology, "_cache", {"at": 0.0, "graph": None})


def test_edges_from_dependencies_fold_inferred_nodes_and_drop_others():
    payload = {"inboundDependencies": [{"service": {"name": "merchant-storefront"}}],
               "outboundDependencies": [{"service": {"name": "ledger:8084"}}, {"service": {"name": "redis:payments.events"}},
                                        {"service": {"name": "payment-router"}}]}
    assert topology.edges_from_dependencies("checkout-api", payload) == {("checkout-api", "ledger"), ("checkout-api", "payment-router")}


def test_fetch_graph_uses_the_service_map_and_caches_it(fresh_cache):
    m = FixtureMCP()
    g = topology.fetch_graph(m, now=1000.0)
    assert g.source.startswith("service_map") and "acquirer-sim" in g.edges["payment-router"]
    calls = m.n
    assert topology.fetch_graph(m, now=1000.0 + topology.CACHE_S - 1) is g and m.n == calls
    assert topology.current_graph(now=1000.0 + 1) is g
    assert topology.current_graph(now=1000.0 + 3 * topology.CACHE_S).source == "static"   # too old: static map


def test_fetch_graph_falls_back_to_static_after_two_failures(fresh_cache):
    m = FixtureMCP(fail=True)
    g = topology.fetch_graph(m, now=1000.0)
    assert g.source == "static" and m.n == 2


def test_services_from_dimensions_reads_container_pod_and_deployment():
    f = topology.services_from_dimensions
    assert f({"_S1": {"k8s.container.name": "ledger", "k8s.pod.name": "ledger-7c9f8-abcde"}}) == ["ledger"]
    assert f({"_S1": {"k8s.deployment.name": "wallet-sim"}}) == ["wallet-sim"]
    assert f({"_S1": {"k8s.pod.name": "merchant-sim-5d4-xyz"}}) == ["merchant-sim"]   # not merchant-copilot
    assert f({"_S1": {"k8s.container.name": "postgres"}}) == [] and f({}) == []


# ------------------------------------------------------------------ trigger: automatic join
def _inc(name, iid, dims=None):
    return {"detectorName": PFX + name, "detectorId": "D-" + iid, "incidentId": iid, "anomalyState": "ANOMALOUS", "severity": "Major",
            "events": [{"timestamp": 1792472120000, "inputs": {"_S1": {"key": dims or {}}}}]}


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "STATE_DIR", tmp_path / "cases")


@pytest.fixture
def twice(state, tmp_path, monkeypatch):
    from sre_agent import trigger
    monkeypatch.setattr(trigger, "STATE_FILE", tmp_path / "trigger.json")
    g = topology.static_graph()

    def run(now, incs):   # the trigger acts on the second sight
        trigger.poll_once(now, incs, graph=g)
        return trigger.poll_once(now + 30, incs, graph=g)
    return run


def test_act4b_caller_alert_joins_the_callee_case(twice):
    now = time.time()
    a = _inc("wallet-sim error rate above 20%", "I1")
    [c] = twice(now, [a])
    out = twice(now + 60, [a, _inc("agent mandate blocks above 10% of AMP payments", "I2")])
    assert len(out) == 1 and out[0]["id"] == c["id"] and len(cs.list_cases(open_only=True)) == 1
    j = out[0]["incidents"][1]["joined"]
    assert j["rule"] == "call_path" and j["path"] == ["checkout-api", "wallet-sim"] and j["hops"] == 1 and j["graph"] == "static"
    assert out[0]["topology"]["root_candidates"] == ["wallet-sim"]


def test_act5_ledger_and_webhook_stay_separate(twice):
    now = time.time()
    a = _inc("ledger p90 latency above 400ms", "I1")
    [c] = twice(now, [a])
    out = twice(now + 60, [a, _inc("webhook dead-letters", "I2")])
    assert len(out) == 1 and out[0]["id"] != c["id"] and len(cs.list_cases(open_only=True)) == 2


def test_act7_after_act6_wallet_sim_does_not_join_the_leftover_ledger_case(twice):
    now = time.time()
    a = _inc("Kubernetes container restarted", "I1", {"k8s.container.name": "ledger", "k8s.pod.name": "ledger-7c9f8-abcde"})
    [c] = twice(now, [a])
    out = twice(now + 60, [a, _inc("Kubernetes deployment below desired replicas", "I2", {"k8s.deployment.name": "wallet-sim"})])
    assert len(out) == 1 and out[0]["id"] != c["id"]


def test_act2_cpu_alert_joins_by_container_dimension(twice):
    now = time.time()
    a = _inc("risk-engine p90 latency above 100ms", "I1")
    [c] = twice(now, [a])
    out = twice(now + 60, [a, _inc("container CPU at its limit (throttling)", "I2", {"k8s.container.name": "risk-engine"})])
    assert out[0]["id"] == c["id"] and out[0]["incidents"][1]["joined"]["rule"] == "same_service"


def test_alert_without_any_service_keeps_the_old_join(twice):
    now = time.time()
    a = _inc("ledger p90 latency above 400ms", "I1")
    [c] = twice(now, [a])
    out = twice(now + 60, [a, _inc("Kubernetes pod pending", "I2")])
    assert out[0]["id"] == c["id"] and out[0]["incidents"][1]["joined"]["rule"] == "unscoped"


# ------------------------------------------------------------------ possible ties (suggestions)
def _case(detector, iid, state="open", age_s=0, dims=None):
    c = cs.new_case("tuktukpay-demo", [{"detector": PFX + detector, "incident_id": iid, "dimensions": dims or {}}])
    c["opened_epoch"] = time.time() - age_s
    for s in {"open": [], "investigating": ["investigating"], "proposed": ["investigating", "proposed"],
              "awaiting_approval": ["investigating", "proposed", "awaiting_approval"], "resolved": None}[state] or []:
        cs.transition(c, s)
    if state == "resolved":
        c["state"] = "resolved"
    cs.save(c)
    return c


def test_downstream_case_is_tied_to_the_earlier_caller_case_in_both_directions(state):
    up = _case("agent mandate blocks above 10% of AMP payments", "I1", state="proposed", age_s=600)   # checkout-api, 10 min earlier
    down = _case("wallet-sim error rate above 20%", "I2")
    found = ties.record_ties(down, topology.static_graph())
    assert [t["case_id"] for t in found] == [up["id"]]
    t = down["ties"][up["id"]]
    assert t["relation"] == "likely_cause_of" and t["path"] == ["checkout-api", "wallet-sim"] and t["status"] == "suggested"
    assert 590 <= t["gap_s"] <= 610 and t["state"] == "proposed"
    back = cs.load(up["id"])["ties"][down["id"]]
    assert back["relation"] == "likely_symptom_of" and back["gap_s"] == -t["gap_s"]


def test_no_tie_for_siblings_old_cases_or_a_rerun_of_the_same_alert(state):
    _case("webhook dead-letters", "I1")                                     # not on a call path with ledger
    _case("checkout-api p90 latency above 1s", "I2", age_s=ties.TIE_LOOKBACK_S + 60)   # too old
    _case("ledger p90 latency above 400ms", "I3", state="resolved", age_s=60)          # same alert, earlier run
    c = _case("ledger p90 latency above 400ms", "I3")
    assert ties.record_ties(c, topology.static_graph()) == []


def test_dismissed_tie_stays_dismissed(state):
    up = _case("checkout-api p90 latency above 1s", "I1", state="proposed", age_s=60)
    down = _case("ledger p90 latency above 400ms", "I2")
    ties.record_ties(down, topology.static_graph())
    assert ties.dismiss(down["id"], up["id"], "nick@console")[0] == 200
    again = cs.load(down["id"])
    ties.record_ties(again, topology.static_graph())
    assert again["ties"][up["id"]]["status"] == "dismissed" and cs.load(up["id"])["ties"][down["id"]]["status"] == "dismissed"


def test_merge_moves_alerts_and_closes_the_other_case(state):
    up = _case("checkout-api p90 latency above 1s", "I1", state="proposed", age_s=60)
    down = _case("ledger p90 latency above 400ms", "I2", state="proposed")
    ties.record_ties(down, topology.static_graph())
    code, out = ties.merge(down["id"], up["id"], "nick@console")
    assert code == 200, out
    t, s = cs.load(down["id"]), cs.load(up["id"])
    assert [i["incident_id"] for i in t["incidents"]] == ["I2", "I1"] and t["incidents"][1]["joined"]["rule"] == "merged"
    assert t["ties"][up["id"]]["status"] == "merged" and s["state"] == "closed" and s["merged_into"] == down["id"]
    assert ties.find_ties(t, cs.list_cases(), topology.static_graph()) == []   # a merged case is never suggested again
    assert ties.merge(down["id"], up["id"], "nick@console") == (200, {"ok": True, "case_id": down["id"], "note": "already merged"})
    assert cs.load(down["id"])["merged_from"] == [up["id"]]


def test_merge_is_refused_while_a_case_is_busy_or_waiting_for_approval(state):
    up = _case("checkout-api p90 latency above 1s", "I1", state="investigating", age_s=60)
    down = _case("ledger p90 latency above 400ms", "I2", state="proposed")
    ties.record_ties(down, topology.static_graph())
    assert ties.merge(down["id"], up["id"], "x")[0] == 409
    waiting = _case("payment-router error rate above 5%", "I3", state="awaiting_approval", age_s=30)
    c = _case("acquirer-sim timeouts", "I4", state="proposed")
    c["incidents"][0]["services"] = ["acquirer-sim"]
    cs.save(c)
    ties.record_ties(c, topology.static_graph())
    assert ties.merge(c["id"], waiting["id"], "x")[0] == 409
    assert ties.merge("../etc", c["id"], "x")[0] == 400


def test_correlation_note_names_candidates_joins_and_ties():
    from sre_agent.investigator import correlation_note
    c = {"topology": {"root_candidates": ["wallet-sim"]},
         "incidents": [{"detector": PFX + "wallet-sim error rate above 20%"},
                       {"detector": PFX + "agent mandate blocks", "joined": {"rule": "call_path", "path": ["checkout-api", "wallet-sim"], "gap_s": 60}}],
         "ties": {"C-10261400-abcd": {"case_id": "C-10261400-abcd", "relation": "likely_cause_of", "path": ["ledger"], "state": "proposed",
                                      "detectors": ["x"], "gap_s": -30, "status": "suggested"},
                  "C-10261400-ffff": {"case_id": "C-10261400-ffff", "relation": "same_service", "status": "dismissed"}}}
    note = correlation_note(c)
    assert "checkout-api → wallet-sim" in note and "wallet-sim" in note and "60 s" in note
    assert "CAUSE of case C-10261400-abcd" in note and "30 s after" in note and "ffff" not in note
    assert correlation_note({"incidents": [{"detector": "x"}]}) == ""


def test_eval_cases_never_tie(state):
    up = _case("checkout-api p90 latency above 1s", "I1", state="proposed", age_s=60)
    c = cs.new_case("tuktukpay-demo", [{"detector": PFX + "ledger p90 latency above 400ms", "incident_id": "manual-act5"}], source="eval")
    assert ties.record_ties(c, topology.static_graph()) == []
    up["source"] = "eval"; cs.save(up)
    assert ties.record_ties(_case("ledger p90 latency above 400ms", "I2"), topology.static_graph()) == []


def test_act1_check_next_names_the_silent_acquirer_behind_payment_router():
    g = topology.static_graph()
    assert g.check_next(["payment-router"]) == [{"service": "acquirer-sim", "path": ["payment-router", "acquirer-sim"]}]
    s = g.summary(["checkout-api", "payment-router"])
    assert s["root_candidates"] == ["payment-router"] and [x["service"] for x in s["check_next"]] == ["acquirer-sim"]
    assert g.check_next(["acquirer-sim"]) == [] and g.check_next([]) == []
    near = [x["service"] for x in g.check_next(["checkout-api"])]
    assert near[:4] == ["ledger", "payment-router", "risk-engine", "wallet-sim"] and near[-1] == "acquirer-sim"   # 1 hop before 2


def test_correlation_note_for_a_single_alert_names_the_silent_callee():
    from sre_agent.investigator import correlation_note
    c = {"incidents": [{"detector": PFX + "payment-router error rate above 5%"}], "topology": topology.static_graph().summary(["payment-router"])}
    note = correlation_note(c)
    assert "first root-cause candidates): payment-router" in note and "acquirer-sim (payment-router → acquirer-sim)" in note


def _live(name, iid, since="2026-10-26T14:12:00Z"):
    return {"detector": PFX + name, "incident_id": iid, "severity": "Major", "anomaly_state": "ANOMALOUS", "since": since, "dimensions": {}}


def test_view_collapses_refires_shows_firing_state_and_offers_unowned_alerts(state):
    g = topology.static_graph()
    old1 = _case("payment-router error rate above 5%", "I-old", state="resolved", age_s=1200)
    old2 = _case("payment-router error rate above 5%", "I-old", state="resolved", age_s=700)    # re-run of the same alert
    c = _case("payment-router p90 latency above 1s", "I-p90", state="proposed")
    ties.record_ties(c, g)
    live = [_live("payment-router error rate above 5%", "I-new"), _live("payment-router p90 latency above 1s", "I-p90"),
            _live("ledger p90 latency above 400ms", "I-led")]
    v = ties.view(cs.load(c["id"]), live, g, case_of=lambda iid: None)
    assert [t["case_id"] for t in v["cases"]] == [old2["id"]] and v["cases"][0]["alert_firing"] is True
    assert v["cases"][0]["state"] == "resolved" and old1["id"] not in [t["case_id"] for t in v["cases"]]
    assert [(a["incident_id"], a["relation"]) for a in v["alerts"]] == [("I-new", "same_service")]   # ledger: not on a path
    owned = ties.view(cs.load(c["id"]), live, g, case_of=lambda iid: {"state": "investigating"} if iid == "I-new" else None)
    assert owned["alerts"] == []


def test_attach_adds_the_alert_with_its_path_and_refuses_busy_cases(state):
    g = topology.static_graph()
    c = _case("checkout-api p90 latency above 1s", "I1", state="proposed")
    code, out = ties.attach(c["id"], _live("payment-router error rate above 5%", "I2"), g, "nick@console")
    assert code == 200, out
    t = cs.load(c["id"])
    assert t["incidents"][1]["joined"]["rule"] == "added" and t["incidents"][1]["joined"]["path"] == ["checkout-api", "payment-router"]
    assert t["topology"]["root_candidates"] == ["payment-router"]
    busy = _case("ledger p90 latency above 400ms", "I3", state="investigating")
    assert ties.attach(busy["id"], _live("checkout-api p90 latency above 1s", "I4"), g, "x")[0] == 409


def test_merge_records_who_and_when_and_flags_alerts_the_brief_has_not_seen(state):
    up = _case("checkout-api p90 latency above 1s", "I1", state="proposed", age_s=60)
    down = _case("ledger p90 latency above 400ms", "I2", state="proposed")
    d = cs.load(down["id"]); d["investigation"] = {"root_cause_service": "ledger"}; cs.save(d)
    ties.record_ties(cs.load(down["id"]), topology.static_graph())
    assert ties.merge(down["id"], up["id"], "nick@console")[0] == 200
    s, t = cs.load(up["id"]), cs.load(down["id"])
    assert s["merged_by"] == "nick@console" and s["merged_at"].endswith("Z") and t["incidents"][1]["joined"]["at"] == s["merged_at"]
    assert t["unreviewed_alerts"] == [PFX + "checkout-api p90 latency above 1s"]
    assert ties.view(s, [], topology.static_graph()) == {"cases": [], "alerts": [], "graph": "static"}   # merged case: no tie buttons


def test_view_hides_earlier_firings_of_alerts_the_case_already_covers(state):
    g = topology.static_graph()
    _case("payment-router error rate above 5%", "I-old", state="resolved", age_s=600)
    c = _case("payment-router error rate above 5%", "I-new", state="proposed")
    ties.record_ties(c, g)
    assert ties.view(cs.load(c["id"]), [], g)["cases"] == []
