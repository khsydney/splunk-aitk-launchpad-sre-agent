"""Runs inside the AI Toolkit container under Python 3.11 (/dltk/sre-venv). Reads JSON {"rows": [...], "window",
"provider"} on stdin, runs one TukTukPay SRE agent case per row (policy `ask`: propose only), prints JSON {"results": [...]}.
Called by app/model/tuktuk_sre.py (the toolkit's Python 3.9 module)."""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sre_agent import case as cs                       # noqa: E402
from sre_agent.engine import run_investigation         # noqa: E402
from sre_agent.o11y_mcp import O11yMCP                 # noqa: E402
from sre_agent.splunk_platform import SplunkPlatform   # noqa: E402
from sre_agent.trigger import fetch_open_incidents, ours  # noqa: E402
from sre_agent.branching import render_tree  # noqa: E402


def incidents(row: dict) -> list[dict]:
    want_id = str(row.get("incident_id") or row.get("incidentId") or "").strip()
    want_det = str(row.get("detector") or row.get("signature") or "").strip().lower()
    if want_id or want_det:
        live = ours(fetch_open_incidents())
        hit = [i for i in live if (want_id and i["incident_id"] == want_id) or (want_det and want_det in i["detector"].lower())]
        if hit:
            return hit[:3]
    svc = str(row.get("svc") or row.get("service") or "unknown").strip()
    ev = str(row.get("evidence") or "")[:400]
    return [{"detector": f"ML anomaly: {svc} ({ev})", "incident_id": f"ml-{int(time.time())}", "severity": "ML",
             "anomaly_state": "ANOMALOUS", "since": None}]


def main():
    req = json.load(sys.stdin)
    if req.get("method") in ("loop", "tree"):   # per call from SPL: method="loop" | "tree" (else the container default)
        os.environ["SRE_AGENT_METHOD"] = req["method"]
    mcp, splunk = O11yMCP(), SplunkPlatform()
    out = []
    for row in req.get("rows", []):
        t0 = time.time()
        try:
            c = cs.new_case(os.getenv("DEPLOYMENT_ENVIRONMENT", "tuktukpay-demo"), incidents(row), source="aitk-container")
            c = run_investigation(c, mcp, splunk, req.get("provider") or "anthropic", "ask", window=req.get("window") or "-15m")
            inv, st = c.get("investigation") or {}, c.get("stats") or {}
            out.append({"case_id": c["id"], "state": c["state"], "root_cause_service": inv.get("root_cause_service"),
                        "failure_mode": inv.get("failure_mode"), "confidence": inv.get("confidence"), "summary": inv.get("summary"),
                        "proposed_action": json.dumps(inv.get("proposed_action")), "hypotheses": json.dumps(inv.get("hypotheses")),
                        "cause_chain": " -> ".join(inv.get("cause_chain") or []), "model": st.get("model"),
                        "tree": render_tree(inv.get("tree") or []), "tree_json": json.dumps(inv.get("tree") or []),
                        "cost_usd": st.get("cost_usd"), "seconds": round(time.time() - t0)})
        except Exception as e:  # one bad row must not lose the others
            out.append({"case_id": None, "state": "error", "summary": f"{type(e).__name__}: {e}"[:500], "seconds": round(time.time() - t0)})
    print(json.dumps({"results": out}, default=str))


if __name__ == "__main__":
    main()
