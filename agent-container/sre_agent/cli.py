"""CLI: console | watch | investigate | cases | show | approve | reject | close | tools. Evaluation = `investigate --act N [--no-marker]`."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time

from . import case as cs
from . import catalogue
from .acts import ACTS, EVAL_CASES, expected_actions, score_root_cause
from .audit import emit


def _clients(need_splunk: bool = True):
    from .o11y_mcp import O11yMCP
    mcp = O11yMCP()
    splunk = None
    if need_splunk:
        from .splunk_platform import SplunkPlatform
        splunk = SplunkPlatform()
    return mcp, splunk


def _print_case(c: dict, verbose: bool = False):
    inv, d = c.get("investigation") or {}, c.get("decision") or {}
    print(f"\n== Case {c['id']}  state={c['state']}  env={c['environment']}  source={c['source']}")
    for i in c["incidents"]:
        print(f"   incident {i.get('incident_id')}  {i.get('detector')}  {i.get('severity')}  since {i.get('since')}")
    if c.get("stats"):
        s = c["stats"]
        print(f"   investigator: provider={s.get('provider')} model={s.get('model')} requests={s.get('requests')} tokens in/out={s.get('input_tokens')}/{s.get('output_tokens')} "
              f"cache_read={s.get('cache_read_tokens')} cost=${s.get('cost_usd', 0):.4f} tool_calls={s.get('investigator_tool_calls')} spl={s.get('spl_calls')} tainted={s.get('tainted')}")
        if s.get("audit_write_failures"):
            print(f"   WARNING: {s['audit_write_failures']} audit record(s) did not reach the audit index (see sre.audit.write_failed on stderr)")
    if inv:
        print(f"   root cause: {inv.get('root_cause_service')} ({inv.get('failure_mode')}, confidence {inv.get('confidence')})")
        for h in inv.get("hypotheses", []):
            print(f"     - [{h.get('status')}] {h.get('statement')}  evidence={h.get('evidence_ids')} independent={h.get('independent')}")
        print(f"   narrative: {inv.get('narrative')}")
        print(f"   proposed: {(inv.get('proposed_action') or {}).get('type')} — {(inv.get('proposed_action') or {}).get('rationale')}")
    if d:
        print(f"   policy: action={d.get('action')} tier={d.get('tier')} requirement={d.get('requirement')} mode={d.get('mode')}")
        for r in d.get("reasons", []):
            print(f"     · {r}")
        if d.get("request_preview"):
            print(f"   executor would send: {json.dumps(d['request_preview'])}")
        if d.get("verification", {}).get("description"):
            print(f"   verification: {d['verification']['immediate']} → {d['verification']['description']}")
        if d.get("jev"):
            print(f"   Jev (advisory, mode={d['jev'].get('mode')}): {d['jev'].get('verdict')} — {d['jev'].get('reason')}")
        if d.get("real_world"):
            print(f"   real-world equivalent: {d['real_world']}")
        if c["state"] == "awaiting_approval":
            print(f"   >>> approve with: sre-agent approve {c['id']} {d.get('plan_hash')}   (expires {time.strftime('%H:%M:%SZ', time.gmtime(d.get('approval_expires_at', 0)))})")
    if c.get("outcome"):
        print(f"   outcome: {json.dumps(c['outcome'])}")
    if verbose:
        print(json.dumps(c, indent=1, default=str))


def cmd_investigate(a):
    from .engine import run_investigation
    from .trigger import fetch_open_incidents, ours
    mcp, splunk = _clients()
    incidents = []
    if a.act:
        act = ACTS[a.act]
        prefix = os.getenv("SRE_AGENT_DETECTOR_PREFIX", "TukTukPay [tuktukpay-demo]")
        incidents = [{"detector": f"{prefix} {d}", "incident_id": f"manual-{a.act}", "severity": "Manual", "anomaly_state": "ANOMALOUS", "since": None} for d in act.detectors[:2]]
    else:
        live = ours(fetch_open_incidents())
        if a.incident:
            incidents = [i for i in live if i["incident_id"] == a.incident]
        elif a.detector:
            incidents = [i for i in live if a.detector.lower() in i["detector"].lower()]
        if not incidents:
            print("no matching open incident; use --act N to investigate a scenario without a live alert", file=sys.stderr)
            sys.exit(2)
    c = cs.new_case(os.getenv("DEPLOYMENT_ENVIRONMENT", "tuktukpay-demo"), incidents, source="manual")
    try:
        c = run_investigation(c, mcp, splunk, a.provider, a.policy, marker_mode=not a.no_marker, window=a.window)
    except KeyboardInterrupt:   # Ctrl-C: end the case the same way as the console's Stop, never leave it `investigating`
        from .cancel import Stopped
        from .engine import stopped
        c = cs.load(c["id"])
        if c["state"] in ("open", "investigating"):
            if c["state"] == "open":
                cs.transition(c, "investigating")
            c = stopped(c, Stopped(f"{os.getenv('USER', 'operator')}@cli (Ctrl-C)", "the investigation"))
        _print_case(c, a.verbose)
        sys.exit(130)
    _print_case(c, a.verbose)
    if a.act and c.get("investigation"):
        print("   scenario check (keyword smoke test, NOT accuracy):", json.dumps(score_root_cause(ACTS[a.act], c["investigation"].get("narrative", "") + " " + c["investigation"].get("root_cause_service", ""))))
        want = expected_actions(ACTS[a.act])
        got = (c["investigation"].get("proposed_action") or {}).get("type", "")
        print(f"   action check: proposed={got} expected={' or '.join(sorted(want))} -> {'PASS' if got in want else 'FAIL'}")


def cmd_watch(a):
    from . import topology
    from .engine import run_investigation
    from .trigger import poll_once
    mcp, splunk = _clients()
    while True:
        try:
            for c in poll_once(graph=topology.fetch_graph(mcp)):
                if c["state"] == "open":
                    c = run_investigation(c, mcp, splunk, a.provider, a.policy, window=a.window)
                    _print_case(c)
        except Exception as e:  # noqa: BLE001
            emit("sre.watch.error", error=f"{type(e).__name__}: {e}"[:300])
        if a.once:
            break
        time.sleep(a.interval)


def cmd_cases(a):
    for c in cs.list_cases(open_only=not a.all):
        print(f"{c['id']}  {c['state']:<26} {c['opened_at']}  {', '.join(i.get('detector', '')[27:] for i in c['incidents'])[:90]}")


def cmd_show(a):
    _print_case(cs.load(a.case_id), a.verbose)


def cmd_approve(a):
    from .engine import approve_and_execute
    c = cs.load(a.case_id)
    mcp, splunk = _clients()
    c = approve_and_execute(c, a.plan_hash, a.approver, mcp, splunk, dry_run=a.dry_run)
    _print_case(c)


def cmd_reject(a):
    from .engine import reject
    _print_case(reject(cs.load(a.case_id), a.approver, a.reason))


def cmd_close(a):
    from .engine import close
    _print_case(close(cs.load(a.case_id), a.operator, a.reason))


def cmd_console(a):
    from .console import serve
    serve(a.port, a.provider, a.policy)


def cmd_eval_record(a):
    from .evals import record_case
    path = record_case(a.case, a.provider or os.getenv("SRE_AGENT_PROVIDER", "mock"), a.window)
    fx = json.loads(path.read_text())
    r = fx["recorded_run"]
    print(f"recorded {a.case}: {len(fx['calls'])} calls -> {path}")
    print(f"   live run: {r['provider']} root cause {r['root_cause_service']} action {r['proposed_action']} ${r['cost_usd']} {r['investigation_seconds']}s"
          + (f"  ERROR {r['error']}" if r.get("error") else ""))


def cmd_eval(a):
    from .evals import run_all, table
    rows = run_all(a.provider or os.getenv("SRE_AGENT_PROVIDER", "mock"), [x for x in (a.cases or "").split(",") if x] or None, a.runs)
    print(table(rows))
    if a.json_out:
        pathlib.Path(a.json_out).write_text(json.dumps(rows, indent=1, default=str))
    for r in rows:
        if r["miss_detail"] and a.verbose:
            print(f"\n{r['case']} calls not in the fixture:\n  " + "\n  ".join(r["miss_detail"]))


def cmd_tools(a):
    from .toolset import TOOL_SCHEMAS
    print("Investigator tools:", ", ".join(t["name"] for t in TOOL_SCHEMAS))
    print("Catalogue actions offered to the model:", ", ".join(catalogue.action_enum_for_model()))
    print("Forbidden:", ", ".join(a.name for a in catalogue.ACTIONS.values() if a.tier == "forbidden"))


def main(argv=None):
    p = argparse.ArgumentParser(prog="sre-agent", description="TukTukPay AI SRE agent prototype (investigate-and-propose by default)")
    p.add_argument("--provider", default=None, help="mock | anthropic | bedrock (default SRE_AGENT_PROVIDER or mock)")
    p.add_argument("--policy", default=os.getenv("SRE_AGENT_POLICY", "ask"), choices=["ask", "auto-demo"])
    p.add_argument("--window", default="-15m")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("investigate", help="open a case for a live incident (or a scenario) and investigate it")
    s.add_argument("--detector"); s.add_argument("--incident"); s.add_argument("--act", choices=sorted(ACTS)); s.add_argument("--no-marker", action="store_true", help="hide config.changed evidence (evaluation mode)")
    s.set_defaults(fn=cmd_investigate)
    s = sub.add_parser("watch", help="poll open incidents and investigate new cases"); s.add_argument("--once", action="store_true"); s.add_argument("--interval", type=int, default=30); s.set_defaults(fn=cmd_watch)
    s = sub.add_parser("cases"); s.add_argument("--all", action="store_true"); s.set_defaults(fn=cmd_cases)
    s = sub.add_parser("show"); s.add_argument("case_id"); s.set_defaults(fn=cmd_show)
    s = sub.add_parser("approve"); s.add_argument("case_id"); s.add_argument("plan_hash"); s.add_argument("--approver", default=os.getenv("USER", "operator")); s.add_argument("--dry-run", action="store_true"); s.set_defaults(fn=cmd_approve)
    s = sub.add_parser("reject"); s.add_argument("case_id"); s.add_argument("--approver", default=os.getenv("USER", "operator")); s.add_argument("--reason", default="rejected"); s.set_defaults(fn=cmd_reject)
    s = sub.add_parser("close"); s.add_argument("case_id"); s.add_argument("--operator", default=os.getenv("USER", "operator")); s.add_argument("--reason", default="closed by operator"); s.set_defaults(fn=cmd_close)
    s = sub.add_parser("tools"); s.set_defaults(fn=cmd_tools)
    s = sub.add_parser("eval-record", help="record a replayable eval fixture while the act runs (live clients, writes evals/cases/<case>.json)")
    s.add_argument("--case", required=True, choices=sorted(EVAL_CASES)); s.set_defaults(fn=cmd_eval_record)
    s = sub.add_parser("eval", help="replay the recorded fixtures through the agent and print a pass/fail table")
    s.add_argument("--cases", help="comma-separated, default: every recorded case"); s.add_argument("--runs", type=int, default=1)
    s.add_argument("--json-out", help="also write the rows as JSON to this file"); s.set_defaults(fn=cmd_eval)
    s = sub.add_parser("console", help="chat-style web console on 127.0.0.1: triage alerts live, ask follow-ups, approve"); s.add_argument("--port", type=int, default=8790); s.set_defaults(fn=cmd_console)
    a = p.parse_args(argv)
    a.fn(a)
