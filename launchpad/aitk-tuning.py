"""AI Toolkit agent tuning harness (27 Oct 2026) for TukTukPaySRE on the EC2 Splunk.

  apply <instructions.txt> <o11y tools,comma-separated|all> <splunk tools,comma-separated|all>
        set the agent's system prompt and which tools of o11y_cloud_us1 / splunk_ec2_logs it may use
  run <act> [label] [--detector <name fragment>]
        build the prompt the alert sends (real open incident of our detectors, newest first), invoke the agent with
        `| aiagent`, save answer + tool calls under $TUNING_DIR, count the test (limit 35)

The prompt only carries what the alert carries: detector, severity, incident id, onset. Never scenario facts.
Run with and SPLUNK_O11Y_TOKEN set.
"""
import json, os, pathlib, sys, time, urllib.request
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))
from stack import S, BASE  # noqa: E402

A = BASE + "/en-US/splunkd/__raw/servicesNS/admin/Splunk_ML_Toolkit/mltk/"
DIR = pathlib.Path(os.environ.get("TUNING_DIR", "/tmp/aitk-tuning")); DIR.mkdir(parents=True, exist_ok=True)
COUNT = DIR / "count.txt"
AGENT = "TukTukPaySRE"
PROMPT = ('Splunk Observability Cloud alert: detector "{signature}" is firing (severity {severity}), incident {incidentId}, '
          'first alerted {onset} UTC. Investigate and report the root cause.')


def agent():
    st, b = S._req(A + f"agents?output_mode=json&name={AGENT}", headers=S.h, timeout=60)
    d = json.loads(b); a = d[0] if isinstance(d, list) else d
    return (a.get("versions") or a.get("details", {}).get("versions"))[0]


def put(body):
    r = urllib.request.Request(A + "agents", data=json.dumps(body).encode(), headers={**S.h, "Content-Type": "application/json"}, method="PUT")
    with S.op.open(r, timeout=180) as x:
        return x.status


def apply(prompt_file, o11y_sel, splunk_sel):
    v = agent()
    st, b = S._req(A + "mcp_connection?output_mode=json", headers=S.h, timeout=60)
    conns = {c["name"]: c for c in json.loads(b)}
    mcps = []
    for name, sel in (("o11y_cloud_us1", o11y_sel), ("splunk_ec2_logs", splunk_sel)):
        allt = [t["name"] if isinstance(t, dict) else t for t in conns[name].get("tools", [])]
        want = allt if sel == "all" else [t for t in allt if t in sel.split(",")]
        missing = [] if sel == "all" else [t for t in sel.split(",") if t not in allt]
        if missing:
            sys.exit(f"unknown tools for {name}: {missing}")
        if want:
            mcps.append({"name": name, "tools": want, "approval_required_tools": []})
    body = {"name": AGENT, "system_prompt": pathlib.Path(prompt_file).read_text().strip(), "mcps": mcps, "llm": v["llm"], "acl": v.get("acl") or {}}
    print("apply ->", put(body), "|", [(m["name"], len(m["tools"])) for m in mcps])


def open_incident():
    T = os.environ["SPLUNK_O11Y_TOKEN"]
    url = "https://api.us1.signalfx.com/v2/incident?includeResolved=false&limit=200&query=" + urllib.parse.quote("detectorName:TukTukPay*")
    inc = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"X-SF-TOKEN": T}), timeout=60))
    ours = [i for i in inc if str(i.get("detectorName", "")).startswith("TukTukPay [tuktukpay-demo]") and i.get("anomalyState") == "ANOMALOUS"]
    ours.sort(key=lambda i: -((i.get("events") or [{}])[0].get("timestamp") or 0))
    return ours


def run(act, label="", match=""):
    n = int(COUNT.read_text()) if COUNT.exists() else 0
    if n >= 35:
        sys.exit("test budget of 35 runs used up")
    incs = open_incident()
    if not incs:
        sys.exit("no open tuktukpay-demo incident: wait for the act's detector to fire")
    if match:   # pick the newest open incident of a detector whose name contains `match`
        incs = [x for x in incs if match.lower() in x["detectorName"].lower()]
        if not incs:
            sys.exit(f"no open incident matching {match!r}")
    i = incs[0]
    ev = (i.get("events") or [{}])[0]
    row = {"signature": i["detectorName"], "severity": i.get("severity"), "incidentId": i["incidentId"],
           "onset": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime((ev.get("timestamp") or 0) / 1000))}
    prompt = PROMPT.format(**row)
    spl = ("| makeresults | eval " + ", ".join(f'{k}="{v}"' for k, v in row.items()) +
           f' | aiagent agent_name="{AGENT}" prompt="{PROMPT.replace(chr(34), chr(39))}" trigger="Eval" source="aitk-tuning {label}"')
    t0 = time.time()
    res = S.search(spl, earliest="-1m", app="Splunk_ML_Toolkit", wait=600)
    secs = time.time() - t0
    n += 1; COUNT.write_text(str(n))
    rows = res.get("results") or []
    out = rows[0] if rows else {}
    answer = next((out[k] for k in ("response", "agent_response", "result", "output") if out.get(k)), "")
    # tool calls from the run history (newest run)
    st, b = S._req(A + "run_history", json.dumps({"count": 10, "offset": 0}).encode(), {**S.h, "Content-Type": "application/json"}, timeout=90)
    mine = [h for h in json.loads(b)["history"] if f"aitk-tuning {label}" in str(h.get("trigger_source"))]   # our run, not an alert's
    turn = ((mine[0]["data"] if mine else None) or [{}])[0]
    calls = [{"name": c.get("name"), "status": c.get("tool_call_status"), "args": c.get("arguments"), "error": c.get("error")}
             for c in (turn.get("trace") or [])]
    rec = {"test": n, "act": act, "label": label, "incident": row, "prompt": prompt, "seconds": round(secs), "fields": sorted(out.keys()),
           "answer": answer or turn.get("response"), "calls": calls, "skills_loaded": turn.get("skills"), "messages": res.get("messages")}
    (DIR / f"test-{n:02d}-{act}.json").write_text(json.dumps(rec, indent=1, default=str))
    print(f"TEST {n}/35 {act} {label} | {round(secs)} s | detector: {row['signature'][27:]} | calls: {len(calls)} | failed: {sum(1 for c in calls if c['status'] == 'failure')} | skills loaded: {turn.get('skills')}")
    for c in calls:
        a = json.dumps(c["args"])[:160] if c["name"] and c["name"].startswith("splunk") else ""
        print(f"  - {c['name']} {c['status']} {a} {('ERR ' + str(c['error'])[:100]) if c['error'] else ''}")
    print("ANSWER:\n" + str(rec["answer"])[:3500])


if __name__ == "__main__":
    import urllib.parse  # noqa: F401
    cmd = sys.argv[1]
    if cmd == "apply":
        apply(*sys.argv[2:5])
    elif cmd == "run":
        args = sys.argv[3:]
        match = args[args.index("--detector") + 1] if "--detector" in args else ""
        run(sys.argv[2], " ".join(a for a in args if a not in ("--detector", match)), match)
