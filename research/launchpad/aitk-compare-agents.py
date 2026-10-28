"""Side-by-side run of two AI Toolkit agents on the same live incident (27 Oct 2026): TukTukPaySRE (GPT-OSS 120B,
checklist v15) vs TukTukPaySREClaude (Claude Sonnet 5.5, hypothesis tree). Same prompt as the tuning harness (only
what the alert carries: detector, severity, incident id, onset), sent to both at once. Saves answer + tool calls to
$COMPARE_DIR/<act>-<agent>.json and prints a summary.
Run: SPLUNK_O11Y_TOKEN=... python3 -I aitk-compare-agents.py <act> [--detector <name fragment>]
"""
import json, os, pathlib, sys, threading, time
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "lib")); sys.path.insert(0, str(HERE))
from stack import S, BASE  # noqa: E402
import importlib.util
spec = importlib.util.spec_from_file_location("harness", HERE / "aitk-tuning.py")
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)   # reuse open_incident() and PROMPT

AGENTS = os.environ.get("COMPARE_AGENTS", "TukTukPaySRE,TukTukPaySREClaude").split(",")
A = BASE + "/en-US/splunkd/__raw/servicesNS/admin/Splunk_ML_Toolkit/mltk/"
OUT = pathlib.Path(os.environ.get("COMPARE_DIR", "/tmp/aitk-compare")); OUT.mkdir(parents=True, exist_ok=True)
act = sys.argv[1]
match = sys.argv[sys.argv.index("--detector") + 1] if "--detector" in sys.argv else ""
incs = H.open_incident()
if match:
    incs = [x for x in incs if match.lower() in x["detectorName"].lower()]
if not incs:
    sys.exit("no open tuktukpay-demo incident (matching): wait for the detector")
i = incs[0]; ev = (i.get("events") or [{}])[0]
row = {"signature": i["detectorName"], "severity": i.get("severity"), "incidentId": i["incidentId"],
       "onset": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime((ev.get("timestamp") or 0) / 1000))}
prompt = H.PROMPT.format(**row)
label = f"compare {act} {int(time.time())}"
print("incident:", row["signature"][27:], row["incidentId"], "onset", row["onset"])
res = {}

def run(agent):
    spl = (f'| makeresults | aiagent agent_name="{agent}" prompt="{prompt.replace(chr(34), chr(39))}" trigger="Eval" source="{label}"')
    t0 = time.time(); r = S.search(spl, earliest="-1m", app="Splunk_ML_Toolkit", wait=1200)
    res[agent] = {"seconds": round(time.time() - t0), "messages": r.get("messages"), "error": r.get("error")}

th = [threading.Thread(target=run, args=(a,)) for a in AGENTS]
[t.start() for t in th]; [t.join() for t in th]
st, b = S._req(A + "run_history", json.dumps({"count": 20, "offset": 0}).encode(), {**S.h, "Content-Type": "application/json"}, timeout=90)
for agent in AGENTS:
    h = next((x for x in json.loads(b)["history"] if x.get("agent_name") == agent and label in str(x.get("trigger_source"))), None)
    turn = ((h or {}).get("data") or [{}])[0]
    calls = [{"name": c.get("name"), "status": c.get("tool_call_status"), "args": c.get("arguments"), "error": c.get("error")} for c in (turn.get("trace") or [])]
    rec = {"act": act, "agent": agent, "incident": row, "prompt": prompt, **res.get(agent, {}),
           "processing_time": turn.get("processing_time"), "calls": calls, "answer": turn.get("response")}
    (OUT / f"{act}-{agent}.json").write_text(json.dumps(rec, indent=1, default=str))
    bad = sum(1 for c in calls if c["status"] != "success")
    print(f"\n===== {agent}: {rec['seconds']} s | calls {len(calls)} | failed {bad} | answer {len(str(rec['answer'] or ''))} chars")
    print(str(rec["answer"])[:2500])
