"""Step 3 — ask the agent something and print its answer and tool calls (proves the whole chain works).
Run: python3 quickstart/03_ask_agent.py ["your question"]   (default: a health check of your environment)"""
import sys as _s, pathlib as _p; _s.path.insert(0, str(_p.Path(__file__).resolve().parent))  # find _common.py
import json, sys, time
from _common import S, cfg, aitk

name = cfg.get("AGENT_NAME", required=True)
q = sys.argv[1] if len(sys.argv) > 1 else (f"Give a short health check of environment {cfg.get('O11Y_ENVIRONMENT')}: the 3 services with the most "
                                            "errors or the highest latency in the last 30 minutes, with numbers. Do not investigate further.")
label = f"quickstart {int(time.time())}"
print(f"asking {name} (takes 1–5 minutes) ...", flush=True)
t0 = time.time()
r = S.search(f'| makeresults | aiagent agent_name="{name}" prompt="{q.replace(chr(34), chr(39))}" trigger="Eval" source="{label}"',
             earliest="-1m", app="Splunk_ML_Toolkit", wait=1200)
st, hist = aitk("run_history", {"count": 10, "offset": 0})
run = next((h for h in hist.get("history", []) if label in str(h.get("trigger_source"))), None) if isinstance(hist, dict) else None
turn = ((run or {}).get("data") or [{}])[0]
calls = turn.get("trace") or []
print(f"\n{round(time.time() - t0)} s · {len(calls)} tool calls · {sum(1 for c in calls if c.get('tool_call_status') != 'success')} failed")
for c in calls:
    print(f"  - {c.get('name')} {c.get('tool_call_status')}")
print("\n" + str(turn.get("response") or (r.get("results") or [{}])[0] or r.get("messages")))
