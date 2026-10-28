"""Live test of the ML anomaly detection (27 Oct 2026): runs every act on the war-room panel, then scores the three
AI Toolkit DensityFunction models (tuktuk_log_errors, tuktuk_apm_errors, tuktuk_apm_p90) and the live alert
"TukTukPay - ML anomaly runs TukTukPaySRE" against the exact act times.

  run    : for each act: 3 min baseline, act for HOLD_S (default 420 s), back to baseline; writes the timeline JSON.
  score  : replays the alert's detection per minute over the whole test (same SPL and rule as the alert: an error
           model flags a service, or the latency model in 2 of 3 minutes), and reads the detector alerts and the
           live alert's agent runs for the same window. Prints a per-act table and the false alarms.
Run: CHAOS=<war-room URL> python3 -I ml-detection-act-test.py run|score [timeline.json]
"""
import calendar, json, os, pathlib, sys, time, urllib.request
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))
from stack import S  # noqa: E402

ACTS = os.environ.get("ACTS", "act1,act2,act3,act4,act4b,act5,act6,act7").split(",")
HOLD_S = int(os.environ.get("HOLD_S", "420"))
OUT = pathlib.Path(os.environ.get("OUT_DIR", "/tmp/ml-detection-test")); OUT.mkdir(parents=True, exist_ok=True)


def log(*a):
    print(time.strftime("%H:%M:%S", time.gmtime()), *a, flush=True)


def panel(name):
    urllib.request.urlopen(urllib.request.Request(f"{os.environ['CHAOS']}/scenarios/{name}", data=b"", method="POST"), timeout=20).read()


def run():
    tl = {"start": time.time(), "acts": []}
    for act in ACTS:
        panel("baseline"); log("baseline before", act); time.sleep(180)
        panel(act); s = time.time(); log("started", act); time.sleep(HOLD_S)
        panel("baseline"); e = time.time(); log("ended", act)
        tl["acts"].append({"act": act, "start": s, "end": e})
        (OUT / "timeline.json").write_text(json.dumps(tl, indent=1))
    time.sleep(240)   # a quiet tail to measure false alarms after the last act
    tl["end"] = time.time()
    (OUT / "timeline.json").write_text(json.dumps(tl, indent=1))
    log("done; panel on baseline")


ENV = "filter('sf_environment','tuktukpay-demo')"
P90 = (f"| sim flow query=\"data('service.request.duration.ns.p90', filter={ENV} and filter('sf_error','false') and not "
       "filter('sf_dimensionalized','*'), rollup='max').max(by=['sf_service']).publish()\" resolution=60000 "
       "| eval p90_ms=round(_value/1e6,1) | apply tuktuk_apm_p90 | eval svc=sf_service, sig=\"p90\", flag='IsOutlier(p90_ms)' | table _time svc sig flag")
ERR = (f"| sim flow query=\"data('service.request.count', filter={ENV}, rollup='sum').sum(by=['sf_service','sf_error']).publish()\" "
       "resolution=60000 | stats sum(eval(if(sf_error=\"true\",_value,0))) as errs sum(_value) as reqs by _time sf_service "
       "| where reqs>0 | eval apm_err_pct=round(100*errs/reqs,2) | apply tuktuk_apm_errors "
       "| eval svc=sf_service, sig=\"apm_err\", flag='IsOutlier(apm_err_pct)' | table _time svc sig flag")
LOGS = ("index=tuktukpay sourcetype!=splunk_o11y_cloud_hec_alert source!=http:* source!=kubernetes "
        "| bin _time span=1m | stats count(eval(severity=\"error\" OR severity=\"warn\")) as bad by _time source "
        "| apply tuktuk_log_errors | eval svc=source, sig=\"logs\", flag='IsOutlier(bad)' | table _time svc sig flag")


def ts(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return calendar.timegm(time.strptime(str(v)[:19], "%Y-%m-%dT%H:%M:%S"))   # Splunk returns UTC (+00:00)


def score(path):
    tl = json.loads(pathlib.Path(path).read_text())
    t0, t1 = tl["start"] - 60, tl.get("end", time.time())
    flags = []   # (minute, svc, sig)
    for name, q in (("p90", P90), ("apm_err", ERR), ("logs", LOGS)):
        r = S.search(q + " | where flag=1", earliest=str(int(t0)), app="Splunk_ML_Toolkit", wait=900)
        rows = r.get("results") or []
        log(name, "flagged minutes", len(rows), r.get("error", ""))
        flags += [(int(ts(x["_time"]) // 60 * 60), x["svc"], x["sig"]) for x in rows if ts(x["_time"]) <= t1]
    fs = set(flags)
    # the alert's rule per minute m: any error-signal flag, or p90 flagged in 2 of the minutes m-2..m
    def fired(m):
        hits = {}
        for (mm, svc, sig) in fs:
            if mm == m and sig != "p90":
                hits.setdefault(svc, set()).add(sig)
            if sig == "p90" and mm == m and sum((m - 60 * k, svc, "p90") in fs for k in range(3)) >= 2:
                hits.setdefault(svc, set()).add("p90")
        return hits
    minutes = range(int(t0 // 60 * 60), int(t1 // 60 * 60) + 60, 60)
    alerts = {m: fired(m) for m in minutes}
    det = S.search("index=tuktukpay sourcetype=splunk_o11y_cloud_hec_alert vendor_severity!=ok | eval t=_time | table t signature",
                   earliest=str(int(t0)), wait=300).get("results") or []
    runs = S.search('index=_audit sourcetype="ai_agent:response" trigger_source="*ML anomaly*" | eval t=_time | stats min(t) as t by session_id',
                    earliest=str(int(t0)), wait=300).get("results") or []
    rows, fa = [], []
    acts = tl["acts"]
    for a in acts:
        win = [m for m in minutes if a["start"] - 60 <= m <= a["end"] + 60]
        first = next((m for m in win if alerts[m]), None)
        svcs = {}
        for m in win:
            for svc, sigs in alerts[m].items():
                svcs.setdefault(svc, set()).update(sigs)
        d = sorted(float(x["t"]) for x in det if a["start"] - 30 <= float(x["t"]) <= a["end"] + 60)
        r = sorted(float(x["t"]) for x in runs if a["start"] <= float(x["t"]) <= a["end"] + 300)
        rows.append({"act": a["act"], "detected": first is not None, "ml_delay_s": None if first is None else round(first - a["start"]),
                     "detector_delay_s": round(d[0] - a["start"]) if d else None, "agent_run_after_s": round(r[0] - a["start"]) if r else None,
                     "flagged": {k: sorted(v) for k, v in sorted(svcs.items())}})
    for m in minutes:   # false alarms: alert fired in a baseline stretch at least 5 min after the previous act ended
        quiet = all(not (a["start"] - 60 <= m <= a["end"] + 300) for a in acts)
        if quiet and alerts[m]:
            fa.append({"minute": time.strftime("%H:%M", time.gmtime(m)), "flagged": {k: sorted(v) for k, v in alerts[m].items()}})
    out = {"acts": rows, "false_alarms": fa, "quiet_minutes": sum(1 for m in minutes if all(not (a["start"] - 60 <= m <= a["end"] + 300) for a in acts))}
    (OUT / "score.json").write_text(json.dumps(out, indent=1))
    print(f"\n{'act':6} {'ML':4} {'ML delay':>9} {'detector':>9} {'agent run':>10}  flagged services (signals)")
    for r in rows:
        f = "; ".join(f"{k} ({'+'.join(v)})" for k, v in r["flagged"].items())
        print(f"{r['act']:6} {'yes' if r['detected'] else 'NO':4} {str(r['ml_delay_s']) + ' s' if r['ml_delay_s'] is not None else '–':>9} "
              f"{str(r['detector_delay_s']) + ' s' if r['detector_delay_s'] is not None else '–':>9} {str(r['agent_run_after_s']) + ' s' if r['agent_run_after_s'] is not None else '–':>10}  {f[:150]}")
    print(f"\nfalse alarms: {len(fa)} minutes in {out['quiet_minutes']} quiet minutes"); [print("  ", x) for x in fa[:10]]


if __name__ == "__main__":
    if sys.argv[1] == "run":
        run()
    else:
        score(sys.argv[2] if len(sys.argv) > 2 else OUT / "timeline.json")
