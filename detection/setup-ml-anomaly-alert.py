"""ML (machine learning) anomaly alert for TukTukPaySRE (27 Oct 2026), created DISABLED. Idempotent.

Three AI Toolkit DensityFunction models (saved 27 Oct, trained on 330 baseline minutes confirmed by the war-room
panel history, upper tail 0.5 %): tuktuk_log_errors (warn+error log events per minute by source), tuktuk_apm_errors
(APM error % per minute by sf_service, via `| sim flow`), tuktuk_apm_p90 (APM p90 latency ms by sf_service).
Every 2 minutes over the last 3 complete minutes: a service is anomalous if any error model flags it, or the latency
model flags it in 2 of the 3 minutes (replay 26-27 Oct: 18 of 23 act starts found, 4 false alarms in about 10 h).
One row per run listing every flagged service (earliest first), so one fault = one agent run; throttled 10 min; action Run AI Agent on TukTukPaySRE.
  python3 -I setup-ml-anomaly-alert.py            create/update (stays disabled)
  python3 -I setup-ml-anomaly-alert.py test <epoch> run the search as if at <epoch> (no action)
  python3 -I setup-ml-anomaly-alert.py enable|disable
Run with TUKTUK_STACK=ec2.
"""
import json, pathlib, sys, urllib.parse
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lib"))
from stack import S  # noqa: E402

NAME = "TukTukPay - ML anomaly runs TukTukPaySRE"
ENV = "filter('sf_environment','tuktukpay-demo')"
P90 = (f"| sim flow query=\"data('service.request.duration.ns.p90', filter={ENV} and filter('sf_error','false') and not "
       "filter('sf_dimensionalized','*'), rollup='max').max(by=['sf_service']).publish()\" resolution=60000 "
       "| eval p90_ms=round(_value/1e6,1) | apply tuktuk_apm_p90 "
       "| eval svc=sf_service, signal=\"APM p90 latency ms\", value=p90_ms, flag='IsOutlier(p90_ms)'")
ERR = (f"| sim flow query=\"data('service.request.count', filter={ENV}, rollup='sum').sum(by=['sf_service','sf_error']).publish()\" "
       "resolution=60000 | stats sum(eval(if(sf_error=\"true\",_value,0))) as errs sum(_value) as reqs by _time sf_service "
       "| where reqs>0 | eval apm_err_pct=round(100*errs/reqs,2) | apply tuktuk_apm_errors "
       "| eval svc=sf_service, signal=\"APM error percent\", value=apm_err_pct, flag='IsOutlier(apm_err_pct)'")
LOGS = ("search index=tuktukpay sourcetype!=splunk_o11y_cloud_hec_alert source!=http:* source!=kubernetes "
        "| bin _time span=1m | stats count(eval(severity=\"error\" OR severity=\"warn\")) as bad by _time source "
        "| apply tuktuk_log_errors | eval svc=source, signal=\"warn+error log events per minute\", value=bad, flag='IsOutlier(bad)'")
TAIL = ("| where _time>=relative_time({now},\"-4m@m\") AND _time<relative_time({now},\"-1m@m\") "
        "| stats sum(flag) as flagged max(value) as peak min(eval(if(flag=1,_time,null()))) as first by svc signal "
        "| where flagged>=if(signal=\"APM p90 latency ms\",2,1) "
        "| eval ev=signal.\" peak \".peak.\" (\".flagged.\" of 3 min)\" "
        "| stats min(first) as first values(ev) as evidence by svc | sort 0 first "
        "| eval line=svc.\": \".mvjoin(evidence,\"; \") "
        "| stats min(first) as onset list(line) as lines list(svc) as svcs "
        "| eval evidence=mvjoin(lines,\" | \"), svc=mvjoin(svcs,\", \"), onset=strftime(onset,\"%Y-%m-%d %H:%M UTC\") "
        "| where isnotnull(svc) AND svc!=\"\" | fields onset svc evidence")

PROMPT = ("Splunk AI Toolkit anomaly models flagged service(s) {svc} in environment tuktukpay-demo from {onset}: "
          "{evidence}. No detector may have fired yet. Investigate: confirm whether it is a real fault, find the service "
          "where it starts (the flagged service may only show the symptom), give the evidence with numbers and times, and "
          "recommend one action for a human to approve.")
CORE = P90 + " | append [" + ERR + "] | append [" + LOGS + "] " + TAIL
# The stock "Run AI Agent" alert action cannot pass result fields to the agent (its command template expands tokens one
# level only and starts from `| makeresults`; a per-search action.run_aiagent.command override is ignored - tested
# 27 Oct). So the search calls | aiagent itself: aiagent fills {field} from the row (Python str.format). Throttle: no
# call if this search started an agent run in the last 10 min (each run writes an ai_agent:response event to _audit
# when it starts).
AGENT = ("| appendcols [search index=_audit sourcetype=\"ai_agent:response\" trigger_source=\"*TukTukPay - ML anomaly*\" "
         "earliest=-10m | stats count as recent_runs] | where isnotnull(svc) AND recent_runs=0 "
         "| aiagent agent_name=\"TukTukPaySRE\" prompt=\"" + PROMPT + "\" trigger=Alert source=\"" + NAME + "\"")
SEARCH = CORE.format(now="now()") + " " + AGENT
FORM = {
    "search": SEARCH, "description": "Runs TukTukPaySRE when the AI Toolkit DensityFunction models flag a tuktukpay-demo service "
    "(logs + APM via sim flow). See setup-ml-anomaly-alert.py.",
    "is_scheduled": "1", "cron_schedule": "*/2 * * * *", "dispatch.earliest_time": "-6m@m", "dispatch.latest_time": "now",
    "actions": "", "action.run_aiagent": "0", "alert.track": "0",
}
base = "/servicesNS/admin/Splunk_ML_Toolkit/saved/searches"
path = f"{base}/{urllib.parse.quote(NAME, safe='')}"
cmd = sys.argv[1] if len(sys.argv) > 1 else "save"
if cmd == "test":
    at = int(sys.argv[2])
    q = CORE.format(now=str(at))   # detection only; never calls the agent
    r = S.search(q, earliest=str(at - 360), app="Splunk_ML_Toolkit", wait=300)
    print(json.dumps(r.get("results"), indent=1), r.get("error", ""),
          [m.get("text", "")[:160] for m in (r.get("messages") or []) if "substituted" not in m.get("text", "")])
elif cmd in ("enable", "disable"):
    st, b = S.post(f"{path}/{cmd}", {})
    print(cmd, "->", st)
else:
    st, _ = S.get(path)
    st, b = S.post(path, FORM) if st == 200 else S.post(base, {"name": NAME, "disabled": "1", **FORM})
    print("save ->", st)
    if st not in (200, 201):
        sys.exit(b[:400])
    if json.loads(S.get(path)[1])["entry"][0]["content"].get("disabled") in (False, "0", 0):
        print("disable ->", S.post(f"{path}/disable", {})[0])
if cmd != "test":
    c = json.loads(S.get(path)[1])["entry"][0]["content"]
    print("state:", NAME, "| disabled", c.get("disabled"), "| cron", c.get("cron_schedule"), "| actions", c.get("actions"),
          "| throttle", c.get("alert.suppress.period"), "by", c.get("alert.suppress.fields"))
