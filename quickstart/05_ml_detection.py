"""Step 5 (optional) — start the agent from ML anomaly detection, before any detector fires.
Needs the Splunk Infrastructure Monitoring Add-on (Splunkbase 5247) for APM metrics in SPL (`| sim flow`).

  python3 quickstart/05_ml_detection.py account      # add-on account: org id, realm, token (O11Y_ORG_ID, O11Y_TOKEN_FILE)
  python3 quickstart/05_ml_detection.py train [24]   # train 3 DensityFunction models on the last N hours (default 24) —
                                                     #   run it when those hours were NORMAL (no incident)
  python3 quickstart/05_ml_detection.py alert        # the scheduled alert (created DISABLED); then: enable | disable

Models: log errors per service, APM error % per service, APM p90 latency per service (upper tail 0.5 %). A service is
anomalous when an error model flags it, or latency is flagged in 2 of 3 minutes; the agent runs at most once per 10
minutes with all flagged services in its prompt. More detectors (ECOD, drift, seasonal, rules) are in detection-modules/."""
import sys as _s, pathlib as _p; _s.path.insert(0, str(_p.Path(__file__).resolve().parent))  # find _common.py
import json, sys, urllib.parse, urllib.request
from _common import S, BASE, cfg, ok, fail

ENV = cfg.get("O11Y_ENVIRONMENT", required=True); IDX = cfg.get("LOG_INDEX", "main"); AGENT = cfg.get("AGENT_NAME", required=True)
NAME = cfg.get("ML_ALERT_NAME", "SRE agent - ML anomaly")
F = f"filter('sf_environment','{ENV}')"
P90 = (f"| sim flow query=\"data('service.request.duration.ns.p90', filter={F} and filter('sf_error','false') and not filter('sf_dimensionalized','*'), "
       "rollup='max').max(by=['sf_service']).publish()\" resolution=60000 | eval p90_ms=round(_value/1e6,1), svc=sf_service")
ERR = (f"| sim flow query=\"data('service.request.count', filter={F}, rollup='sum').sum(by=['sf_service','sf_error']).publish()\" resolution=60000 "
       "| stats sum(eval(if(sf_error=\"true\",_value,0))) as errs sum(_value) as reqs by _time sf_service | where reqs>0 "
       "| eval apm_err_pct=round(100*errs/reqs,2), svc=sf_service")
LOGS = (f"index={IDX} | bin _time span=1m | eval lvl=lower(coalesce(severity, level, log_level, \"\")) "
        "| stats count(eval(lvl IN (\"warn\",\"warning\",\"error\",\"critical\",\"fatal\"))) as bad by _time source | rename source as svc")
MODELS = [("sre_apm_p90", P90, "p90_ms"), ("sre_apm_errors", ERR, "apm_err_pct"), ("sre_log_errors", LOGS, "bad")]
cmd = sys.argv[1] if len(sys.argv) > 1 else ""

if cmd == "account":
    org, token = cfg.get("O11Y_ORG_ID", required=True), cfg.secret_from_file("O11Y_TOKEN_FILE")
    ns = BASE + "/en-US/splunkd/__raw/servicesNS/nobody/splunk_ta_sim"

    def req(method, url, data=None, ctype="application/x-www-form-urlencoded"):
        r = urllib.request.Request(url, data=data, method=method, headers={**S.h, "Content-Type": ctype})
        try:
            with S.op.open(r, timeout=60) as x:
                return x.status, x.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
    st, b = req("GET", ns + "/storage/collections/data/sim_api_config?output_mode=json")
    for rec in (json.loads(b) if st == 200 else []):
        if rec.get("org_id") == org:
            req("DELETE", ns + "/storage/collections/data/sim_api_config/" + rec["_key"])
    st, _ = req("POST", ns + "/storage/collections/data/sim_api_config",
                json.dumps({"org_id": org, "org_name": org, "realm": cfg.get("O11Y_REALM", "us1"), "default": True, "enable": True}).encode(), "application/json")
    (ok if st in (200, 201) else fail)(f"add-on account -> HTTP {st} (if 503: the KV store is still starting, run again)")
    name = urllib.parse.quote(f"splunk_ta_sim:{org}:", safe="")
    st, _ = req("POST", ns + f"/storage/passwords/{name}", urllib.parse.urlencode({"password": token}).encode())
    if st == 404:
        st, _ = req("POST", ns + "/storage/passwords", urllib.parse.urlencode({"name": org, "realm": "splunk_ta_sim", "password": token}).encode())
    (ok if st in (200, 201) else fail)(f"token stored -> HTTP {st}")
    r = S.search(f"| sim flow query=\"data('service.request.count', filter={F}).sum().publish()\" resolution=60000", earliest="-15m", app="splunk_ta_sim", wait=120)
    (ok if r.get("results") else fail)(f"| sim flow returned {len(r.get('results') or [])} rows for environment {ENV}", "check O11Y_ORG_ID, realm and token")
elif cmd == "train":
    hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
    for name, q, field in MODELS:
        r = S.search(f"{q} | fit DensityFunction {field} by svc upper_threshold=0.005 dist=auto into {name} | stats count as rows dc(svc) as services",
                     earliest=f"-{hours}h", app="Splunk_ML_Toolkit", wait=1800)
        res = (r.get("results") or [{}])[0]
        rows = int(res.get("rows") or 0)
        (ok if rows else fail)(f"{name}: {rows} minutes, {res.get('services', 0)} services {r.get('error', '')}",
                               "no data in that window: check LOG_INDEX / O11Y_ENVIRONMENT, or train over more hours")
elif cmd in ("alert", "enable", "disable"):
    path = f"/servicesNS/admin/Splunk_ML_Toolkit/saved/searches/{urllib.parse.quote(NAME, safe='')}"
    if cmd != "alert":
        st, _ = S.post(f"{path}/{cmd}", {}); (ok if st == 200 else fail)(f"{cmd} -> HTTP {st}"); raise SystemExit
    tail = ("| where _time>=relative_time(now(),\"-4m@m\") AND _time<relative_time(now(),\"-1m@m\") "
            "| stats sum(flag) as flagged max(value) as peak min(eval(if(flag=1,_time,null()))) as first by svc signal "
            "| where flagged>=if(signal=\"APM p90 latency ms\",2,1) | eval ev=signal.\" peak \".peak "
            "| stats min(first) as first values(ev) as evidence by svc | sort 0 first | eval line=svc.\": \".mvjoin(evidence,\"; \") "
            "| stats min(first) as onset list(line) as lines list(svc) as svcs "
            "| eval evidence=mvjoin(lines,\" | \"), svc=mvjoin(svcs,\", \"), onset=strftime(onset,\"%Y-%m-%d %H:%M UTC\") | where isnotnull(svc) AND svc!=\"\" "
            "| appendcols [| inputlookup sre_ml_started.csv | where started > relative_time(now(), \"-10m\") | stats count as recent] "
            "| where isnull(recent) OR recent=0 | eval started=now() | outputlookup append=true sre_ml_started.csv ")
    core = (P90 + " | apply sre_apm_p90 | eval signal=\"APM p90 latency ms\", value=p90_ms, flag='IsOutlier(p90_ms)' | append [" + ERR +
            " | apply sre_apm_errors | eval signal=\"APM error percent\", value=apm_err_pct, flag='IsOutlier(apm_err_pct)'] | append [search " + LOGS +
            " | apply sre_log_errors | eval signal=\"warn+error log events per minute\", value=bad, flag='IsOutlier(bad)'] " + tail)
    prompt = ("ML anomaly models flagged service(s) {svc} in environment " + ENV + " from {onset}: {evidence}. No detector may have fired yet. "
              "Investigate: confirm whether it is a real fault, find the service where it starts, give the evidence with numbers and times, "
              "and recommend one action for a human to approve.")
    S.search("| makeresults | eval started=0 | table started | outputlookup sre_ml_started.csv", earliest="-1m", app="Splunk_ML_Toolkit", wait=60)
    form = {"search": core + f'| aiagent agent_name="{AGENT}" prompt="{prompt}" trigger=Alert source="{NAME}"',
            "is_scheduled": "1", "cron_schedule": "*/2 * * * *", "dispatch.earliest_time": "-6m@m", "dispatch.latest_time": "now"}
    st, _ = S.get(path)
    st, b = S.post(path, form) if st == 200 else S.post("/servicesNS/admin/Splunk_ML_Toolkit/saved/searches", {"name": NAME, "disabled": "1", **form})
    (ok if st in (200, 201) else fail)(f"saved '{NAME}' -> HTTP {st}; enable with: python3 quickstart/05_ml_detection.py enable")
else:
    print(__doc__)
