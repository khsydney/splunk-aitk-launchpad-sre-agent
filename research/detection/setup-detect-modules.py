"""Five anomaly detection modules in container tuktuk-detect (28 Oct 2026): features, training, scoring, alert.

The modules (services/anomaly-aitk/, image tuktukpay/anomaly-aitk:2026-10-28i) run in Docker container tuktuk-detect
on the EC2 Splunk, 127.0.0.1:5001; the toolkit reaches them through dsdl_container.conf stanzas det_ecod, det_iforest,
det_drift, det_seasonal, det_rules (api_url https://localhost:5001). One per-minute feature table per service:
  bad, errs, total, events   logs (warn+error+critical, error+critical, all; error event types "type=n;type=n")
  reqs, apm_err_pct, p90_ms  APM (Application Performance Monitoring) via | sim flow
  mem_pct                    container memory % of limit (app containers only: postgres sits at ~100 % from page cache)
  restarts                   container restarts that minute
  ok, dec, mv, mb, decline_pct, mandate_block_pct   on the "business" pseudo-service (checkout-api payment events)
Run with from the repo root:
  features <from> <to>      rebuild lookup tuktuk_detect_features.csv (epoch seconds, 3-hour chunks)
  train <until>             fit the five modules on clean minutes before <until> (war-room panel history; CHAOS=<panel URL>)
  score <out.csv>           apply the five modules to the whole lookup, save the scores locally (replay)
  callees                   write lookup tuktuk_callees.csv (call graph for the ranker, from topology.STATIC_EDGES)
  alert                     create/update the alert "TukTukPay - detection modules run TukTukPaySRE" DISABLED
  test <epoch>              run the alert's detection part as if at <epoch> (never calls the agent)
  enable | disable
"""
import calendar, csv, json, os, pathlib, sys, time, urllib.parse, urllib.request
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "lib"))
from stack import S  # noqa: E402

APP = "Splunk_ML_Toolkit"
LOOKUP = "tuktuk_detect_features.csv"
NAME = "TukTukPay - detection modules run TukTukPaySRE"
ENV = "filter('sf_environment','tuktukpay-demo')"
NS = "filter('k8s.namespace.name','tuktukpay')"
NOT_APP = '"postgres","redis","otel-collector","chaos-controller"'

LOGS = ('search index=tuktukpay sourcetype!=splunk_o11y_cloud_hec_alert source!=http:* source!=kubernetes '
        '| bin _time span=1m | eval lvl=lower(coalesce(severity, level, "")) | fillnull value="-" event '
        '| stats count as c by _time source event lvl '
        '| eval b=if(lvl IN ("warn","warning","error","critical"),c,0), e=if(lvl IN ("error","critical"),c,0), '
        'evp=if(e>0, event."=".e, null()) '
        '| stats sum(b) as bad sum(e) as errs sum(c) as total values(evp) as evs by _time source '
        '| eval events=mvjoin(evs,";") | rename source as svc | fields _time svc bad errs total events')
APM = (f"| sim flow query=\"data('service.request.count', filter={ENV}, rollup='sum').sum(by=['sf_service','sf_error']).publish()\" "
       "resolution=60000 | stats sum(eval(if(sf_error=\"true\",_value,0))) as e sum(_value) as reqs by _time sf_service "
       "| eval apm_err_pct=if(reqs>0, round(100*e/reqs,3), 0) | rename sf_service as svc | fields _time svc reqs apm_err_pct")
P90 = (f"| sim flow query=\"data('service.request.duration.ns.p90', filter={ENV} and filter('sf_error','false') and not "
       "filter('sf_dimensionalized','*'), rollup='max').max(by=['sf_service']).publish()\" resolution=60000 "
       "| eval p90_ms=round(_value/1e6,2) | rename sf_service as svc | fields _time svc p90_ms")
MEM = (f"| sim flow query=\"u=data('container.memory.usage', filter={NS}, rollup='max').max(by=['k8s.container.name']); "
       f"l=data('k8s.container.memory_limit', filter={NS}, rollup='max').max(by=['k8s.container.name']); (100*u/l).publish()\" "
       f"resolution=60000 | rename k8s.container.name as svc | where NOT svc IN ({NOT_APP}) "
       "| eval mem_pct=round(_value,2) | fields _time svc mem_pct")
RST = (f"| sim flow query=\"data('k8s.container.restarts', filter={NS}, rollup='max').max(by=['k8s.container.name']).publish()\" "
       "resolution=60000 | rename k8s.container.name as svc | sort 0 svc _time "
       "| streamstats current=f window=1 last(_value) as prev by svc "
       "| eval restarts=if(isnull(prev), 0, max(_value-prev, 0)) | fields _time svc restarts")
BIZ = ('search index=tuktukpay source=checkout-api event IN (payment.approved, payment.declined, mandate.verified, mandate.blocked) '
       '| bin _time span=1m | stats count(eval(event="payment.approved")) as ok count(eval(event="payment.declined")) as dec '
       'count(eval(event="mandate.verified")) as mv count(eval(event="mandate.blocked")) as mb by _time '
       '| eval decline_pct=if(ok+dec>0, round(100*dec/(ok+dec),3), null()), '
       'mandate_block_pct=if(mv+mb>=10, round(100*mb/(mv+mb),3), null()), svc="business"')
NUM = ["bad", "errs", "total", "reqs", "restarts", "apm_err_pct", "p90_ms", "mem_pct", "decline_pct", "mandate_block_pct"]
# every piece rounds its own minute: log rows and | sim flow rows carry different _time formats, and grouping on _time
# kept two half-empty rows per service and minute (seen 28 Oct)
T = " | eval t=floor(_time/60)*60"
FEATURES = (LOGS + T + "".join(f" | append maxtime=600 maxout=50000 [{q}{T}]" for q in (APM, P90, MEM, RST, BIZ))
            + " | stats " + " ".join(f"max({c}) as {c}" for c in NUM + ["ok", "dec", "mv", "mb"])
            + " first(events) as events by t svc | eval _time=t")
MODULES = {   # model name: (algo, fields it is sent; fit sends only the named fields)
    "det_ecod": ("tuktuk_ecod", ["t", "svc"] + NUM),
    "det_iforest": ("tuktuk_iforest", ["t", "svc"] + NUM),
    "det_drift": ("tuktuk_drift", ["t", "svc", "p90_ms", "mem_pct", "total"]),
    "det_seasonal": ("tuktuk_seasonal", ["t", "svc", "reqs", "total", "p90_ms", "errs", "bad"]),
    "det_rules": ("tuktuk_rules", ["t", "svc", "errs", "reqs", "total", "restarts", "ok", "dec", "mv", "mb", "events"]),
}
SHORT = {m: m[4:] for m in MODULES}
# modules the alert uses: the 28 Oct replay on real data (16 of 19 acts, origin right in 11, 0 false runs on 1,074
# training minutes and 3 on 427 held-out minutes) - adding drift or Isolation Forest only added false alarms
ALERT_MODULES = ["det_ecod", "det_rules", "det_seasonal"]
# topology.py STATIC_EDGES plus the callers outside it (storefront, shopping agent, business pseudo-service): the graph
# the 28 Oct bake-off ranker used (origin ranked first in 6 of 8 acts)
STATIC_EDGES = {"checkout-api": ["risk-engine", "payment-router", "ledger", "wallet-sim"], "payment-router": ["acquirer-sim"],
                "merchant-copilot": ["ledger"], "webhook-dispatcher": ["merchant-sim"], "merchant-storefront": ["checkout-api"],
                "shopping-agent": ["checkout-api", "wallet-sim"], "business": ["checkout-api"]}


def log(*a):
    print(time.strftime("%H:%M:%S", time.gmtime()), *a, flush=True)


def run(q, earliest, latest="now", wait=1800):
    st, body = S.post(f"/servicesNS/admin/{APP}/search/jobs", {"search": q if q.lstrip().startswith(("|", "search ")) else "search " + q,
                                                                "earliest_time": str(earliest), "latest_time": str(latest)})
    if st not in (200, 201):
        return {"error": f"http {st}: {body[:300]}"}
    sid = json.loads(body)["sid"]; t0 = time.time()
    while True:
        if time.time() - t0 > wait:
            return {"error": f"job {sid} not done after {wait} s"}
        st, body = S.get(f"/services/search/jobs/{sid}")
        if st == 404:
            return {"error": f"job {sid} disappeared (HTTP 404)"}
        try:
            c = json.loads(body)["entry"][0]["content"]
            if c.get("dispatchState") == "FAILED":
                return {"error": f"job {sid} failed: {json.dumps(c.get('messages'))[:300]}"}
            if c.get("isDone"):
                break
        except (ValueError, KeyError, IndexError):
            pass
        time.sleep(3)
    out, off = [], 0
    while True:
        st, body = S.get(f"/services/search/jobs/{sid}/results", count=50000, offset=off)
        d = json.loads(body) if st == 200 else {}
        part = d.get("results", [])
        out += part; off += len(part)
        if len(part) < 50000:
            break
    msgs = [m.get("text", "")[:300] for m in d.get("messages", []) if m.get("type") in ("ERROR", "WARN")]
    msgs += ["container: " + m["text"].split(" with parameters")[0] for m in d.get("messages", []) if m.get("text", "").startswith("AITKC info: /")]
    return {"results": out, "messages": msgs}


def iso(ts):
    return calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))


def clean_windows(until):
    """Baseline periods from the war-room panel history, minus 10 min after every act (recovery); nothing before the history."""
    url = os.environ.get("CHAOS")
    if not url:
        sys.exit("set CHAOS=<war-room panel URL>")
    hist = json.load(urllib.request.urlopen(url.rstrip("/") + "/history", timeout=20))
    out, start = [], None
    for h in hist:
        t = iso(h["ts"]); base = h.get("action") == "scenario" and h.get("scenario") == "baseline"
        if base and start is None:
            start = t + 600
        elif not base and start is not None:
            if t - 120 > start:
                out.append((start, t - 120))
            start = None
    if start is not None:
        out.append((start, until))
    return [(a, min(b, until)) for a, b in out if min(b, until) - a >= 600]


def cmd_features(a, b, append=False):
    chunk = 3 * 3600; n = 0
    for i, s in enumerate(range(a, b, chunk)):
        e = min(s + chunk, b)
        r = run(f"{FEATURES} | where t>={s} AND t<{e} | outputlookup append={'f' if i == 0 and not append else 't'} {LOOKUP} | stats count",
                earliest=s - 120, latest=e)
        c = int((r.get("results") or [{}])[0].get("count", 0)); n += c
        log(f"chunk {time.strftime('%d %H:%M', time.gmtime(s))} rows {c}", r.get("error", ""), r.get("messages", [])[:2])
        if r.get("error"):
            sys.exit(f"stopped; resume with: features {s} {b} append")
    log("feature rows total", n)


def cmd_train(until):
    win = clean_windows(until)
    mins = sum(b - a for a, b in win) // 60
    log(f"{len(win)} clean windows, {mins} minutes:", [(time.strftime('%d %H:%M', time.gmtime(a)), time.strftime('%d %H:%M', time.gmtime(b))) for a, b in win])
    cond = " OR ".join(f"(t>={a} AND t<{b})" for a, b in win)
    for model, (algo, fields) in MODULES.items():
        # fit answers with the module's own output (none for most modules), so success is the container's "/fit done"
        q = f"| inputlookup {LOOKUP} | where {cond}{FILL} | fit AITKContainer algo={algo} {' '.join(fields)} into app:{model} | stats count"
        t0 = time.time(); r = run(q, earliest=0)
        ok = any("/fit done successfully" in m for m in r.get("messages", []))
        log(f"{model}: {'trained' if ok else 'FAILED'} in {time.time()-t0:.0f} s", r.get("error", ""),
            [m for m in r.get("messages", []) if "no events" not in m and "/fit done" not in m][:3])


# the toolkit drops every row with an empty field (fit and apply), so fill: numbers -1 (the modules read it as missing)
FILL = " | fillnull value=-1 " + " ".join(NUM + ["ok", "dec", "mv", "mb"]) + " | fillnull value=\"-\" events"


def apply_spl(src, models=None):
    q = src + FILL
    for model in models or MODULES:
        s = SHORT[model]
        q += f" | apply {model} | rename score as s_{s} flag as f_{s} reason as r_{s} | fields - detector predicted_*"
    return q


def cmd_score(out):
    q = apply_spl(f"| inputlookup {LOOKUP} | sort 0 svc t") + " | table t svc " + " ".join(
        f"s_{s} f_{s} r_{s}" for s in SHORT.values()) + " " + " ".join(NUM)
    t0 = time.time(); r = run(q, earliest=0)
    rows = r.get("results") or []
    log(f"scored {len(rows)} rows in {time.time()-t0:.0f} s", r.get("error", ""), r.get("messages", [])[:3])
    if rows:
        cols = sorted({k for x in rows for k in x})
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, cols); w.writeheader(); w.writerows(rows)
        log("saved", out)


def cmd_callees():
    pairs = ",".join(f'"{s}|{" ".join(c)}"' for s, c in STATIC_EDGES.items())
    r = run(f"| makeresults | eval x=mvappend({pairs}) | mvexpand x "
            "| eval svc=mvindex(split(x,\"|\"),0), callees=mvindex(split(x,\"|\"),1) | table svc callees | outputlookup tuktuk_callees.csv",
            earliest="-1m")
    log("callees", len(r.get("results") or []), r.get("error", ""), r.get("messages"))


# The alert: features for the last 90 min (drift needs a 30-min window), the five modules, the last 3 complete minutes.
# A service is anomalous if any ALERT_MODULES module flags it in those minutes. Ranker: the likely origin is a flagged
# service none of whose callees is flagged (deepest on the call graph), real services before the business pseudo-service
# (it only summarises payment outcomes), highest score first. One row per run; throttled per origin
# service for 30 min via lookup tuktuk_detect_started.csv (marker written when the agent is started, not when it ends).
TAIL = ("| where t>=relative_time({now},\"-4m@m\") AND t<relative_time({now},\"-1m@m\") "
        "| eval hit=mvappend(" + ",".join(f"if(f_{SHORT[m]}=1, \"{SHORT[m]}: \".r_{SHORT[m]}, null())" for m in ALERT_MODULES) + "), "
        "score=max(" + ",".join(f"coalesce(s_{SHORT[m]},0)" for m in ALERT_MODULES) + ") "
        "| where mvcount(hit)>0 | stats max(score) as score values(hit) as why min(t) as first by svc "
        "| lookup tuktuk_callees.csv svc OUTPUT callees | eventstats values(svc) as flagged "
        "| eval c=split(coalesce(callees,\"\"),\" \"), fc=mvcount(mvmap(c, if(isnotnull(mvfind(flagged, \"^\".c.\"$\")), c, null()))) "
        "| eval deep=if(isnull(fc) OR fc=0, 1, 0), biz=if(svc=\"business\", 1, 0), line=svc.\" (\".mvjoin(mvindex(why,0,2),\"; \").\")\" "
        "| sort 0 -deep biz -score | stats first(svc) as origin list(line) as lines min(first) as onset "
        "| eval evidence=mvjoin(lines,\" | \"), onset=strftime(onset,\"%Y-%m-%d %H:%M UTC\") | fields origin onset evidence")
PROMPT = ("AI Toolkit anomaly detectors (ECOD, hour-of-day baseline, statistical rules) flagged "
          "environment tuktukpay-demo from {onset}. Likely origin on the call graph: {origin}. Flagged services and reasons: "
          "{evidence}. No detector may have fired yet. Investigate: confirm whether it is a real fault, find the service where "
          "it starts (the origin is a ranking, not a verdict), give the evidence with numbers and times, and recommend one "
          "action for a human to approve.")
THROTTLE = ("| search NOT [| inputlookup tuktuk_detect_started.csv | where at>now()-1800 | rename svc as origin | fields origin "
            "| append [| makeresults | eval origin=\"__none__\" | fields origin]] "
            "| eval at=now(), svc=origin | outputlookup append=t tuktuk_detect_started.csv | fields - at svc")
AGENT = "| aiagent agent_name=\"TukTukPaySRE\" prompt=\"" + PROMPT + "\" trigger=Alert source=\"" + NAME + "\""


def core(now):
    return apply_spl(FEATURES, ALERT_MODULES) + " " + TAIL.format(now=now)


def cmd_alert():
    base = f"/servicesNS/admin/{APP}/saved/searches"; path = f"{base}/{urllib.parse.quote(NAME, safe='')}"
    run("| makeresults | eval svc=\"__none__\", at=0 | fields svc at | outputlookup tuktuk_detect_started.csv", earliest="-1m")
    form = {"search": core("now()") + " " + THROTTLE + " " + AGENT,
            "description": "Runs TukTukPaySRE when the five detection modules in container tuktuk-detect flag a tuktukpay-demo "
                           "service. See setup-detect-modules.py.",
            "is_scheduled": "1", "cron_schedule": "*/2 * * * *", "dispatch.earliest_time": "-92m@m", "dispatch.latest_time": "now",
            "actions": "", "action.run_aiagent": "0", "alert.track": "0"}
    st, _ = S.get(path)
    st, b = S.post(path, form) if st == 200 else S.post(base, {"name": NAME, "disabled": "1", **form})
    log("saved", NAME, "->", st, b[:200] if st not in (200, 201) else "")
    log("disable ->", S.post(f"{path}/disable", {})[0])


def cmd_toggle(what):
    path = f"/servicesNS/admin/{APP}/saved/searches/{urllib.parse.quote(NAME, safe='')}"
    log(what, "->", S.post(f"{path}/{what}", {})[0])


def cmd_test(at):
    t0 = time.time(); r = run(core(str(at)), earliest=at - 92 * 60, latest=at)
    log(f"{time.strftime('%d %H:%M', time.gmtime(at))} in {time.time()-t0:.0f} s:", json.dumps(r.get("results")), r.get("error", ""), r.get("messages", [])[:3])


if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else ""
    if c == "features":
        cmd_features(int(sys.argv[2]), int(sys.argv[3]), len(sys.argv) > 4 and sys.argv[4] == "append")
    elif c == "train":
        cmd_train(int(sys.argv[2]))
    elif c == "score":
        cmd_score(sys.argv[2])
    elif c == "callees":
        cmd_callees()
    elif c == "alert":
        cmd_alert()
    elif c == "test":
        cmd_test(int(sys.argv[2]))
    elif c in ("enable", "disable"):
        cmd_toggle(c)
    else:
        sys.exit(__doc__)
