"""Model bake-off, step 1 (28 Oct 2026): export a per-minute feature table per service and the act labels.

Features per (minute, service): bad (warn+error+critical log events), errs (error+critical), total (all log events),
apm_err_pct, reqs, p90_ms; per (minute, container): restarts; a "business" pseudo-service: decline_pct,
mandate_block_pct (only minutes with >= 10 mandate checks). Labels: every minute's war-room scenario from the panel
history (baseline or act name). Output: <out>/features.csv, <out>/labels.json. Read-only.
Run: CHAOS=<war-room URL> python3 -I ml-bakeoff-export.py <out dir> [hours back, default 36]
"""
import calendar, csv, json, os, pathlib, sys, time, urllib.request
from collections import defaultdict
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "lib"))
from stack import S  # noqa: E402

OUT = pathlib.Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
HOURS = int(sys.argv[2]) if len(sys.argv) > 2 else 36
NOW = int(time.time() // 60 * 60)
START = NOW - HOURS * 3600
CHUNK = 6 * 3600


def log(*a):
    print(time.strftime("%H:%M:%S", time.gmtime()), *a, flush=True)


def ts(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return calendar.timegm(time.strptime(str(v)[:19], "%Y-%m-%dT%H:%M:%S"))


def search(q, a, b, app="search"):
    r = S.search(f"{q} | where _time>={a} AND _time<{b}", earliest=str(a - 60), app=app, wait=1800)
    if r.get("error"):
        log("ERROR", r["error"][:200])
    return r.get("results") or []


ENV = "filter('sf_environment','tuktukpay-demo')"
BASE = "index=tuktukpay sourcetype!=splunk_o11y_cloud_hec_alert source!=http:* source!=kubernetes"
Q = {
    "logs": (f'{BASE} | bin _time span=1m | stats count(eval(severity="error" OR severity="warn" OR severity="critical")) as bad '
             'count(eval(severity="error" OR severity="critical")) as errs count as total by _time source | rename source as svc', "search"),
    "apm": (f"| sim flow query=\"data('service.request.count', filter={ENV}, rollup='sum').sum(by=['sf_service','sf_error']).publish()\" "
            "resolution=60000 | stats sum(eval(if(sf_error=\"true\",_value,0))) as errs_apm sum(_value) as reqs by _time sf_service "
            "| eval apm_err_pct=if(reqs>0, round(100*errs_apm/reqs,3), 0) | rename sf_service as svc | table _time svc reqs apm_err_pct", "splunk_ta_sim"),
    "p90": (f"| sim flow query=\"data('service.request.duration.ns.p90', filter={ENV} and filter('sf_error','false') and not "
            "filter('sf_dimensionalized','*'), rollup='max').max(by=['sf_service']).publish()\" resolution=60000 "
            "| eval p90_ms=round(_value/1e6,2) | rename sf_service as svc | table _time svc p90_ms", "splunk_ta_sim"),
    "restarts": ("| sim flow query=\"data('k8s.container.restarts', filter=filter('k8s.namespace.name','tuktukpay'), rollup='max')"
                 ".max(by=['k8s.container.name']).publish()\" resolution=60000 | rename k8s.container.name as svc | eval rs=_value | table _time svc rs", "splunk_ta_sim"),
    "biz": (f'{BASE} source=checkout-api event IN (payment.approved, payment.declined, mandate.verified, mandate.blocked) | bin _time span=1m '
            '| stats count(eval(event="payment.approved")) as ok count(eval(event="payment.declined")) as dec count(eval(event="mandate.verified")) as mv '
            'count(eval(event="mandate.blocked")) as mb by _time | eval decline_pct=if(ok+dec>0, round(100*dec/(ok+dec),3), 0), '
            'mandate_block_pct=if(mv+mb>=10, round(100*mb/(mv+mb),3), "") | eval svc="business" | table _time svc decline_pct mandate_block_pct', "search"),
}

rows = defaultdict(dict)   # (minute, svc) -> features
for name, (q, app) in Q.items():
    n = 0
    for a in range(START, NOW, CHUNK):
        for x in search(q, a, min(a + CHUNK, NOW), app):
            m = int(ts(x["_time"]) // 60 * 60)
            d = rows[(m, x["svc"])]
            for k, v in x.items():
                if k in ("_time", "svc") or k.startswith("_"):
                    continue
                d[k] = v
            n += 1
    log(name, "rows", n)

# restarts: counter → per-minute increase
series = defaultdict(list)
for (m, svc), d in rows.items():
    if "rs" in d:
        series[svc].append((m, float(d["rs"] or 0)))
for svc, pts in series.items():
    pts.sort()
    prev = None
    for m, v in pts:
        rows[(m, svc)]["restarts"] = 0 if prev is None else max(0.0, v - prev)
        prev = v
        rows[(m, svc)].pop("rs", None)

COLS = ["bad", "errs", "total", "reqs", "apm_err_pct", "p90_ms", "restarts", "decline_pct", "mandate_block_pct"]
with open(OUT / "features.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["minute", "svc"] + COLS)
    for (m, svc), d in sorted(rows.items()):
        w.writerow([m, svc] + [d.get(c, "") for c in COLS])
log("features.csv rows", len(rows))

hist = json.load(urllib.request.urlopen(os.environ["CHAOS"] + "/history", timeout=20))
hist = hist if isinstance(hist, list) else hist.get("history", [])
ev = sorted((calendar.timegm(time.strptime(h["ts"], "%Y-%m-%dT%H:%M:%SZ")), h["scenario"]) for h in hist if h.get("action") == "scenario")
(OUT / "labels.json").write_text(json.dumps({"start": START, "end": NOW, "history_from": ev[0][0] if ev else None, "switches": ev}))
log("labels: switches", len(ev), "from", time.strftime("%m-%d %H:%M", time.gmtime(ev[0][0])) if ev else None)
