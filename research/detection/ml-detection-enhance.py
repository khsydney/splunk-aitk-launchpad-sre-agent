"""Offline test of improvements to the ML anomaly detection (27 Oct 2026), scored on the live act test recorded by
ml-detection-act-test.py (timeline.json). Nothing here changes the live alert.

Candidate signals (all generic: no scenario names or flags):
  logs_v2   warn+error+CRITICAL log events per minute, by service (v1 ignored `critical`, e.g. service.crashed)
  events    per (service, event type) counts per minute for warn/error/critical events, zeros filled
  novel     an event type at warn/error/critical never seen in the clean training minutes (models cannot score
            unseen groups, so v1 ignored e.g. kya.registry_unavailable entirely)
  biz       checkout ratios per minute: payment decline %, agent-mandate block %
  restarts  Kubernetes container restarts per minute (any restart counts)
Training: clean minutes = the war-room panel's baseline periods (from its /history), 5 min after each switch to
baseline, before the test started. Models are saved under new names (tuktuk_*_v2), the live models are untouched.
Variants: V1 = live alert; V2 = V1 + logs_v2 + events + novel; V3 = V2 + biz; V4 = V3 + restarts.
Run: CHAOS=<war-room URL> python3 -I ml-detection-enhance.py <timeline.json>
"""
import calendar, json, os, pathlib, sys, time, urllib.request
from collections import defaultdict
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "lib"))
from stack import S  # noqa: E402

tl = json.loads(pathlib.Path(sys.argv[1]).read_text())
OUT = pathlib.Path(sys.argv[1]).parent
T0, T1 = tl["start"] - 60, tl.get("end", time.time())
ACTS = tl["acts"]


def log(*a):
    print(time.strftime("%H:%M:%S", time.gmtime()), *a, flush=True)


def ts(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return calendar.timegm(time.strptime(str(v)[:19], "%Y-%m-%dT%H:%M:%S"))


def minute(v):
    return int(ts(v) // 60 * 60)


# ---- clean training windows from the panel's history -------------------------------------------------------------
hist = json.load(urllib.request.urlopen(os.environ["CHAOS"] + "/history", timeout=20))
hist = hist if isinstance(hist, list) else hist.get("history", [])
ev = [(calendar.timegm(time.strptime(h["ts"], "%Y-%m-%dT%H:%M:%SZ")), h["scenario"]) for h in hist if h.get("action") == "scenario"]
ev = [e for e in ev if e[0] < T0] + [(T0, "TEST")]
clean = [(a + 300, b) for (a, s), (b, _) in zip(ev, ev[1:]) if s == "baseline" and b - a > 600]
log("clean windows", len(clean), "minutes", sum(b - a for a, b in clean) // 60)
CLEAN = " OR ".join(f"(_time>={int(a)} AND _time<{int(b)})" for a, b in clean)
TRAIN_FROM = str(int(min(a for a, _ in clean) - 60))

SEV = 'severity IN ("warn","error","critical")'
BASE = "index=tuktukpay sourcetype!=splunk_o11y_cloud_hec_alert source!=http:* source!=kubernetes"
LOGS2 = f'{BASE} | bin _time span=1m | stats count(eval(severity="error" OR severity="warn" OR severity="critical")) as bad by _time source'
EVENTS = f'{BASE} {SEV} | eval key=source.":".event | timechart span=1m limit=0 useother=f count by key | fillnull value=0 | untable _time key n'
BIZ = (f'{BASE} source=checkout-api event IN (payment.approved, payment.declined, mandate.verified, mandate.blocked) | bin _time span=1m '
       '| stats count(eval(event="payment.approved")) as ok count(eval(event="payment.declined")) as dec count(eval(event="mandate.verified")) as mv '
       'count(eval(event="mandate.blocked")) as mb by _time | eval decline_pct=if(ok+dec>0, round(100*dec/(ok+dec),2), 0), '
       'mandate_block_pct=if(mv+mb>=10, round(100*mb/(mv+mb),2), null()) | table _time decline_pct mandate_block_pct | untable _time metric value '
       '| where isnotnull(value) AND value!=""')   # a block share from fewer than 10 checks is noise
RESTARTS = ("| sim flow query=\"data('k8s.container.restarts', filter=filter('k8s.namespace.name','tuktukpay'), rollup='max')"
            ".max(by=['k8s.container.name']).publish()\" resolution=60000 | rename k8s.container.name as c | table _time c _value")


def train():
    for name, q, field, by in (("tuktuk_log_errors_v2", LOGS2, "bad", "source"), ("tuktuk_events_v2", EVENTS, "n", "key"),
                               ("tuktuk_biz_v2", BIZ, "value", "metric")):
        r = S.search(f"{q} | where {CLEAN} | fit DensityFunction {field} by {by} upper_threshold=0.005 dist=auto into {name} | stats count as rows dc({by}) as groups",
                     earliest=TRAIN_FROM, app="Splunk_ML_Toolkit", wait=1200)
        log("trained", name, r.get("results"), r.get("error", ""))
    r = S.search(f"{BASE} {SEV} | where {CLEAN} | eval key=source.\":\".event | stats count by key", earliest=TRAIN_FROM, wait=900)
    return {x["key"] for x in r.get("results") or []}


def flags_from(q, model, field, svc_field, sig, svc_map=None):
    r = S.search(f"{q} | apply {model} | where 'IsOutlier({field})'=1 | table _time {svc_field}", earliest=str(int(T0)), app="Splunk_ML_Toolkit", wait=1200)
    rows = r.get("results") or []
    log(sig, "flagged minutes", len(rows), r.get("error", ""))
    return [(minute(x["_time"]), (svc_map or (lambda v: v))(x.get(svc_field, "?")), sig) for x in rows if ts(x["_time"]) <= T1]


def main():
    known = train()
    v1 = json.loads((OUT / "score.json").read_text()) if (OUT / "score.json").exists() else None
    F = defaultdict(set)   # signal -> {(minute, svc, sig)}
    # V1 signals (same as the live alert)
    sys.argv = [sys.argv[0], "score", str(pathlib.Path(sys.argv[1]))]
    import importlib.util
    spec = importlib.util.spec_from_file_location("t", HERE / "ml-detection-act-test.py"); T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)
    for name, q in (("p90", T.P90), ("apm_err", T.ERR), ("logs", T.LOGS)):
        r = S.search(q + " | where flag=1", earliest=str(int(T0)), app="Splunk_ML_Toolkit", wait=900)
        F[name] |= {(minute(x["_time"]), x["svc"], name) for x in r.get("results") or [] if ts(x["_time"]) <= T1}
    F["logs_v2"] |= set(flags_from(LOGS2, "tuktuk_log_errors_v2", "bad", "source", "logs_v2"))
    F["events"] |= set(flags_from(EVENTS, "tuktuk_events_v2", "n", "key", "events", lambda k: k.split(":")[0] + " (" + k.split(":", 1)[-1] + ")"))
    F["biz"] |= set(flags_from(BIZ, "tuktuk_biz_v2", "value", "metric", "biz", lambda m: "checkout-api (" + m + ")"))
    r = S.search(f"{BASE} {SEV} | eval key=source.\":\".event | bin _time span=1m | stats count by _time key | where count>=3", earliest=str(int(T0)), wait=900)
    F["novel"] |= {(minute(x["_time"]), x["key"].split(":")[0] + " (new: " + x["key"].split(":", 1)[-1] + ")", "novel")
                   for x in r.get("results") or [] if x["key"] not in known and ts(x["_time"]) <= T1}
    r = S.search(RESTARTS, earliest=str(int(T0)), app="splunk_ta_sim", wait=900)
    series = defaultdict(list)
    for x in r.get("results") or []:
        series[x["c"]].append((minute(x["_time"]), float(x["_value"] or 0)))
    for c, pts in series.items():
        pts.sort()
        for (m0, v0), (m1, v1_) in zip(pts, pts[1:]):
            if v1_ > v0 and m1 <= T1:
                F["restarts"].add((m1, c + " (restart)", "restarts"))
    log("signals:", {k: len(v) for k, v in F.items()})

    minutes = list(range(int(T0 // 60 * 60), int(T1 // 60 * 60) + 60, 60))
    VARIANTS = {"V1 live": ["logs", "apm_err", "p90"], "V2 +crit/events/novel": ["logs_v2", "apm_err", "p90", "events", "novel"],
                "V3 +business": ["logs_v2", "apm_err", "p90", "events", "novel", "biz"],
                "V4 +restarts": ["logs_v2", "apm_err", "p90", "events", "novel", "biz", "restarts"]}

    def alert_at(m, sigs):
        hits = defaultdict(set)
        for s in sigs:
            for (mm, svc, sig) in F[s]:
                if mm != m:
                    continue
                if sig == "p90" and sum((m - 60 * k, svc, "p90") in F["p90"] for k in range(3)) < 2:
                    continue
                hits[svc].add(sig)
        return hits

    def quiet(m):
        return all(not (a["start"] - 60 <= m <= a["end"] + 300) for a in ACTS)

    report = {}
    for vname, sigs in VARIANTS.items():
        res, fa_eps, last_fa = [], 0, None
        for a in ACTS:
            win = [m for m in minutes if a["start"] - 60 <= m <= a["end"] + 60]
            hits = [(m, alert_at(m, sigs)) for m in win]
            first = next((m for m, h in hits if h), None)
            svcs = defaultdict(set)
            for _, h in hits:
                for k, v in h.items():
                    svcs[k] |= v
            res.append({"act": a["act"], "detected": first is not None, "delay_s": None if first is None else round(first - a["start"]),
                        "flagged": {k: sorted(v) for k, v in sorted(svcs.items())}})
        fa_minutes = [m for m in minutes if quiet(m) and alert_at(m, sigs)]
        for m in fa_minutes:   # episodes: false-alarm minutes more than 10 min apart
            if last_fa is None or m - last_fa > 600:
                fa_eps += 1
            last_fa = m
        report[vname] = {"acts": res, "false_alarm_minutes": len(fa_minutes), "false_alarm_episodes": fa_eps,
                         "quiet_minutes": sum(1 for m in minutes if quiet(m)),
                         "fa_detail": [(time.strftime("%H:%M", time.gmtime(m)), {k: sorted(v) for k, v in alert_at(m, sigs).items()}) for m in fa_minutes][:12]}
    (OUT / "enhance.json").write_text(json.dumps(report, indent=1, default=list))
    print("\n" + "variant".ljust(24) + "".join(a["act"].ljust(9) for a in ACTS) + "false alarms")
    for vname, r in report.items():
        cells = "".join((f"{x['delay_s']}s" if x["detected"] else "MISS").ljust(9) for x in r["acts"])
        print(vname.ljust(24) + cells + f"{r['false_alarm_episodes']} episodes / {r['quiet_minutes']} quiet min")
    print("\nV4 flagged per act:")
    for x in report["V4 +restarts"]["acts"]:
        print(" ", x["act"].ljust(6), "; ".join(f"{k} [{'+'.join(v)}]" for k, v in x["flagged"].items())[:220])
    print("\nV4 false alarms:", report["V4 +restarts"]["fa_detail"])


main()
