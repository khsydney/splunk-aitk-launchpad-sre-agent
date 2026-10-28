"""Statistical rules for what models handle badly (cases 6–10). One row per (minute, service); optional columns:
  errs, reqs, total, restarts — counts;  ok, dec, mv, mb — payment approved / declined, mandates verified / blocked;
  events — error-level event types seen that minute, "type=count;type=count".
Rules (each gives a score, 1.0 = threshold, and a reason):
  poisson    errs is very unlikely under the service's normal error rate (p < alpha) AND >= min_events (default 5)
  novelty    an error-level event type never seen in training, >= novel_min (default 3) per minute
  proportion decline share or mandate-block share very unlikely for today's volume (binomial p < alpha, +5 points)
  heartbeat  requests / log volume fall to 0 for >= silent_min minutes (default 3) where training median > 5
  restarts   any container restart
Params: alpha (1e-4), min_events (5), novel_min (3), silent_min (3)."""
import numpy as np
from . import tuktuk_common as C

NAME = "rules"


def init(df, param):
    return {"svc": {}, "biz": {}}


def _events(s):
    out = {}
    for part in str(s or "").split(";"):
        if "=" in part:
            k, v = part.rsplit("=", 1)
            try:
                out[k.strip()] = float(v)
            except ValueError:
                pass
    return out


def fit(model, df, param):
    d = C.prepare(df)
    for c in ("ok", "dec", "mv", "mb"):
        if c in d:
            d[c] = d[c].fillna(0)
    for svc, g in d.groupby("svc"):
        known = set()
        if "events" in g:
            for s in g["events"]:
                known |= set(_events(s))
        model["svc"][svc] = {"err_rate": float(g["errs"].mean()) if "errs" in g else 0.0,
                             "reqs_med": float(g["reqs"].median()) if "reqs" in g else 0.0,
                             "total_med": float(g["total"].median()) if "total" in g else 0.0, "known": known}
    if {"ok", "dec"} <= set(d.columns) and (d["ok"] + d["dec"]).sum() > 0:
        model["biz"]["decline"] = float(d["dec"].sum() / (d["ok"] + d["dec"]).sum())
    if {"mv", "mb"} <= set(d.columns) and (d["mv"] + d["mb"]).sum() > 0:
        model["biz"]["mandate"] = float(d["mb"].sum() / (d["mv"] + d["mb"]).sum())
    return {"message": f"rule baselines for {len(model['svc'])} services; business {model['biz']}"}


def apply(model, df, param):
    from scipy.stats import binomtest, poisson
    p = C.params(param); alpha = float(p.get("alpha", 1e-4)); min_ev = float(p.get("min_events", 5))
    novel_min = float(p.get("novel_min", 3)); silent_min = int(p.get("silent_min", 3))
    d = C.prepare(df)
    for c in ("ok", "dec", "mv", "mb"):
        if c in d:
            d[c] = d[c].fillna(0)
    rows = []
    for svc, g in d.groupby("svc"):
        base = model["svc"].get(svc, {"err_rate": 0.0, "reqs_med": 0.0, "total_med": 0.0, "known": set()})
        silent_src = "reqs" if base["reqs_med"] > 5 and "reqs" in g else ("total" if base["total_med"] > 5 and "total" in g else None)
        silent = C.consecutive((g[silent_src] <= 0).values, silent_min) if silent_src else np.zeros(len(g), bool)
        for i, (_, r) in enumerate(g.iterrows()):
            cands = []
            e = r.get("errs", 0) or 0
            if e >= min_ev:
                pv = poisson.sf(e - 1, max(base["err_rate"], 0.05))
                if pv < alpha:
                    cands.append((min(10.0, np.log10(alpha / max(pv, 1e-300)) + 1), f"{int(e)} error events/min vs normal {base['err_rate']:.1f} (Poisson p={pv:.0e})"))
            if "events" in g:
                new = {k: v for k, v in _events(r.get("events")).items() if k not in base["known"] and v >= novel_min}
                if new:
                    k, v = max(new.items(), key=lambda kv: kv[1])
                    cands.append((1 + v / 10, f"new error type {k} ({int(v)}/min, never seen in training)"))
            for key, (a, b) in (("decline", ("dec", "ok")), ("mandate", ("mb", "mv"))):
                if key in model["biz"] and a in g and b in g:
                    x, n = r.get(a, 0) or 0, (r.get(a, 0) or 0) + (r.get(b, 0) or 0)
                    p0 = model["biz"][key]
                    if n >= 10 and x / n > p0 + 0.05:
                        pv = binomtest(int(x), int(n), p0, alternative="greater").pvalue
                        if pv < alpha:
                            cands.append((min(10.0, np.log10(alpha / max(pv, 1e-300)) + 1), f"{'payment decline' if key == 'decline' else 'agent-mandate block'} share {100*x/n:.0f}% vs normal {100*p0:.0f}% (n={int(n)}, p={pv:.0e})"))
            if silent[i]:
                cands.append((2.0, f"{'requests' if silent_src == 'reqs' else 'log volume'} fell to 0 for {silent_min}+ min (normally ~{base[silent_src + '_med']:.0f}/min)"))
            if (r.get("restarts", 0) or 0) > 0:
                cands.append((1.0 + float(r["restarts"]), f"{int(r['restarts'])} container restart(s)"))
            best = max(cands, key=lambda x: x[0]) if cands else (0.0, "")
            rows.append((r["t"], svc, NAME, best[0], best[0] >= 1, best[1]))
    return C.result(rows, df)


def save(model, name):
    return C.save(model, name)


def load(name):
    return C.load(name)


def summary(model=None):
    return {"version": {"tuktuk_rules": "2026-10-28i"}, "summary": f"rules for {len((model or {}).get('svc', {}))} services"}
