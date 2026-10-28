"""Time-of-day baseline (case 4): what is normal for THIS hour (UTC (Coordinated Universal Time)), per service and signal.
Training keeps the median and spread per hour of day; hours never seen fall back to the all-day baseline. A minute
is flagged when its robust z against its hour's baseline exceeds z (default 6) for k consecutive minutes (default 2),
in either direction for traffic (a quiet lunch hour is as suspicious as a spike) and upward for errors and latency.
With ~2 days of history this is a first step; Prophet (in the image) replaces it once there are weeks of data.
Params: z (6), k (2), signals (comma list), min_rows (120)."""
import numpy as np
import pandas as pd
from . import tuktuk_common as C

NAME = "seasonal"
DEFAULT = ["reqs", "total", "p90_ms", "errs", "bad"]
TWO_SIDED = {"reqs", "total"}


def init(df, param):
    return {"models": {}}


def _stats(v):
    v = v[np.isfinite(v)]
    if len(v) < 5:
        return None
    med = float(np.median(v)); iqr = float(np.percentile(v, 75) - np.percentile(v, 25))
    return med, (iqr / 1.349 if iqr > 0 else (float(np.std(v)) or 1.0))


def fit(model, df, param):
    p = C.params(param); sigs = [s for s in p.get("signals", ",".join(DEFAULT)).split(",") if s]; min_rows = int(p.get("min_rows", 120))
    d = C.prepare(df); d["hour"] = (d["t"] // 3600 % 24).astype(int)
    for svc, g in d.groupby("svc"):
        if len(g) < min_rows:
            continue
        for c in sigs:
            if c not in g or g[c].notna().sum() < min_rows:
                continue
            y = g[c].astype(float)
            y = np.log1p(y.clip(lower=0)) if c in C.COUNT_COLS else y
            allday = _stats(y.values)
            if not allday:
                continue
            hours = {int(h): s for h, s in ((h, _stats(y[g["hour"] == h].values)) for h in range(24)) if s}
            model["models"][(svc, c)] = {"all": allday, "hours": hours}
    return {"message": f"hour-of-day baselines for {len(model['models'])} service signals"}


def apply(model, df, param):
    p = C.params(param); zt = float(p.get("z", 6)); k = int(p.get("k", 2))
    d = C.prepare(df); d["hour"] = (d["t"] // 3600 % 24).astype(int); rows = []
    for svc, g in d.groupby("svc"):
        best = np.zeros(len(g)); why = [""] * len(g)
        for (s2, c), mm in model["models"].items():
            if s2 != svc or c not in g:
                continue
            y = g[c].astype(float).values
            yy = np.log1p(np.clip(y, 0, None)) if c in C.COUNT_COLS else y
            z = np.array([(v - mm["hours"].get(h, mm["all"])[0]) / mm["hours"].get(h, mm["all"])[1] for v, h in zip(yy, g["hour"])])
            zz = np.abs(z) if c in TWO_SIDED else z
            hit = C.consecutive(np.nan_to_num(zz) > zt, k)
            for i in np.where(hit)[0]:
                sc = zz[i] / zt
                if sc > best[i]:
                    best[i] = sc
                    why[i] = f"{C.LABELS.get(c, c)} {'below' if z[i] < 0 else 'above'} normal for {g['hour'].iloc[i]:02d}:00 UTC (z={z[i]:.1f})"
        for t, s, w in zip(g["t"], best, why):
            rows.append((t, svc, NAME, s, s > 1, w))
    return C.result(rows)


def save(model, name):
    return C.save(model, name)


def load(name):
    return C.load(name)


def summary(model=None):
    return {"version": {"tuktuk_seasonal": "2026-10-28"}, "summary": f"hour-of-day baselines; {len((model or {}).get('models', {}))} service signals"}
