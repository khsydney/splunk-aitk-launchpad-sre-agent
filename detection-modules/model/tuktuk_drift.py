"""Slow drifts, lasting level shifts and resource exhaustion (cases 2, 3) — what a per-minute model cannot see.

Per service and signal (p90_ms, mem_pct, total by default — sparse counts make CUSUM drift; rules cover them):
  * trend: Theil-Sen slope over the last W minutes (default 30) compared with the slopes seen in training
    (flag if steeper than any training slope (q=100) AND the window rose by >= min_rise, default 20 %);
  * level shift (only with level_shift=1; off by default, see apply): one-sided CUSUM (cumulative sum) of robust z-scores against the hour-of-day baseline (k=0.5; h = the larger of 10 and 1.2 × the highest sum in this signal's training data; sum capped at h + 5 so a flag clears ~10 min after recovery);
  * time to limit (mem_pct): projected minutes until 100 % of the limit at the current slope <= ttl (default 30).
Params: window (30), q (100), min_rise (0.2), cusum_k (0.5), cusum_h (10, minimum), level_shift (0), margin (1.2), cusum_cap (5), ttl (30), signals (comma list)."""
import numpy as np
from . import tuktuk_common as C

NAME = "drift"
DEFAULT = ["p90_ms", "mem_pct", "total"]   # continuous signals only; sparse counts are the rules module's job


def _slopes(y, w):
    from scipy.stats import theilslopes
    out = np.full(len(y), np.nan)
    for i in range(w - 1, len(y)):
        seg = y[i - w + 1:i + 1]
        if np.isfinite(seg).sum() >= w // 2:
            ok = np.isfinite(seg)
            out[i] = theilslopes(seg[ok], np.arange(w)[ok])[0]
    return out


def init(df, param):
    return {"models": {}}


def fit(model, df, param):
    p = C.params(param); w = int(p.get("window", 30)); q = float(p.get("q", 100))
    k = float(p.get("cusum_k", 0.5)); h = float(p.get("cusum_h", 10)); margin = float(p.get("margin", 1.2))
    sigs = [s for s in p.get("signals", ",".join(DEFAULT)).split(",") if s]
    d = C.prepare(df)
    model["window"] = w
    for svc, g in d.groupby("svc"):
        for c in sigs:
            if c not in g or g[c].notna().sum() < 2 * w:
                continue
            y = g[c].astype(float).values
            yy = np.log1p(np.clip(y, 0, None)) if c in C.COUNT_COLS else y
            sl = _slopes(yy, w)
            hours = ((g["t"].values // 3600) % 24).astype(int)
            base = {}
            for hh in range(24):   # level per hour of day, so the normal daily curve is not read as a shift
                v = yy[(hours == hh) & np.isfinite(yy)]
                if len(v) >= 30:
                    iq = float(np.percentile(v, 75) - np.percentile(v, 25)); md = float(np.median(v))
                    base[hh] = (md, C.spread(md, iq / 1.349 if iq > 0 else float(np.std(v)), c in C.COUNT_COLS))
            v = yy[np.isfinite(yy)]; iq = float(np.percentile(v, 75) - np.percentile(v, 25)); md = float(np.median(v))
            allday = (md, C.spread(md, iq / 1.349 if iq > 0 else float(np.std(v)), c in C.COUNT_COLS))
            fin = np.abs(sl[np.isfinite(sl)])
            # calibrate the level-shift threshold on this signal's own training data: real signals wander (memory creeps,
            # latency drifts with load), so a fixed h fired on 14 % of clean service-minutes in the 28 Oct replay
            z = np.array([(v - base.get(hh, allday)[0]) / base.get(hh, allday)[1] for v, hh in zip(yy, hours)])
            S, smax = 0.0, 0.0
            for zi in z:
                if np.isfinite(zi):
                    S = max(0.0, S + zi - k); smax = max(smax, S)
            model["models"][(svc, c)] = {"slope_thr": (float(fin.max()) if q >= 100 else float(np.percentile(fin, q))) if len(fin) else 0.0,
                                         "hours": base, "all": allday, "cusum_h": max(h, margin * smax)}
    return {"message": f"drift baselines for {len(model['models'])} service signals"}


def apply(model, df, param):
    p = C.params(param); w = int(p.get("window", model.get("window", 30))); min_rise = float(p.get("min_rise", 0.2))
    k = float(p.get("cusum_k", 0.5)); h = float(p.get("cusum_h", 10)); ttl = float(p.get("ttl", 30))
    level = p.get("level_shift", "0") == "1"   # off by default: on 28 Oct real data it fired on ~14 % of clean minutes, even calibrated
    cap = float(p.get("cusum_cap", 5))   # above-threshold headroom; without a cap the sum stays high for hours after recovery
    d = C.prepare(df); rows = []
    for svc, g in d.groupby("svc"):
        ts = g["t"].values
        best = np.zeros(len(g)); why = [""] * len(g)
        for (s2, c), mm in model["models"].items():
            if s2 != svc or c not in g:
                continue
            y = g[c].astype(float).values
            yy = np.log1p(np.clip(y, 0, None)) if c in C.COUNT_COLS else y
            sl = _slopes(yy, w)
            lab = C.LABELS.get(c, c)
            # trend: unusually steep AND a real rise over the window
            for i in range(len(g)):
                if not np.isfinite(sl[i]) or i < w - 1:
                    continue
                start, end = y[i - w + 1], y[i]
                rise = (end - start) / max(abs(start), 1e-6) if np.isfinite(start) and np.isfinite(end) else 0
                sc = sl[i] / max(mm["slope_thr"], 1e-9)
                if sc > 1 and rise >= min_rise and sc > best[i]:
                    best[i] = sc; why[i] = f"{lab} rising {rise*100:.0f}% in {w} min (trend {sc:.1f}× normal)"
            # level shift: one-sided CUSUM of robust z
            hrs = ((g["t"].values // 3600) % 24).astype(int)
            hs = mm.get("cusum_h", h); cap_s = hs + cap   # drains in ~2*cap minutes once the signal is normal
            z = np.array([(v - mm["hours"].get(hh, mm["all"])[0]) / mm["hours"].get(hh, mm["all"])[1] for v, hh in zip(yy, hrs)]) if level else np.full(len(g), np.nan)
            S = 0.0
            for i in range(len(g)):
                if not np.isfinite(z[i]):
                    continue
                S = min(cap_s, max(0.0, S + z[i] - k))
                sc = S / hs
                if sc > 1 and sc > best[i]:
                    best[i] = sc; why[i] = f"{lab} shifted up and stayed (CUSUM {S:.0f})"
            # time to limit for resources reported as % of a limit
            if c == "mem_pct":
                for i in range(len(g)):
                    if np.isfinite(sl[i]) and sl[i] > 0 and np.isfinite(y[i]):
                        mins = (100 - y[i]) / sl[i]
                        if 0 <= mins <= ttl:
                            sc = 1 + (ttl - mins) / ttl
                            if sc > best[i]:
                                best[i] = sc; why[i] = f"memory at {y[i]:.0f}% of limit, reaches 100% in ~{mins:.0f} min"
        for i in range(len(g)):
            rows.append((ts[i], svc, NAME, best[i], best[i] > 1, why[i]))
    return C.result(rows, df)


def save(model, name):
    return C.save(model, name)


def load(name):
    return C.load(name)


def summary(model=None):
    return {"version": {"tuktuk_drift": "2026-10-28i"}, "summary": f"trend + CUSUM + time-to-limit; {len((model or {}).get('models', {}))} service signals"}
