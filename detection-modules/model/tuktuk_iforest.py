"""Isolation Forest per service: unusual COMBINATIONS of signals that are each within normal range (case 5).
Flags only when the score stays above threshold for k consecutive minutes (default 2), which cut its false alarms
from 36.7 to 1.4 per day in the 28 Oct bake-off. Skips the business pseudo-service (its sparse ratios gave 58 of 67
clean-minute flags in the 28 Oct replay). Params: q (99.5), k (2), min_rows (60), skip (business)."""
import numpy as np
from . import tuktuk_common as C

NAME = "iforest"


def init(df, param):
    return {"models": {}}


def fit(model, df, param):
    from sklearn.ensemble import IsolationForest
    p = C.params(param); q = float(p.get("q", 99.5)); min_rows = int(p.get("min_rows", 60))
    d = C.prepare(df)
    skip = set(p.get("skip", "business").split(","))   # ratios with small samples: the rules module tests them properly
    for svc, g in d.groupby("svc"):
        if svc in skip:
            continue
        cols = [c for c in C.usable_cols(g) if C.matrix(g, [c])[c].std() > 0]
        if len(g) < min_rows or len(cols) < 2:
            continue
        X = C.matrix(g, cols); sc = C.Scaler().fit(X); Z = sc.transform(X)
        m = IsolationForest(n_estimators=200, random_state=0).fit(Z)
        s = -m.score_samples(Z)
        model["models"][svc] = {"cols": cols, "scaler": sc, "if": m, "med": float(np.median(s)), "thr": C.threshold(s, q)}
    return {"message": f"Isolation Forest trained for {len(model['models'])} services"}


def apply(model, df, param):
    k = int(C.params(param).get("k", 2)); d = C.prepare(df); rows = []
    for svc, g in d.groupby("svc"):
        mm = model["models"].get(svc)
        if not mm:
            continue
        Z = mm["scaler"].transform(C.matrix(g, mm["cols"]))
        norm = (-mm["if"].score_samples(Z) - mm["med"]) / max(mm["thr"] - mm["med"], 1e-9)
        flags = C.consecutive(norm > 1, k)
        for t, s, f, z in zip(g["t"], norm, flags, Z):
            rows.append((t, svc, NAME, s, f, ("unusual combination: " + (C.top_reasons(np.abs(z), mm["cols"], 3, 1.5) or "several signals")) if f else ""))
    return C.result(rows, df)


def save(model, name):
    return C.save(model, name)


def load(name):
    return C.load(name)


def summary(model=None):
    return {"version": {"tuktuk_iforest": "2026-10-28i"}, "summary": f"Isolation Forest per service; {len((model or {}).get('models', {}))} services"}
