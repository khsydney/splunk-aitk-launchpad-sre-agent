"""ECOD (PyOD) per service over all its signals: the main trigger for sudden multi-signal anomalies (case 1).
fit: one ECOD per service on the (clean) training rows; threshold = 99.9th percentile of training scores; a service is flagged after k consecutive minutes (k=2).
ECOD's per-signal surprise is capped by the most extreme training value, so a threshold at the training maximum
hides single-signal anomalies (tested 28 Oct).
apply: score / threshold (1.0 = threshold), flag, reason = the most extreme signals (robust z).
Params: q (default 99.9), k (default 2), min_rows (default 60)."""
import numpy as np
from . import tuktuk_common as C

NAME = "ecod"


def init(df, param):
    return {"models": {}}


def fit(model, df, param):
    from pyod.models.ecod import ECOD
    p = C.params(param); q = float(p.get("q", 99.9)); min_rows = int(p.get("min_rows", 60))
    d = C.prepare(df)
    for svc, g in d.groupby("svc"):
        cols = [c for c in C.usable_cols(g) if C.matrix(g, [c])[c].std() > 0]
        if len(g) < min_rows or not cols:
            continue
        X = C.matrix(g, cols); sc = C.Scaler().fit(X); Z = sc.transform(X)
        m = ECOD(); m.fit(Z)
        s = m.decision_function(Z)
        model["models"][svc] = {"cols": cols, "scaler": sc, "ecod": m, "med": float(np.median(s)), "thr": C.threshold(s, q)}
    return {"message": f"ECOD trained for {len(model['models'])} services"}


def apply(model, df, param):
    k = int(C.params(param).get("k", 2)); d = C.prepare(df); rows = []
    for svc, g in d.groupby("svc"):
        mm = model["models"].get(svc)
        if not mm:
            continue
        Z = mm["scaler"].transform(C.matrix(g, mm["cols"]))
        s = mm["ecod"].decision_function(Z)
        norm = (s - mm["med"]) / max(mm["thr"] - mm["med"], 1e-9)
        flags = C.consecutive(norm > 1, k)
        for t, sc_, z, flag in zip(g["t"], norm, Z, flags):
            rows.append((t, svc, NAME, sc_, flag, C.top_reasons(z, mm["cols"]) if flag else ""))
    return C.result(rows, df)


def save(model, name):
    return C.save(model, name)


def load(name):
    return C.load(name)


def summary(model=None):
    return {"version": {"tuktuk_ecod": "2026-10-28i"}, "summary": f"ECOD per service; {len((model or {}).get('models', {}))} services"}
