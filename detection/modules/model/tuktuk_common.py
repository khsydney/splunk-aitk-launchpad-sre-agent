"""Shared helpers for the TukTukPay anomaly modules (AI Toolkit DSDL container, Python 3.9).

Input rows (one per minute and service), as sent by `| fit|apply AITKContainer`: t (epoch seconds), svc, and any of
the signal columns below. Every module returns the same columns per input row:
    t, svc, detector, score (normalised: 1.0 = threshold), flag (0/1), reason (plain text: which signal, which test)
"""
import os
import numpy as np
import pandas as pd

MODEL_DIRECTORY = "/srv/app/model/data/"
COUNT_COLS = ["bad", "errs", "total", "reqs", "restarts"]          # log1p before scaling
SIGNAL_COLS = ["bad", "errs", "total", "reqs", "restarts", "apm_err_pct", "p90_ms", "mem_pct", "decline_pct", "mandate_block_pct"]
LABELS = {"bad": "warn+error+critical logs", "errs": "error logs", "total": "log volume", "reqs": "requests", "restarts": "restarts",
          "apm_err_pct": "APM error %", "p90_ms": "p90 latency ms", "mem_pct": "memory % of limit", "decline_pct": "payment decline %",
          "mandate_block_pct": "agent-mandate block %", "logs_per_req": "log volume per request", "errs_per_req": "errors per request"}
DERIVED = {"logs_per_req": ("total", "reqs"), "errs_per_req": ("errs", "reqs")}   # ratios catch signals that decouple


def params(param):
    p = ((param or {}).get("options") or {}).get("params") or {}
    return {k: str(v).strip('"') for k, v in p.items()}


def prepare(df):
    """Numeric signals, sorted by service and time; missing counts = 0, missing gauges carried forward."""
    d = df.copy()
    d["t"] = pd.to_numeric(d["t"], errors="coerce")
    d["svc"] = d["svc"].astype(str)
    for c in SIGNAL_COLS:
        if c in d:
            d[c] = pd.to_numeric(d[c], errors="coerce")
    d = d.dropna(subset=["t"]).sort_values(["svc", "t"]).reset_index(drop=True)
    for c in COUNT_COLS + ["apm_err_pct"]:
        if c in d:
            d[c] = d[c].fillna(0)
    gauges = [c for c in ("p90_ms", "mem_pct", "decline_pct", "mandate_block_pct") if c in d]
    if gauges:
        d[gauges] = d.groupby("svc")[gauges].ffill()
    return d


def matrix(g, cols):
    X = pd.DataFrame(index=g.index)
    for c in cols:
        if c in DERIVED:
            a, b = DERIVED[c]
            X[c] = np.log1p(g[a].astype(float).clip(lower=0)) - np.log1p(g[b].astype(float).clip(lower=0))
        elif c in COUNT_COLS:
            X[c] = np.log1p(g[c].astype(float).clip(lower=0))
        else:
            X[c] = g[c].astype(float)
    return X


class Scaler:
    """Robust scaling (median / IQR), fitted on training rows only; constant columns get scale 1."""

    def fit(self, X):
        self.cols = list(X.columns)
        self.med = X.median()
        iqr = X.quantile(0.75) - X.quantile(0.25)
        self.sd = iqr.where(iqr > 0, X.std()).replace(0, 1).fillna(1)
        self.fill = self.med.fillna(0)
        return self

    def transform(self, X):
        X = X[self.cols].fillna(self.fill)
        return ((X - self.med) / self.sd).values


def usable_cols(g):
    cols = [c for c in SIGNAL_COLS if c in g and g[c].notna().sum() > 0]
    return cols + [d for d, (a, b) in DERIVED.items() if a in cols and b in cols and g[b].sum() > 0]


def top_reasons(z, cols, n=2, min_z=3.0):
    order = np.argsort(-z)
    out = [f"{LABELS.get(cols[i], cols[i])} z={z[i]:.1f}" for i in order[:n] if z[i] >= min_z]
    return ", ".join(out)


def result(rows):
    out = pd.DataFrame(rows, columns=["t", "svc", "detector", "score", "flag", "reason"])
    if len(out):
        out["score"] = out["score"].astype(float).round(3)
        out["flag"] = out["flag"].astype(int)
    return out


def save(model, name):
    from joblib import dump
    os.makedirs(MODEL_DIRECTORY, exist_ok=True)
    dump(model, MODEL_DIRECTORY + name + ".joblib")
    return model


def load(name):
    from joblib import load as jl
    return jl(MODEL_DIRECTORY + name + ".joblib")


def consecutive(flags, k):
    """True where the last k values (in time order) are all True."""
    f = np.asarray(flags, dtype=bool)
    if k <= 1:
        return f
    out = np.zeros_like(f)
    run = 0
    for i, v in enumerate(f):
        run = run + 1 if v else 0
        out[i] = run >= k
    return out


def threshold(train_scores, q):
    """q = 100 (default): the highest score seen in clean training data; lower q trades false alarms for sensitivity."""
    return float(np.max(train_scores)) if q >= 100 else float(np.percentile(train_scores, q))
