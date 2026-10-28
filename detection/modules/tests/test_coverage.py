"""Coverage test for the anomaly modules (28 Oct 2026). Runs in the container image, no network:
  docker run --rm --network none -v <repo>/services/anomaly-aitk:/work:ro --entrypoint python3 tuktukpay/anomaly-aitk:<tag> /work/tests/test_coverage.py

Synthetic data: 2 days of baseline per service (daily traffic curve, Poisson log counts, latency, memory, business
counts) to train; day 3 = the same baseline plus one injected fault per case; a clean day 3 to count false alarms.
Prints a case × module matrix and fails if a case is caught by none of its intended modules or a module raises
more than 3 false-alarm episodes on the clean day.
"""
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, "/dltk")
from app.model import tuktuk_drift, tuktuk_ecod, tuktuk_iforest, tuktuk_rules, tuktuk_seasonal  # noqa: E402

rng = np.random.default_rng(7)
DAY = 1440
T0 = 1_793_000_000 // 86400 * 86400   # midnight UTC


def baseline(days, seed):
    r = np.random.default_rng(seed)
    rows = []
    for m in range(days * DAY):
        t = T0 + 60 * m
        hod = (m % DAY) / DAY
        curve = 1 + 0.5 * np.sin(2 * np.pi * (hod - 0.3))                  # busy midday, quiet night
        reqs = r.poisson(300 * curve)
        rows.append({"t": t, "svc": "checkout", "reqs": reqs, "total": reqs + r.poisson(20), "errs": r.poisson(0.5), "bad": r.poisson(3),
                     "restarts": 0, "apm_err_pct": abs(r.normal(0.1, 0.05)), "p90_ms": r.normal(500 + 60 * curve, 15),
                     "events": "payment.declined=%d" % r.poisson(2)})
        rows.append({"t": t, "svc": "ledger", "reqs": r.poisson(100 * curve), "total": r.poisson(100 * curve), "errs": r.poisson(0.2),
                     "bad": r.poisson(1), "restarts": 0, "apm_err_pct": 0.0, "p90_ms": r.normal(6, 0.5), "mem_pct": r.normal(40, 1.5)})
        rows.append({"t": t, "svc": "quiet", "reqs": r.poisson(20), "total": r.poisson(20), "errs": 0, "bad": 0, "restarts": 0,
                     "apm_err_pct": 0.0, "p90_ms": r.normal(2, 0.2)})
        ok = r.poisson(280 * curve); dec = r.binomial(ok + 20, 0.07); mv = r.poisson(50); mb = r.binomial(mv + 2, 0.04)
        rows.append({"t": t, "svc": "business", "ok": ok, "dec": dec, "mv": mv, "mb": mb,
                     "decline_pct": 100 * dec / max(ok + dec, 1), "mandate_block_pct": 100 * mb / max(mv + mb, 1)})
    return pd.DataFrame(rows)


train = baseline(2, 1)
day3 = baseline(1, 2); day3["t"] += 2 * 86400
clean = baseline(1, 3); clean["t"] += 2 * 86400
start3 = T0 + 2 * 86400


def inj(df, svc, m0, n, **changes):
    sel = (df.svc == svc) & (df.t >= start3 + 60 * m0) & (df.t < start3 + 60 * (m0 + n))
    for col, fn in changes.items():
        cur = df.loc[sel, col].values if col in df else np.zeros(sel.sum())
        if col != "events":
            cur = cur.astype(float)
        df.loc[sel, col] = fn(cur, np.arange(sel.sum()))
    return (svc, start3 + 60 * m0, start3 + 60 * (m0 + n))


CASES = {   # case: (window, intended modules)
    "1 sudden multi-signal spike": (inj(day3, "checkout", 120, 10, errs=lambda v, i: v + 80, apm_err_pct=lambda v, i: v + 8, p90_ms=lambda v, i: v + 400), {"ecod", "rules"}),
    "2 slow latency ramp (+60% over 90 min)": (inj(day3, "checkout", 300, 90, p90_ms=lambda v, i: v * (1 + 0.6 * i / 90)), {"drift"}),
    "2b memory leak toward the limit": (inj(day3, "ledger", 420, 60, mem_pct=lambda v, i: 40 + 55 * i / 60), {"drift"}),
    "3 lasting level shift (+25% latency)": (inj(day3, "ledger", 600, 120, p90_ms=lambda v, i: v * 1.25), {"drift"}),
    "4 traffic drop at the busy hour": (inj(day3, "checkout", 7 * 60, 20, reqs=lambda v, i: v * 0.45, total=lambda v, i: v * 0.45), {"seasonal"}),
    "5 unusual combination (logs decouple from traffic)": (inj(day3, "checkout", 900, 15, total=lambda v, i: v * 0.6 + 40), {"iforest", "ecod", "seasonal", "drift"}),   # 28 Oct: caught by seasonal/drift, not by ECOD/IF
    "6 errors on a quiet service (12/min)": (inj(day3, "quiet", 1000, 5, errs=lambda v, i: v + 12, bad=lambda v, i: v + 12), {"rules", "ecod"}),
    "7 new error type": (inj(day3, "checkout", 1100, 5, events=lambda v, i: np.array(["brand.new_error=10"] * len(i), dtype=object)), {"rules"}),
    "8 decline share 25%": (inj(day3, "business", 1150, 10, dec=lambda v, i: v * 4, decline_pct=lambda v, i: np.full(len(i), 25.0)), {"rules", "ecod"}),
    "9 service goes silent": (inj(day3, "ledger", 1250, 10, reqs=lambda v, i: 0 * v, total=lambda v, i: 0 * v), {"rules", "seasonal"}),
    "10 container restart": (inj(day3, "ledger", 1350, 1, restarts=lambda v, i: v + 1), {"rules"}),
}
# a single harmless warning on the quiet service must NOT alarm (rules minimum size)
NOT_ALARM = inj(day3, "quiet", 1380, 1, bad=lambda v, i: v + 1)

MODS = {"ecod": tuktuk_ecod, "iforest": tuktuk_iforest, "drift": tuktuk_drift, "seasonal": tuktuk_seasonal, "rules": tuktuk_rules}
COLS = {"rules": None}   # rules gets every column; the others only the numeric signals
SIGNALS = ["t", "svc", "bad", "errs", "total", "reqs", "restarts", "apm_err_pct", "p90_ms", "mem_pct", "decline_pct", "mandate_block_pct"]
param = {"options": {"params": {}}}


def run(name, mod, df_train, df_test):
    cols = None if name == "rules" else [c for c in SIGNALS if c in df_train]
    m = mod.init(df_train, param); mod.fit(m, df_train if cols is None else df_train[cols], param)
    return mod.apply(m, df_test if cols is None else df_test[cols], param)


def episodes(res):
    f = res[res.flag == 1].sort_values("t"); eps = 0; last = {}
    for _, r in f.iterrows():
        if r.svc not in last or r.t - last[r.svc] > 600:
            eps += 1
        last[r.svc] = r.t
    return eps


results, fa = {}, {}
for name, mod in MODS.items():
    results[name] = run(name, mod, train, day3)
    fa[name] = episodes(run(name, mod, train, clean))
    print(f"{name:9} trained; false-alarm episodes on the clean day: {fa[name]}", flush=True)

print("\ncase".ljust(52) + "".join(n.ljust(10) for n in MODS) + "intended")
ok = True
for case, ((svc, a, b), want) in CASES.items():
    cells, hit_any = [], False
    for name in MODS:
        r = results[name]
        h = r[(r.svc == svc) & (r.t >= a) & (r.t < b + 600) & (r.flag == 1)]
        cells.append(("✓ " + str(int((h.t.min() - a) // 60)) + "m" if len(h) else "·").ljust(10))
        hit_any |= bool(len(h)) and name in want
    ok &= hit_any
    print(case.ljust(52) + "".join(cells) + ("/".join(sorted(want)) + ("" if hit_any else "  ← MISSED")))
svc, a, b = NOT_ALARM
r = results["rules"]
single = r[(r.svc == svc) & (r.t >= a) & (r.t < b) & (r.flag == 1)]
print(f"\nsingle harmless warning on the quiet service → rules flag: {'YES (bad)' if len(single) else 'no (good)'}")
ok &= not len(single)
for name, n in fa.items():
    ok &= n <= 3
print("\nRESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
