"""Model bake-off, step 2 (28 Oct 2026): runs inside the AI Toolkit container image (pandas, scikit-learn, PyOD).
Trains every candidate on clean baseline minutes and scores act detection and false alarms on the test period.

Per service, the signal vector is: log1p(bad, errs, total, reqs, restarts), apm_err_pct, p90_ms (business pseudo-
service: decline_pct, mandate_block_pct). Each model is fitted per service on clean training minutes and alerts when
its score exceeds the 99.5th percentile of its own training scores (same false-alarm budget for every model).
Clean minute = scenario baseline and at least 5 min after the switch to baseline. Train = clean minutes before the
test start; test = everything from the test start (acts + clean minutes).
Usage (in the container): python3 /work/ml-bakeoff-eval.py /work/features.csv /work/labels.json <test_start_epoch>
"""
import json, sys, time, warnings
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")

feat = pd.read_csv(sys.argv[1])
lab = json.load(open(sys.argv[2]))
TEST_START = float(sys.argv[3])
Q = 99.5

# ---- minute labels -----------------------------------------------------------------------------------------------
sw = lab["switches"]
minutes = np.arange(int(lab["history_from"] // 60 * 60) + 60, int(lab["end"]), 60)
state, act_of = {}, {}
j = -1
for m in minutes:
    while j + 1 < len(sw) and sw[j + 1][0] <= m:
        j += 1
    scen, since = sw[j][1], sw[j][0]
    if scen == "baseline":
        state[m] = "clean" if m - since >= 300 else "tail"
    else:
        state[m] = "act"; act_of[m] = (scen, since)
feat = feat[feat.minute.isin(state.keys())].copy()

# ---- feature matrix per service ------------------------------------------------------------------------------------
SVC_COLS = ["bad", "errs", "total", "reqs", "restarts", "apm_err_pct", "p90_ms"]
BIZ_COLS = ["decline_pct", "mandate_block_pct"]
frames = {}
for svc, g in feat.groupby("svc"):
    g = g.set_index("minute").reindex(sorted(state.keys()))
    cols = BIZ_COLS if svc == "business" else SVC_COLS
    X = g[cols].apply(pd.to_numeric, errors="coerce")
    for c in ("bad", "errs", "total", "reqs", "restarts"):
        if c in X:
            X[c] = np.log1p(X[c].fillna(0))
    if "apm_err_pct" in X:
        X["apm_err_pct"] = X["apm_err_pct"].fillna(0)
    X = X.ffill().fillna(X.median()).fillna(0)
    X = X.loc[:, X.std() > 0]            # drop constant columns
    if X.shape[1] and (g["reqs"].notna().sum() if "reqs" in g else 1) >= 0:
        frames[svc] = X
train_idx = [m for m in sorted(state) if state[m] == "clean" and m < TEST_START]
test_idx = [m for m in sorted(state) if m >= TEST_START and state[m] in ("clean", "act")]
print(f"services {len(frames)} | train clean minutes {len(train_idx)} | test minutes {len(test_idx)} "
      f"(clean {sum(state[m]=='clean' for m in test_idx)}, act {sum(state[m]=='act' for m in test_idx)})", flush=True)


# ---- models --------------------------------------------------------------------------------------------------------
def models():
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from pyod.models.ecod import ECOD
    from pyod.models.copod import COPOD
    from pyod.models.hbos import HBOS
    from pyod.models.lof import LOF
    from pyod.models.knn import KNN
    return {
        "per-signal threshold (≈ DensityFunction)": None,
        "Isolation Forest": lambda: IsolationForest(n_estimators=200, random_state=0),
        "ECOD (PyOD)": lambda: ECOD(),
        "COPOD (PyOD)": lambda: COPOD(),
        "HBOS (PyOD)": lambda: HBOS(),
        "LOF (PyOD)": lambda: LOF(n_neighbors=20),
        "kNN distance (PyOD)": lambda: KNN(n_neighbors=10),
        "One-Class SVM": lambda: OneClassSVM(nu=0.01, gamma="scale"),
    }


def scores(model, Xtr, Xte):
    if hasattr(model, "decision_scores_") or model.__class__.__module__.startswith("pyod"):
        model.fit(Xtr)
        return model.decision_function(Xtr), model.decision_function(Xte)
    model.fit(Xtr)
    return -model.score_samples(Xtr) if hasattr(model, "score_samples") else -model.decision_function(Xtr), \
           -model.score_samples(Xte) if hasattr(model, "score_samples") else -model.decision_function(Xte)


def run(name, factory):
    flags = {}   # minute -> set(services)
    t0 = time.time()
    for svc, X in frames.items():
        Xtr, Xte = X.loc[train_idx], X.loc[test_idx]
        if len(Xtr) < 60:
            continue
        mu, sd = Xtr.median(), (Xtr.quantile(0.75) - Xtr.quantile(0.25)).replace(0, np.nan).fillna(Xtr.std()).replace(0, 1)
        Ztr, Zte = ((Xtr - mu) / sd).values, ((Xte - mu) / sd).values
        if factory is None:   # upper-tail threshold per signal
            thr = np.percentile(Ztr, Q, axis=0)
            hit = (Zte > thr).any(axis=1)
        else:
            try:
                s_tr, s_te = scores(factory(), Ztr, Zte)
            except Exception as e:  # noqa: BLE001
                print("  ", name, svc, "failed:", type(e).__name__, str(e)[:80]); continue
            hit = s_te > np.percentile(s_tr, Q)
        for m, h in zip(test_idx, hit):
            if h:
                flags.setdefault(m, set()).add(svc)
    return flags, time.time() - t0


def evaluate(flags, consecutive=1):
    if consecutive > 1:   # a service must be flagged in N consecutive minutes
        flags = {m: {s for s in svcs if all(s in flags.get(m - 60 * k, set()) for k in range(consecutive))} for m, svcs in flags.items()}
        flags = {m: s for m, s in flags.items() if s}
    acts = {}
    for m in test_idx:
        if state[m] == "act":
            name, since = act_of[m]
            acts.setdefault((name, since), [])
    res = {}
    for (name, since) in acts:
        win = [m for m in test_idx if state[m] == "act" and act_of[m] == (name, since)]
        hit = [m for m in win if m in flags]
        res[(name, since)] = (round(hit[0] - since) if hit else None, sorted(set().union(*[flags[m] for m in hit])) if hit else [])
    clean = [m for m in test_idx if state[m] == "clean"]
    fa = [m for m in clean if m in flags]
    eps, last = 0, None
    for m in fa:
        if last is None or m - last > 600:
            eps += 1
        last = m
    per_day = eps / (len(clean) / 1440) if clean else 0
    return res, len(fa), eps, per_day, len(clean)


out = {}
for name, fac in models().items():
    flags, secs = run(name, fac)
    for cons in (1, 2):
        res, fam, eps, pday, nclean = evaluate(flags, cons)
        det = [v[0] for v in res.values() if v[0] is not None]
        key = name + ("" if cons == 1 else " · 2 consecutive min")
        out[key] = {"acts": {f"{k[0]}@{time.strftime('%H:%M', time.gmtime(k[1]))}": v for k, v in res.items()},
                    "detected": len(det), "total": len(res), "median_delay_s": float(np.median(det)) if det else None,
                    "fa_minutes": fam, "fa_episodes": eps, "fa_per_day": round(pday, 1), "clean_minutes": nclean, "fit_s": round(secs, 1)}
        print(f"{key:58} detected {len(det)}/{len(res)}  median delay {out[key]['median_delay_s']} s  "
              f"false alarms {eps} episodes ({round(pday,1)}/day over {nclean} clean min)  fit {round(secs,1)} s", flush=True)
json.dump(out, open("/tmp/bakeoff.json", "w"), indent=1, default=str)   # /work is read-only for the container user
print("\nper act (detected delay s / flagged services), best models:")
for key in out:
    if " · " in key:
        continue
    print(" ", key)
    for a, v in out[key]["acts"].items():
        print("     ", a.ljust(14), "MISS" if v[0] is None else f"{v[0]:>5} s", ", ".join(v[1])[:120])
