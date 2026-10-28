"""Model bake-off, step 3 (28 Oct 2026): which COMBINATION of anomaly models works best? Runs in the AI Toolkit
container image like step 2 (same data, same 99.5th-percentile false-alarm budget per model and service).

Two jobs, scored separately:
  trigger   is something wrong?   → acts detected, delay, false-alarm episodes per day on clean minutes
  ranker    where does it start?  → is the act's origin service ranked 1st (top-1) / in the top 3 among the
                                    services flagged in the trigger's first 3 alert minutes
Normalised score = model score / that model's threshold for the service (> 1 = flagged).
Call-graph ranker: among flagged services, prefer the deepest one (none of its callees is flagged), then by score —
the caller → callee rule the SRE agent uses (a caller records its callee's failures).
Usage (in the container): python3 /work/ml-bakeoff-combos.py /work/features.csv /work/labels.json <test_start_epoch>
"""
import json, sys, warnings
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")

feat = pd.read_csv(sys.argv[1]); lab = json.load(open(sys.argv[2])); TEST_START = float(sys.argv[3]); Q = 99.5
ORIGIN = {"act1": {"acquirer-sim"}, "act2": {"risk-engine"}, "act3": {"merchant-copilot"}, "act4": {"business", "checkout-api", "shopping-agent"},
          "act4b": {"wallet-sim"}, "act5": {"ledger"}, "act6": {"ledger"}, "act7": {"wallet-sim"}}
CALLS = {"merchant-storefront": {"checkout-api"}, "shopping-agent": {"checkout-api", "wallet-sim"}, "business": {"checkout-api"},
         "checkout-api": {"risk-engine", "payment-router", "ledger", "wallet-sim"}, "payment-router": {"acquirer-sim"},
         "merchant-copilot": {"ledger"}, "webhook-dispatcher": {"merchant-sim"}}

# ---- labels and features (same as step 2) -----------------------------------------------------------------------------
sw = lab["switches"]; minutes = np.arange(int(lab["history_from"] // 60 * 60) + 60, int(lab["end"]), 60)
state, act_of, j = {}, {}, -1
for m in minutes:
    while j + 1 < len(sw) and sw[j + 1][0] <= m:
        j += 1
    scen, since = sw[j][1], sw[j][0]
    state[m] = ("clean" if m - since >= 300 else "tail") if scen == "baseline" else "act"
    if scen != "baseline":
        act_of[m] = (scen, since)
feat = feat[feat.minute.isin(state.keys())]
SVC_COLS, BIZ_COLS = ["bad", "errs", "total", "reqs", "restarts", "apm_err_pct", "p90_ms"], ["decline_pct", "mandate_block_pct"]
frames = {}
for svc, g in feat.groupby("svc"):
    g = g.set_index("minute").reindex(sorted(state.keys()))
    X = g[BIZ_COLS if svc == "business" else SVC_COLS].apply(pd.to_numeric, errors="coerce")
    for c in ("bad", "errs", "total", "reqs", "restarts"):
        if c in X:
            X[c] = np.log1p(X[c].fillna(0))
    if "apm_err_pct" in X:
        X["apm_err_pct"] = X["apm_err_pct"].fillna(0)
    X = X.ffill().fillna(X.median()).fillna(0)
    X = X.loc[:, X.std() > 0]
    if X.shape[1]:
        frames[svc] = X
train_idx = [m for m in sorted(state) if state[m] == "clean" and m < TEST_START]
test_idx = [m for m in sorted(state) if m >= TEST_START and state[m] in ("clean", "act")]
clean_test = [m for m in test_idx if state[m] == "clean"]
acts = sorted({act_of[m] for m in test_idx if state[m] == "act"}, key=lambda a: a[1])


def factories():
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from pyod.models.ecod import ECOD
    from pyod.models.copod import COPOD
    from pyod.models.lof import LOF
    return {"ECOD": ECOD, "COPOD": COPOD, "LOF": lambda: LOF(n_neighbors=20),
            "IF": lambda: IsolationForest(n_estimators=200, random_state=0), "OCSVM": lambda: OneClassSVM(nu=0.01, gamma="scale")}


def fit_score(model, Ztr, Zte):
    model.fit(Ztr)
    if model.__class__.__module__.startswith("pyod"):
        return model.decision_function(Ztr), model.decision_function(Zte)
    return -model.score_samples(Ztr), -model.score_samples(Zte)


# N[model][svc] = Series over test minutes of normalised score (score / threshold); "PS" = per-signal thresholds
N = {}
for name, fac in list(factories().items()) + [("PS", None)]:
    N[name] = {}
    for svc, X in frames.items():
        Xtr, Xte = X.loc[train_idx], X.loc[test_idx]
        mu = Xtr.median(); sd = (Xtr.quantile(0.75) - Xtr.quantile(0.25)).replace(0, np.nan).fillna(Xtr.std()).replace(0, 1)
        Ztr, Zte = ((Xtr - mu) / sd).values, ((Xte - mu) / sd).values
        if fac is None:
            thr = np.maximum(np.percentile(Ztr, Q, axis=0), 1e-6)
            s = (Zte / thr).max(axis=1)
        else:
            s_tr, s_te = fit_score(fac(), Ztr, Zte)
            thr = np.percentile(s_tr, Q)
            lo = np.median(s_tr)   # map so that median-normal → 0, threshold → 1 (comparable across models)
            s = (s_te - lo) / max(thr - lo, 1e-9)
        N[name][svc] = pd.Series(s, index=test_idx)


def flagged_by(model, m):
    return {svc for svc, s in N[model].items() if s.get(m, -1) > 1}   # minutes outside the test set count as not flagged


def consec(fn, k=2):
    return lambda m: {s for s in fn(m) if all(s in fn(m - 60 * i) for i in range(1, k)) } if m - 60 * (k - 1) in N["ECOD"][next(iter(N["ECOD"]))].index else set()


TRIGGERS = {
    "ECOD": lambda m: flagged_by("ECOD", m),
    "COPOD": lambda m: flagged_by("COPOD", m),
    "One-Class SVM": lambda m: flagged_by("OCSVM", m),
    "Isolation Forest, 2 consecutive min": consec(lambda m: flagged_by("IF", m)),
    "per-signal (≈ live design)": lambda m: flagged_by("PS", m),
    "ECOD AND COPOD (same service)": lambda m: flagged_by("ECOD", m) & flagged_by("COPOD", m),
    "ECOD AND Isolation Forest": lambda m: flagged_by("ECOD", m) & flagged_by("IF", m),
    "ECOD AND One-Class SVM": lambda m: flagged_by("ECOD", m) & flagged_by("OCSVM", m),
    "vote ≥ 2 of ECOD / IF / OCSVM": lambda m: {s for s in frames if sum(N[k][s][m] > 1 for k in ("ECOD", "IF", "OCSVM")) >= 2},
    "vote ≥ 3 of 5 (ECOD, COPOD, IF, OCSVM, LOF)": lambda m: {s for s in frames if sum(N[k][s][m] > 1 for k in ("ECOD", "COPOD", "IF", "OCSVM", "LOF")) >= 3},
    "mean score ECOD + IF + OCSVM > 1": lambda m: {s for s in frames if np.mean([N[k][s][m] for k in ("ECOD", "IF", "OCSVM")]) > 1},
    "ECOD OR (IF, 2 consecutive)": lambda m: flagged_by("ECOD", m) | consec(lambda mm: flagged_by("IF", mm))(m),
}


def score_of(kind, svc, m):
    if kind == "mean3":
        return np.mean([N[k][svc][m] for k in ("ECOD", "IF", "OCSVM")])
    return N[kind][svc][m]


def deepest_first(cands, sc):
    leaves = [s for s in cands if not (CALLS.get(s, set()) & set(cands))]
    rest = [s for s in cands if s not in leaves]
    return sorted(leaves, key=lambda s: -sc[s]) + sorted(rest, key=lambda s: -sc[s])


RANKERS = {"ECOD score": ("ECOD", False), "Isolation Forest score": ("IF", False), "mean ECOD+IF+OCSVM": ("mean3", False),
           "call graph + ECOD score": ("ECOD", True), "call graph + mean score": ("mean3", True), "call graph + IF score": ("IF", True)}

print(f"services {len(frames)} | train {len(train_idx)} clean min | test: {len(acts)} acts, {len(clean_test)} clean min\n")
print("TRIGGERS".ljust(46) + "detected  median delay  false alarms/day")
trig_res = {}
for tname, fn in TRIGGERS.items():
    first = {}
    for a in acts:
        win = [m for m in test_idx if state[m] == "act" and act_of[m] == a]
        hit = [m for m in win if fn(m)]
        first[a] = hit[0] if hit else None
    det = [first[a] - a[1] for a in acts if first[a] is not None]
    fa = [m for m in clean_test if fn(m)]
    eps, last = 0, None
    for m in fa:
        if last is None or m - last > 600:
            eps += 1
        last = m
    per_day = eps / (len(clean_test) / 1440)
    trig_res[tname] = (first, len(det), per_day)
    print(f"{tname:46}{len(det)}/{len(acts)}      {str(round(float(np.median(det)))) + ' s' if det else '–':>8}      {per_day:5.1f}")

print("\nRANKERS (origin service among those flagged in the first 3 alert minutes of the trigger 'ECOD')")
print("ranker".ljust(28) + "top-1  top-3   per act (origin rank)")
first = trig_res["ECOD"][0]
for rname, (kind, graph) in RANKERS.items():
    top1 = top3 = 0; cells = []
    for a in acts:
        f = first[a]
        if f is None:
            cells.append(f"{a[0]}:miss"); continue
        mins = [f + 60 * k for k in range(3)]
        cands = set().union(*[TRIGGERS["ECOD"](m) for m in mins if m in N["ECOD"]["checkout-api"].index]) if "checkout-api" in N["ECOD"] else set()
        if not cands:
            cells.append(f"{a[0]}:none"); continue
        sc = {s: max(score_of(kind, s, m) for m in mins if m in N["ECOD"][s].index) for s in cands}
        order = deepest_first(list(cands), sc) if graph else sorted(cands, key=lambda s: -sc[s])
        pos = next((i + 1 for i, s in enumerate(order) if s in ORIGIN.get(a[0], set())), None)
        top1 += pos == 1; top3 += bool(pos and pos <= 3)
        cells.append(f"{a[0]}:{pos or '–'}")
    print(f"{rname:28}{top1}/{len(acts)}    {top3}/{len(acts)}    " + " ".join(cells))
