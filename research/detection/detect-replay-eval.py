"""Replay the detection-module alert offline (28 Oct 2026) on scores from `setup-detect-modules.py score`.

Emulates the alert: a tick every 2 minutes looks at the last 3 complete minutes; a service is flagged if any module
flags it; the likely origin is a flagged service with no flagged callee, highest score first; one agent run per origin
per 30 minutes. Per act (war-room panel history): delay from the act's start to the first run, the origin named, the
modules that fired. On baseline (10 min after an act until 2 min before the next): agent runs = false alarms, split into
minutes used for training and the held-out minutes after <holdout_from>.
  CHAOS=<panel URL> python3 -I detect-replay-eval.py <scores.csv> <holdout_from epoch>
Read-only (reads the CSV and the panel history).
"""
import calendar, csv, json, os, sys, urllib.request
from collections import defaultdict

SCORES, HOLD = sys.argv[1], int(sys.argv[2])
MODS = os.environ.get("MODS", "ecod,iforest,drift,seasonal,rules").split(",")   # subset to compare combinations
CALLS = {"merchant-storefront": {"checkout-api"}, "shopping-agent": {"checkout-api", "wallet-sim"}, "business": {"checkout-api"},
         "checkout-api": {"risk-engine", "payment-router", "ledger", "wallet-sim"}, "payment-router": {"acquirer-sim"},
         "merchant-copilot": {"ledger"}, "webhook-dispatcher": {"merchant-sim"}}
ORIGIN = {"act1": {"acquirer-sim"}, "act2": {"risk-engine"}, "act3": {"merchant-copilot"}, "act4": {"business", "checkout-api", "shopping-agent"},
          "act4b": {"wallet-sim"}, "act5": {"ledger"}, "act6": {"ledger"}, "act7": {"wallet-sim"}}

hits = defaultdict(dict)   # minute -> svc -> (score, [modules])
last = 0
for r in csv.DictReader(open(SCORES)):
    t = int(float(r["t"])) // 60 * 60; last = max(last, t)
    mods = [m for m in MODS if r.get(f"f_{m}") == "1"]
    if mods:
        sc = max(float(r.get(f"s_{m}") or 0) for m in mods)
        hits[t][r["svc"]] = (sc, mods)
ts = sorted(hits) or [0]

hist = json.load(urllib.request.urlopen(os.environ["CHAOS"].rstrip("/") + "/history", timeout=20))
ev = [(calendar.timegm(__import__("time").strptime(h["ts"][:19], "%Y-%m-%dT%H:%M:%S")), h.get("scenario") if h.get("action") == "scenario" else "flag:" + str(h.get("flag", h.get("action")))) for h in hist]
acts, clean = [], []
for i, (t, sc) in enumerate(ev):
    nxt = ev[i + 1][0] if i + 1 < len(ev) else None
    if sc == "baseline":
        a, b = t + 600, (nxt - 120 if nxt else None)
        clean.append((a, b))
    else:
        acts.append((sc, t, nxt or t + 1800))
lo = min(t for t, _ in ev); hi = last + 60   # end of the scored data (not of the flagged minutes)
clean = [(a, b or hi) for a, b in clean if (b or hi) > a]

started, runs = {}, []
for T in range(lo // 120 * 120, hi + 120, 120):
    flagged = {}
    for m in range(T - 240, T - 60, 60):
        for s, (sc, mods) in hits.get(m, {}).items():
            p = flagged.get(s, (0, set()))
            flagged[s] = (max(p[0], sc), p[1] | set(mods))
    if not flagged:
        continue
    deep = [s for s in flagged if not (CALLS.get(s, set()) & set(flagged))]
    origin = sorted(deep or flagged, key=lambda s: (s == "business", -flagged[s][0]))[0]   # business summarises outcomes: never first if a service is flagged
    if started.get(origin, -1e12) > T - 1800:
        continue
    started[origin] = T
    runs.append((T, origin, sorted(flagged), sorted(set().union(*[v[1] for v in flagged.values()]))))

print("act      start   first run  origin named        right?  modules that fired   flagged services")
right = found = 0
for name, a, b in acts:
    if not name.startswith("act"):
        continue
    first = next((r for r in runs if a <= r[0] <= b + 120), None)
    if first:
        found += 1; ok = first[1] in ORIGIN.get(name, set()); right += ok
        print(f"{name:7} {__import__('time').strftime('%d %H:%M', __import__('time').gmtime(a))}  +{first[0]-a:4d} s    {first[1]:18} {'yes' if ok else 'no ':3}     {','.join(first[3]):20} {', '.join(first[2])}")
    else:
        print(f"{name:7} {__import__('time').strftime('%d %H:%M', __import__('time').gmtime(a))}  not detected")
nacts = sum(1 for n, _, _ in acts if n.startswith("act"))
print(f"\nacts detected {found}/{nacts}, origin first {right}/{found}")
for label, sel in (("training baseline", lambda T: T < HOLD), ("held-out baseline", lambda T: T >= HOLD)):
    mins = sum(max(0, min(b, hi) - max(a, lo)) for a, b in clean if sel(a) or sel(b - 1)) // 60
    mins = sum(max(0, (min(b, hi) - max(a, lo)) // 60) for a, b in clean if sel(a))
    fa = [r for r in runs if any(a <= r[0] < b for a, b in clean) and sel(r[0])]
    print(f"{label}: {len(fa)} agent runs in {mins} min ({len(fa) * 1440 / max(mins, 1):.1f}/day)")
    for T, o, fl, mods in fa:
        why = "; ".join(f"{s}" for s in fl)
        print(f"   {__import__('time').strftime('%d %H:%M', __import__('time').gmtime(T))} origin {o}  modules {','.join(mods)}  flagged {why}")
