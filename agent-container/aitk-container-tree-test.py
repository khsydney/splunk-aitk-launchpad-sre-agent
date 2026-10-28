"""Live test (27 Oct 2026): our SRE agent in the AI Toolkit container, single loop vs sub-agent hypothesis tree, on
the trap that fooled the prompt-only tree: Act 7 (wallet-sim 1.7.0 crash loop), 3 min baseline, then Act 4b (KYA
registry down). Both methods are called at the same moment through SPL on the same Act 4b incident:
  | makeresults | eval detector="wallet-sim error" | fit AITKContainer algo=tuktuk_sre method=<m> window="-12m" detector into app:tuktuk_sre
Changes the war-room panel (about 25 min). Results to $OUT_DIR/container-<act>-<method>.json.
Run: SPLUNK_O11Y_TOKEN=... CHAOS=<war-room URL> python3 -I aitk-container-tree-test.py [act7-then-act4b|act1]
"""
import importlib.util, json, os, pathlib, sys, threading, time, urllib.request
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))
from stack import S  # noqa: E402
spec = importlib.util.spec_from_file_location("harness", HERE / "aitk-tuning.py")
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)
CHAOS = os.environ["CHAOS"]
OUT = pathlib.Path(os.environ.get("OUT_DIR", "/tmp/aitk-container-test")); OUT.mkdir(parents=True, exist_ok=True)


def log(*a):
    print(time.strftime("%H:%M:%S", time.gmtime()), *a, flush=True)


def panel(name):
    urllib.request.urlopen(urllib.request.Request(f"{CHAOS}/scenarios/{name}", data=b"", method="POST"), timeout=20).read()


def wait_incident(fragment, since, limit=600):
    while time.time() - since < limit:
        time.sleep(30)
        try:
            inc = next((i for i in H.open_incident() if fragment in i["detectorName"]
                        and ((i.get("events") or [{}])[0].get("timestamp") or 0) / 1000 >= since - 30), None)
            if inc:
                return inc
        except Exception as e:  # transient API errors
            log("poll error", e)
    return None


def run(act, method, detector, res):
    t0 = time.time()
    spl = (f'| makeresults | eval detector="{detector}" | fit AITKContainer algo=tuktuk_sre method={method} window="-12m" '
           f'detector into app:tuktuk_sre')
    r = S.search(spl, earliest="-1m", app="Splunk_ML_Toolkit", wait=1800)
    row = (r.get("results") or [{}])[0]
    rec = {"act": act, "method": method, "seconds": round(time.time() - t0), "messages": [m.get("text", "")[:300] for m in (r.get("messages") or [])],
           **{k.replace("predicted_", ""): v for k, v in row.items() if k.startswith("predicted_")}}
    (OUT / f"container-{act}-{method}.json").write_text(json.dumps(rec, indent=1))
    res[method] = rec


def compare(act, detector):
    res = {}
    th = [threading.Thread(target=run, args=(act, m, detector, res)) for m in ("loop", "tree")]
    [t.start() for t in th]; [t.join() for t in th]
    for m in ("loop", "tree"):
        r = res.get(m, {})
        log(f"== {act} {m}: {r.get('seconds')} s | {r.get('model')} | USD {r.get('cost_usd')} | root cause {r.get('root_cause_service')}")
        print("   ", (r.get("summary") or str(r.get("messages")))[:400])
        if r.get("tree"):
            print(r["tree"])


mode = sys.argv[1] if len(sys.argv) > 1 else "act7-then-act4b"
if mode == "act7-then-act4b":
    panel("baseline"); log("baseline"); time.sleep(180)
    panel("act7"); log("act7 started (the leftover to avoid)"); time.sleep(420)
    panel("baseline"); log("baseline 3 min"); time.sleep(180)
    panel("act4b"); start = time.time(); log("act4b started")
    inc = wait_incident("wallet-sim error", start)
    log("incident", inc and inc["incidentId"])
    if inc:
        compare("act4b", "wallet-sim error")
else:
    panel("baseline"); log("baseline"); time.sleep(180)
    panel("act1"); start = time.time(); log("act1 started")
    inc = wait_incident("payment-router error", start)
    log("incident", inc and inc["incidentId"])
    if inc:
        compare("act1", "payment-router error")
panel("baseline"); log("done; panel on baseline")
