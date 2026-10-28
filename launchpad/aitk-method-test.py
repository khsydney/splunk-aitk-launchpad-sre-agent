"""Method test (27 Oct 2026): does the hypothesis tree beat the v15 checklist? Same model (Claude Sonnet 4.5) on both
sides: TukTukPaySREClaudeChecklist (v15 instructions unchanged) vs TukTukPaySREClaude (hypothesis tree). For each act:
3 min baseline, start the act, wait for the act's detector to open an incident after the start, run both agents on it
at once (aitk-compare-agents.py), back to baseline. Changes the war-room panel; about 12 min per act.
Run: SPLUNK_O11Y_TOKEN=... CHAOS=<war-room URL> python3 -I aitk-method-test.py [act ...]
"""
import importlib.util, os, pathlib, subprocess, sys, time, urllib.request
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))
spec = importlib.util.spec_from_file_location("harness", HERE / "aitk-tuning.py")
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)

CHAOS = os.environ["CHAOS"]
DETECTOR = {"act1": "payment-router error", "act2": "risk-engine p90", "act4b": "wallet-sim error",
            "act6": "container restarted", "act7": "container restarted"}
acts = sys.argv[1:] or ["act2", "act6", "act1", "act7", "act4b"]
env = {**os.environ, "COMPARE_AGENTS": "TukTukPaySREClaudeChecklist,TukTukPaySREClaude"}


def panel(name):
    urllib.request.urlopen(urllib.request.Request(f"{CHAOS}/scenarios/{name}", data=b"", method="POST"), timeout=20).read()


def log(*a):
    print(time.strftime("%H:%M:%S", time.gmtime()), *a, flush=True)


for act in acts:
    panel("baseline"); log("baseline before", act); time.sleep(180)
    panel(act); start = time.time(); log("started", act)
    inc = None
    while time.time() - start < 600 and not inc:
        time.sleep(30)
        try:
            inc = next((i for i in H.open_incident() if DETECTOR[act] in i["detectorName"]
                        and ((i.get("events") or [{}])[0].get("timestamp") or 0) / 1000 >= start - 30), None)
        except Exception as e:  # transient API errors: keep polling
            log("poll error", e)
    if not inc:
        log("no fresh incident for", act, "- skipped"); continue
    log("incident", inc["incidentId"], inc["detectorName"][27:])
    subprocess.run([sys.executable, "-I", str(HERE / "aitk-compare-agents.py"), f"m-{act}", "--detector", DETECTOR[act]], env=env)
panel("baseline"); log("done; panel on baseline")
