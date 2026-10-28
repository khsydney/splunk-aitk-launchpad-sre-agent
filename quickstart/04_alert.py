"""Step 4 — run the agent automatically when an Observability Cloud detector fires. Created DISABLED.
Needs detector alerts in Splunk: in Observability Cloud add a "Splunk platform" notification integration that sends
to a HEC (HTTP Event Collector) token for DETECTOR_ALERT_INDEX, and add it to your detectors' notifications.
How it works: a search every 2 minutes finds firing alerts, skips incidents the agent already took in the last
30 minutes (a lookup is written the moment a run starts), and ends in `| aiagent` so the alert's fields reach the
agent — the "Run AI Agent" alert action does not pass them. At most 3 incidents per run.
Run: python3 quickstart/04_alert.py [--enable | --disable]"""
import sys as _s, pathlib as _p; _s.path.insert(0, str(_p.Path(__file__).resolve().parent))  # find _common.py
import json, sys, urllib.parse
from _common import S, cfg, ok, fail

NAME = cfg.get("ALERT_NAME", "SRE agent - investigate detector alerts")
AGENT, ENV, IDX = cfg.get("AGENT_NAME", required=True), cfg.get("O11Y_ENVIRONMENT", required=True), cfg.get("DETECTOR_ALERT_INDEX", "main")
PREFIX = cfg.get("O11Y_DETECTOR_PREFIX", "")
LOOKUP = "sre_agent_started.csv"
APP = "/servicesNS/admin/Splunk_ML_Toolkit"
path = f"{APP}/saved/searches/{urllib.parse.quote(NAME, safe='')}"

if len(sys.argv) > 1 and sys.argv[1] in ("--enable", "--disable"):
    st, _ = S.post(f"{path}/{sys.argv[1][2:]}", {}); (ok if st == 200 else fail)(f"{sys.argv[1][2:]} -> HTTP {st}"); raise SystemExit

# the lookup must exist before the alert's subsearch reads it
S.search(f'| makeresults | eval incidentId="none", started=0 | table incidentId started | outputlookup {LOOKUP}', earliest="-1m", app="Splunk_ML_Toolkit", wait=60) \
    if "incidentId" not in json.dumps(S.search(f"| inputlookup {LOOKUP} | head 1", earliest="-1m", app="Splunk_ML_Toolkit", wait=60)) else None
PROMPT = ("A Splunk Observability Cloud detector is firing: {signature} (severity {severity}, service {service}, incident {incidentId}). "
          f"Investigate it in environment {ENV}: confirm it is still firing, find the service where the fault starts (the alerting "
          "service may only show the symptom), give the evidence with numbers and times, and recommend one action for a human to approve.")
SEARCH = (f'index={IDX} sourcetype=splunk_o11y_cloud_hec_alert vendor_severity!=ok' + (f' signature="{PREFIX}*"' if PREFIX else "") +
          ' | eval service=coalesce(\'sflo_dimensions.sf_service\', \'service.name\', \'sflo_dimensions.k8s.deployment.name\', '
          '\'sflo_dimensions.k8s.container.name\', "unknown") '
          '| stats latest(_time) as t latest(vendor_severity) as severity by signature service incidentId '
          f'| search NOT [| inputlookup {LOOKUP} | where started > relative_time(now(), "-30m") | append [| makeresults | eval incidentId="none"] | fields incidentId] '
          '| sort - t | head 3 '
          f'| eval started=now() | outputlookup append=true {LOOKUP} '
          f'| aiagent agent_name="{AGENT}" prompt="{PROMPT}" trigger=Alert source="{NAME}"')
FORM = {"search": SEARCH, "description": f"Runs the AI Toolkit agent {AGENT} for each firing Observability Cloud detector (once per incident).",
        "is_scheduled": "1", "cron_schedule": "*/2 * * * *", "dispatch.earliest_time": "-5m", "dispatch.latest_time": "now"}
st, _ = S.get(path)
st, b = S.post(path, FORM) if st == 200 else S.post(f"{APP}/saved/searches", {"name": NAME, "disabled": "1", **FORM})
if st not in (200, 201):
    fail(f"save alert: HTTP {st} {b[:300]}"); raise SystemExit(1)
c = json.loads(S.get(path)[1])["entry"][0]["content"]
ok(f"saved '{NAME}' (every 2 min, {'DISABLED' if c.get('disabled') in (True, '1', 1) else 'enabled'}); enable with: python3 quickstart/04_alert.py --enable")
r = S.search(f'index={IDX} sourcetype=splunk_o11y_cloud_hec_alert earliest=-24h | stats count', earliest="-24h", wait=60)
n = int(((r.get("results") or [{}])[0]).get("count", 0))
(ok(f"{n} detector alert events in index {IDX} in the last 24 h") if n else
 fail(f"no detector alerts in index {IDX} yet", "add a 'Splunk platform' notification integration in Observability Cloud (see the script header)"))
