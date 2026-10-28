"""One-off (26 Oct 2026): Splunk alert that runs the AI Toolkit agent TukTukPaySRE when one of our Observability Cloud
detectors fires. Source: index=tuktukpay sourcetype=splunk_o11y_cloud_hec_alert (SplunkPlatform integration HVkc_mLAwAM,
default template). Every minute over the last 3 minutes, firing events only (vendor_severity != ok), our detectors only;
the service comes from the dimensions or else the first word of the detector name (our detectors aggregate the service away); one agent run per detector (per-result trigger), throttled once per incident (incidentId, from the integration template since 26 Oct 17:07Z) for 15 minutes. The prompt carries only
fields without free text (signature, severity, service, detector link): the action wraps it in prompt="...", so a quote
inside a field would break the command. Saved in the Splunk_ML_Toolkit app (where the aiagent command lives).
Idempotent: updates the search if it exists.
Run:  python3 -I setup-alert-to-agent.py
"""
import json, pathlib, sys, urllib.parse
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "lib"))
from stack import S  # noqa: E402

NAME = "TukTukPay - Observability Cloud alert runs TukTukPaySRE"
SEARCH = ('index=tuktukpay sourcetype=splunk_o11y_cloud_hec_alert signature="TukTukPay [tuktukpay-demo]*" vendor_severity!=ok '
          '| rex field=signature "^TukTukPay \\[tuktukpay-demo\\] (?<named>[A-Za-z-]+)" '
          '| eval service=coalesce(\'sflo_dimensions.sf_service\', \'service.name\', \'sflo_dimensions.k8s.deployment.name\', '
          '\'sflo_dimensions.k8s.container.name\', named) '
          '| stats latest(_time) as _time latest(vendor_severity) as severity latest(itsiDrilldownURI) as detector_url by signature service incidentId '
          '| sort - _time')
PROMPT = ("A Splunk Observability Cloud detector is firing: $result.signature$ (severity $result.severity$, service $result.service$, "
          "detector $result.detector_url$). Investigate it in environment tuktukpay-demo: confirm it is still firing, find the service "
          "where the fault starts (the alerting service may only show the symptom), give the evidence with numbers and times, and "
          "recommend one action for a human to approve.")
FORM = {
    "search": SEARCH, "description": "Runs the AI Toolkit agent TukTukPaySRE for each firing tuktukpay-demo detector (Observability Cloud -> HEC -> this search).",
    "is_scheduled": "1", "cron_schedule": "* * * * *", "dispatch.earliest_time": "-3m", "dispatch.latest_time": "now",
    "alert_type": "number of events", "alert_comparator": "greater than", "alert_threshold": "0",
    "alert.digest_mode": "0", "alert.suppress": "1", "alert.suppress.fields": "incidentId", "alert.suppress.period": "15m",
    "alert.track": "1", "alert.severity": "4",
    "actions": "run_aiagent", "action.run_aiagent": "1",
    "action.run_aiagent.param.agent_name": "TukTukPaySRE", "action.run_aiagent.param.prompt": PROMPT,
}
base = "/servicesNS/admin/Splunk_ML_Toolkit/saved/searches"
st, _ = S.get(f"{base}/{urllib.parse.quote(NAME, safe='')}")
if st == 200:
    st, b = S.post(f"{base}/{urllib.parse.quote(NAME, safe='')}", FORM)
    print("update ->", st)
else:
    st, b = S.post(base, {"name": NAME, **FORM})
    print("create ->", st)
if st not in (200, 201):
    sys.exit(b[:400])
st, b = S.get(f"{base}/{urllib.parse.quote(NAME, safe='')}")
c = json.loads(b)["entry"][0]["content"]
print("saved:", NAME, "| scheduled", c.get("is_scheduled"), "| cron", c.get("cron_schedule"), "| actions", c.get("actions"),
      "| agent", c.get("action.run_aiagent.param.agent_name"), "| throttle", c.get("alert.suppress.period"), "by", c.get("alert.suppress.fields"))
