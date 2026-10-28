"""AI Toolkit container module (27 Oct 2026): runs the TukTukPay SRE agent (services/sre-agent) as the toolkit's
"model". The toolkit's container API loads app/model/<algo>.py and calls init/fit/save/load/summary/apply.

SPL:  ... rows with detector (or incident_id) ...
      | fit AITKContainer algo=tuktuk_sre window="-15m" into app:tuktuk_sre      (fit = init + fit + save + apply)
      | apply tuktuk_sre                                                          (later calls)
Each row = one alert. Columns read: incident_id, detector (a fragment is enough; matched against live open
incidents), or svc + evidence for an ML anomaly row (no detector). One case per row; policy `ask` (propose only).
Returns per row: case_id, state, root_cause_service, failure_mode, confidence, summary, proposed_action,
hypotheses (JSON), model, cost_usd, seconds.
"""
import json, time
import pandas as pd


def init(df, param):
    return {"created": time.time()}


def fit(model, df, param):
    return {"message": "TukTukPay SRE agent ready (no training)"}


def save(model, name):
    return model


def load(name):
    return {"loaded": name}


def summary(model=None):
    return {"version": {"sre_agent": "2026-10-27"}, "summary": "LLM SRE agent: Claude via Anthropic API, tools via MCP"}


def apply(model, df, param):
    """Hand the rows to the agent (Python 3.11 venv) and return its results as a dataframe."""
    import subprocess
    p = ((param or {}).get("options") or {}).get("params") or {}
    req = {"rows": [{k: (None if pd.isna(v) else v) for k, v in r.items()} for r in df.to_dict("records")],
           "window": str(p.get("window", "-15m")).strip('"'), "provider": str(p.get("provider", "anthropic")).strip('"'),
           "method": str(p.get("method", "")).strip('"')}
    run = subprocess.run(["/dltk/sre-venv/bin/python", "/dltk/sre-agent/aitk_runner.py"], input=json.dumps(req, default=str),
                         capture_output=True, text=True, timeout=1800)
    if run.returncode != 0:
        return pd.DataFrame([{"state": "error", "summary": (run.stderr or run.stdout)[-800:]}])
    return pd.DataFrame(json.loads(run.stdout.strip().splitlines()[-1])["results"])
