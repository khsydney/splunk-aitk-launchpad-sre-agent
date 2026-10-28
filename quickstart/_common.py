"""Shared helpers for the quick-start steps."""
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import config as cfg  # noqa: E402  (loads config.env first)
from stack import S, BASE  # noqa: E402

AITK = BASE + "/en-US/splunkd/__raw/servicesNS/admin/Splunk_ML_Toolkit/mltk/"
JSON_H = {**S.h, "Content-Type": "application/json"}


def aitk(path, body=None, method=None, timeout=180):
    """Call the AI Toolkit REST API (namespaced as admin: plain /services/... fails inside the toolkit's handler)."""
    import urllib.request
    data = json.dumps(body).encode() if body is not None else None
    url = AITK + path + ("" if body is not None or "?" in path else "?output_mode=json")
    r = urllib.request.Request(url, data=data, headers=JSON_H if data else S.h, method=method or ("POST" if data else "GET"))
    try:
        with S.op.open(r, timeout=timeout) as x:
            raw = x.read().decode()
            st = x.status
    except Exception as e:  # noqa: BLE001
        st = getattr(e, "code", 0); raw = e.read().decode() if hasattr(e, "read") else str(e)
    try:
        return st, json.loads(raw)
    except ValueError:
        return st, {"raw": raw[:300]}


def ok(msg, fix=""):
    print("  ✓ " + msg)


def fail(msg, fix=""):
    print("  ✗ " + msg + (f"\n      fix: {fix}" if fix else ""))


def o11y_headers():
    return {"X-SF-TOKEN": cfg.secret_from_file("O11Y_TOKEN_FILE"), "X-SF-REALM": cfg.get("O11Y_REALM", "us1"),
            "X-SPLUNK-O11Y-TOOL-SETS": cfg.get("O11Y_TOOL_SETS", "apm,metrics,detectors,dashboards")}


def prompt_text():
    det = cfg.get("O11Y_DETECTOR_PREFIX", "")
    t = (ROOT / "quickstart" / "prompts" / "sre_agent.md").read_text()
    vals = {"PLATFORM_DESCRIPTION": cfg.get("PLATFORM_DESCRIPTION", "a web platform"), "O11Y_ENVIRONMENT": cfg.get("O11Y_ENVIRONMENT", required=True),
            "DETECTOR_SCOPE": f'; detectors whose names start with "{det}" only' if det else "", "LOG_INDEX": cfg.get("LOG_INDEX", "main"),
            "LOG_SCHEMA": cfg.get("LOG_SCHEMA", "search errors by severity or log level"), "O11Y_REALM": cfg.get("O11Y_REALM", "us1"),
            "SPLUNK_WEB_URL": cfg.get("SPLUNK_WEB_URL", required=True).rstrip("/")}
    for k, v in vals.items():
        t = t.replace("{" + k + "}", v)
    return t
