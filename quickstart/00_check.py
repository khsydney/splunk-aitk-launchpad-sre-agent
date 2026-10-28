"""Step 0 — check everything the agent needs, before creating anything. Read-only.
Run: python3 quickstart/00_check.py"""
import sys as _s, pathlib as _p; _s.path.insert(0, str(_p.Path(__file__).resolve().parent))  # find _common.py
import json, re
from _common import S, cfg, aitk, ok, fail, o11y_headers
import sys; sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "lib"))
from mcp import MCP

print("Splunk")
if not S.ok:
    fail("cannot log in to " + cfg.get("SPLUNK_WEB_URL", ""), "check SPLUNK_WEB_URL and the user/password in SPLUNK_CREDS_FILE"); raise SystemExit(1)
ok("logged in to " + cfg.get("SPLUNK_WEB_URL"))
st, b = S.get("/services/server/info")
ver = json.loads(b)["entry"][0]["content"].get("version", "?"); ok(f"Splunk {ver}")
st, b = S.get("/services/apps/local", count=0)
apps = {e["name"]: e["content"] for e in json.loads(b)["entry"]}
NEED = {"Splunk_ML_Toolkit": ("AI Toolkit", "6.2", "Splunkbase app 2890"), "splunk_cloud_connect": ("Splunk Cloud Connect", "1.1", "Splunkbase app 8772; link it to a Splunk Cloud tenant (Launchpad agents run there)")}
OPTIONAL = {"Splunk_MCP_Server": ("Splunk MCP Server (logs for the agent)", "Splunkbase app 7931"), "splunk_ta_sim": ("Infrastructure Monitoring Add-on (step 5)", "Splunkbase app 5247")}
for app, (label, minv, fix) in NEED.items():
    c = apps.get(app)
    if not c or c.get("disabled"):
        fail(f"{label} not installed or disabled", fix)
    else:
        v = c.get("version", "0")
        (ok if tuple(map(int, re.findall(r"\d+", v)[:2])) >= tuple(map(int, minv.split("."))) else fail)(f"{label} {v}" + ("" if v >= minv else f" (need {minv}+)"))
for app, (label, fix) in OPTIONAL.items():
    (ok(f"{label} installed") if app in apps else print(f"  - {label}: not installed (optional; {fix})"))
st, b = S.get("/services/authentication/current-context")
caps = set(json.loads(b)["entry"][0]["content"].get("capabilities", []))
(ok("user can manage agent connections") if "edit_agent_connections" in caps else
 fail("user lacks capability edit_agent_connections", "give the user the role mltk_admin (Settings > Users)"))

print("AI Toolkit")
st, d = aitk("aicommander")
conns = {c["name"]: c for c in (d.get("data") or [])} if isinstance(d, dict) else {}
name = cfg.get("LLM_CONNECTION", "")
if name in conns:
    c = conns[name]; ok(f"LLM connection {name}: {c.get('provider')} / {c.get('model')}")
    if "claude" in str(c.get("model", "")).lower() and re.search(r"(sonnet|opus|haiku)-5(?:-|$)|5\.5", str(c.get("model")).lower()):
        fail("this Claude model rejects the Launchpad runtime's fixed `thinking: disabled`", "use claude-sonnet-4-5-20250929, or the container agent (agent-container/)")
else:
    fail(f"LLM connection '{name}' not found (have: {', '.join(conns) or 'none'})", "AI Toolkit > Connections > + Connection > LLM, then set LLM_CONNECTION")
if not re.fullmatch(r"[A-Za-z0-9]+", cfg.get("AGENT_NAME", "")):
    fail(f"AGENT_NAME '{cfg.get('AGENT_NAME')}' must be letters and digits only", "Launchpad's runtime rejects other characters")
else:
    ok(f"agent name {cfg.get('AGENT_NAME')}")

print("Observability Cloud")
try:
    tools = MCP(cfg.get("O11Y_MCP_URL"), o11y_headers()).list_tools()
    ok(f"MCP gateway: {len(tools)} tools for realm {cfg.get('O11Y_REALM')}")
except Exception as e:  # noqa: BLE001
    fail(f"MCP gateway: {type(e).__name__}: {str(e)[:150]}", "check O11Y_TOKEN_FILE (an API token), O11Y_REALM and O11Y_MCP_URL")

print("Logs")
r = S.search(f"index={cfg.get('LOG_INDEX', 'main')} earliest=-1h | stats count", earliest="-1h", wait=60)
n = int(((r.get("results") or [{}])[0]).get("count", 0))
(ok(f"index {cfg.get('LOG_INDEX')}: {n} events in the last hour") if n else fail(f"index {cfg.get('LOG_INDEX')} has no events in the last hour", "set LOG_INDEX to the index with your application logs"))
if cfg.get("SPLUNK_MCP_URL"):
    try:
        tools = MCP(cfg.get("SPLUNK_MCP_URL"), {"Authorization": "Bearer " + cfg.secret_from_file("SPLUNK_MCP_TOKEN_FILE")},
                    verify=cfg.get("SPLUNK_VERIFY_TLS", "true") != "false").list_tools()
        ok(f"Splunk MCP Server: {len(tools)} tools")
    except Exception as e:  # noqa: BLE001
        fail(f"Splunk MCP Server: {type(e).__name__}: {str(e)[:150]}", "check SPLUNK_MCP_URL (port 8089, /services/mcp) and SPLUNK_MCP_TOKEN_FILE")
else:
    print("  - Splunk MCP Server not configured: the agent will see metrics and traces but not logs")
