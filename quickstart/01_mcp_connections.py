"""Step 1 — create the agent's MCP (Model Context Protocol) tool connections in the AI Toolkit. Idempotent.
  * Observability Cloud (APM, metrics, traces, detectors, incidents) through the hosted MCP gateway — always.
  * Splunk logs through the Splunk MCP Server app — when SPLUNK_MCP_URL is set.
The tool list is fetched by this script (the toolkit's own list/test cannot read the gateway's event-stream replies;
creating the connection does not contact the server). The token is stored encrypted by the AI Toolkit.
Run: python3 quickstart/01_mcp_connections.py"""
import sys as _s, pathlib as _p; _s.path.insert(0, str(_p.Path(__file__).resolve().parent))  # find _common.py
import sys
from _common import cfg, aitk, ok, fail, o11y_headers
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "lib"))
from mcp import MCP

st, existing = aitk("mcp_connection")
have = {c.get("name") for c in existing} if isinstance(existing, list) else set()

name = cfg.get("O11Y_MCP_CONNECTION", "o11y_cloud")
if name in have:
    ok(f"{name} already exists (not changed)")
else:
    h = o11y_headers()
    tools = [{"name": t["name"], "description": t.get("description", "")} for t in MCP(cfg.get("O11Y_MCP_URL"), h).list_tools()]
    st, r = aitk("mcp_connection", {"name": name, "type": "CUSTOM", "approval_required_tools": [], "tools": tools,
                                    "description": f"Splunk Observability Cloud (realm {cfg.get('O11Y_REALM')}), read-only tools. "
                                                   f"Always filter on environment {cfg.get('O11Y_ENVIRONMENT')}.",
                                    "details": {"url": cfg.get("O11Y_MCP_URL"), "auth_type": "API_KEY", "headers": h}})
    (ok(f"created {name} with {len(tools)} tools") if st == 200 else fail(f"create {name}: HTTP {st} {r}"))

if cfg.get("SPLUNK_MCP_URL"):
    name = cfg.get("SPLUNK_MCP_CONNECTION", "splunk_logs")
    if name in have:
        ok(f"{name} already exists (not changed)")
    else:
        token = cfg.secret_from_file("SPLUNK_MCP_TOKEN_FILE")
        keep = {"splunk_run_query", "splunk_get_indexes", "splunk_get_sourcetypes", "splunk_get_metadata", "splunk_get_index_info"}
        allt = MCP(cfg.get("SPLUNK_MCP_URL"), {"Authorization": "Bearer " + token}, verify=cfg.get("SPLUNK_VERIFY_TLS", "true") != "false").list_tools()
        tools = [{"name": t["name"], "description": t.get("description", "")} for t in allt if t["name"] in keep]
        st, r = aitk("mcp_connection", {"name": name, "type": "SPLUNK", "approval_required_tools": [], "tools": tools,
                                        "description": f"Splunk logs (index {cfg.get('LOG_INDEX')}), read-only user.",
                                        "details": {"url": cfg.get("SPLUNK_MCP_URL"), "token": token}})
        (ok(f"created {name} with {len(tools)} tools") if st == 200 else fail(f"create {name}: HTTP {st} {r}"))
else:
    print("  - SPLUNK_MCP_URL not set: no log tools (the agent will use metrics and traces only)")
