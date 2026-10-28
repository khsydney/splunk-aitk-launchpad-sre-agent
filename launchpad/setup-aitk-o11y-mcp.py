"""One-off (26 Oct 2026): AI Toolkit custom MCP (Model Context Protocol) connection to the Splunk Observability Cloud MCP
gateway on the EC2 Splunk, through the AI Toolkit's own API (the same calls as the Connections page):
  POST /servicesNS/admin/Splunk_ML_Toolkit/mltk/mcp_connection/tools   list the gateway's tools (nothing saved)
  POST /servicesNS/admin/Splunk_ML_Toolkit/mltk/mcp_connection         create (headers go to passwords.conf, encrypted)
  POST /servicesNS/admin/Splunk_ML_Toolkit/mltk/mcp_connection/test    the form's "Test connection"
The gateway needs X-SF-TOKEN and X-SF-REALM together (a bearer token alone lists 0 tools), so the connection is CUSTOM with
those as headers; the 41 tools of apm,metrics,detectors,dashboards are all read-only. The token comes from the
SPLUNK_O11Y_TOKEN environment variable and is never printed. Needs the admin user to hold role mltk_admin
(capability edit_agent_connections). The URL must be namespaced (/servicesNS/<user>/...; the handler checks that user, so not nobody): /services/... fails inside the handler.
Run:  python3 -I setup-aitk-o11y-mcp.py
"""
import json, os, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lib"))
from stack import S, BASE  # noqa: E402

NAME = "o11y_cloud_us1"
U = BASE + "/en-US/splunkd/__raw/servicesNS/admin/Splunk_ML_Toolkit/mltk/mcp_connection"
DETAILS = {"url": "https://region-pdx10.api.scs.splunk.com/system/mcp-gateway/v1/", "auth_type": "API_KEY",
           "headers": {"X-SF-TOKEN": os.environ["SPLUNK_O11Y_TOKEN"], "X-SF-REALM": "us1",
                       "X-SPLUNK-O11Y-TOOL-SETS": "apm,metrics,detectors,dashboards"}}
DESCRIPTION = ("Splunk Observability Cloud (realm us1, shared org your Observability Cloud org) through the hosted MCP gateway; "
               "41 read-only tools. Always filter on environment tuktukpay-demo and detectors named 'TukTukPay [tuktukpay-demo]'.")


def call(path, body=None):
    st, b = S._req(U + path + ("" if body is not None else "?output_mode=json"),
                   json.dumps(body).encode() if body is not None else None,
                   {**S.h, "Content-Type": "application/json"}, timeout=180)
    try:
        return st, json.loads(b)
    except ValueError:
        return st, {"raw": b[:300]}


st, ctx = S.get("/services/authentication/current-context")
caps = json.loads(ctx)["entry"][0]["content"]["capabilities"]
if "edit_agent_connections" not in caps:
    sys.exit("admin lacks edit_agent_connections: add role mltk_admin to the admin user first")

st, existing = call("")
if any((c.get("name") == NAME) for c in (existing if isinstance(existing, list) else [])):
    print(f"{NAME} already exists; not changed")
else:
    # The AI Toolkit's own list/test calls send tools/list without a session and read the reply with response.json();
    # the gateway always answers text/event-stream (Accept: application/json alone -> HTTP 406), so they fail with
    # "MCP server response parsing failed". Creating does not contact the server, and agents run in Splunk's cloud
    # runtime (scs .../agent/aws_agentcore/invoke), so the tool list comes from our own MCP client instead.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "services" / "sre-agent"))
    from sre_agent.o11y_mcp import O11yMCP
    tools = [{"name": t["name"], "description": t.get("description", "")} for t in O11yMCP().list_tools()]
    print("tools listed by the sre-agent MCP client:", len(tools))
    st, r = call("", {"name": NAME, "type": "CUSTOM", "description": DESCRIPTION, "details": DETAILS,
                      "tools": tools, "approval_required_tools": []})
    print("create ->", st, "|", str(r.get("message") or r.get("error_message"))[:200])
    if st != 200:
        sys.exit(1)

st, lst = call("")
for c in (lst if isinstance(lst, list) else []):
    if c.get("name") == NAME:
        print("listed:", c.get("name"), c.get("type"), (c.get("details") or {}).get("auth_type"), "| tools:", len(c.get("tools") or []),
              "| header names:", sorted((c.get("details") or {}).get("headers", {}).keys()))
