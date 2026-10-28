"""One-off (27 Oct 2026): AI Toolkit MCP (Model Context Protocol) connection `splunk_ec2_logs` to the Splunk MCP Server app
on the EC2 Splunk (https://splunk.example.com:8089/services/mcp), type SPLUNK (bearer token), with the encrypted
token of the least-privilege user sre_agent (search only, index=tuktukpay only; sre_agent_mcp_token.txt
line 1, never printed; expires 31 Oct). Tools offered to agents: the five log-reading ones below (no user lists, no alert
administration, no splunk_run_saved_search). Agents run in Splunk's cloud runtime, so port 8089 must admit the
Singapore agent runtime address 198.51.100.1 (Agent Launchpad allow list). Idempotent.
Run:  python3 -I setup-aitk-splunk-mcp.py
"""
import json, pathlib, sys
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "lib"))
from stack import S, BASE  # noqa: E402

NAME = "splunk_ec2_logs"
TOKEN, URL = (HERE / "sre_agent_mcp_token.txt").read_text().splitlines()[:2]
KEEP = ["splunk_run_query", "splunk_get_indexes", "splunk_get_sourcetypes", "splunk_get_metadata", "splunk_get_index_info"]
U = BASE + "/en-US/splunkd/__raw/servicesNS/admin/Splunk_ML_Toolkit/mltk/mcp_connection"
H = {**S.h, "Content-Type": "application/json"}

st, b = S._req(U + "?output_mode=json", headers=S.h, timeout=60)
if any(c.get("name") == NAME for c in json.loads(b)):
    sys.exit(f"{NAME} already exists; not changed")
# tool descriptions straight from the server (the toolkit's own list call runs on the instance and is not needed)
import urllib.request  # noqa: E402
r = urllib.request.Request(URL, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode(),
                           headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json",
                                    "Accept": "application/json, text/event-stream"})
body = urllib.request.urlopen(r, timeout=60).read().decode()
msgs = [json.loads(l[5:]) for l in body.splitlines() if l.startswith("data:")] or [json.loads(body)]
tools = [{"name": t["name"], "description": t.get("description", "")} for t in msgs[-1]["result"]["tools"] if t["name"] in KEEP]
print("tools from the server:", [t["name"] for t in tools])
payload = {"name": NAME, "type": "SPLUNK",
           "description": "Splunk Enterprise on EC2 (index=tuktukpay, structured JSON logs; field `event` names each log event). "
                          "Read-only user sre_agent.",
           "details": {"url": URL, "token": TOKEN}, "tools": tools, "approval_required_tools": []}
st, b = S._req(U, json.dumps(payload).encode(), H, timeout=120)
print("create ->", st, json.loads(b).get("message") if b.startswith("{") else b[:200])
