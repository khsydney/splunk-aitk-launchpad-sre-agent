"""Step 2 — create (or update) the Launchpad agent. Idempotent: re-run after changing config.env or the prompt.
Instructions: quickstart/prompts/sre_agent.md with your settings filled in. Tools: the connections from step 1
(a focused set of 13 Observability Cloud tools + 2 log tools; fewer tools = fewer wrong calls).
Run: python3 quickstart/02_agent.py"""
import sys as _s, pathlib as _p; _s.path.insert(0, str(_p.Path(__file__).resolve().parent))  # find _common.py
import time
from _common import cfg, aitk, ok, fail, prompt_text

O11Y_TOOLS = ["o11y_search_alerts_or_incidents", "o11y_get_incident_events", "o11y_analyze_incident", "o11y_get_apm_services_summary",
              "o11y_get_apm_service_errors_and_requests", "o11y_get_apm_service_latency", "o11y_get_apm_service_dependencies",
              "o11y_get_apm_service_dependency_errors_and_requests", "o11y_get_apm_service_dependency_latency",
              "o11y_get_apm_exemplar_traces_summary", "o11y_get_apm_trace_tool", "o11y_get_metric_names", "o11y_execute_signalflow_program"]
LOG_TOOLS = ["splunk_run_query", "splunk_get_sourcetypes"]
name = cfg.get("AGENT_NAME", required=True)

st, conns = aitk("mcp_connection")
by = {c["name"]: c for c in conns} if isinstance(conns, list) else {}
mcps = []
for cname, want in ((cfg.get("O11Y_MCP_CONNECTION", "o11y_cloud"), O11Y_TOOLS), (cfg.get("SPLUNK_MCP_CONNECTION", "splunk_logs"), LOG_TOOLS)):
    if cname in by:
        avail = {t["name"] if isinstance(t, dict) else t for t in by[cname].get("tools", [])}
        mcps.append({"name": cname, "tools": [t for t in want if t in avail], "approval_required_tools": []})
if not mcps:
    raise SystemExit("no MCP connections found: run step 1 first")
body = {"name": name, "description": f"SRE assistant for {cfg.get('PLATFORM_DESCRIPTION')} (read-only).", "system_prompt": prompt_text(),
        "llm": {"connection_name": cfg.get("LLM_CONNECTION", required=True), "provider": cfg.get("LLM_PROVIDER", required=True),
                "model": cfg.get("LLM_MODEL", required=True), "temperature": 0.2, "max_tokens": 16000},
        "mcps": mcps, "knowledge_bases": [], "agent_timeout": int(cfg.get("AGENT_TIMEOUT_S", "900"))}
st, cur = aitk(f"agents?output_mode=json&name={name}")
exists = st == 200 and name in str(cur)
if exists:
    c = cur[0] if isinstance(cur, list) else cur
    body["acl"] = ((c.get("versions") or c.get("details", {}).get("versions") or [{}])[0]).get("acl") or {}
st, r = aitk("agents", body, method="PUT" if exists else "POST")
if st != 200:
    fail(f"{'update' if exists else 'create'} agent: HTTP {st} {r}",
         "if the message is only 'Failed to create agent', look in $SPLUNK_HOME/var/log/splunk/mlspl.log (e.g. agent name rules)")
    raise SystemExit(1)
ok(f"{'updated' if exists else 'created'} agent {name}: {sum(len(m['tools']) for m in mcps)} tools, model {cfg.get('LLM_MODEL')}")
for _ in range(30):   # a new agent is provisioned in Splunk's cloud runtime
    st, cur = aitk(f"agents?output_mode=json&name={name}")
    c = cur[0] if isinstance(cur, list) and cur else cur
    state = ((c.get("versions") or c.get("details", {}).get("versions") or [{}])[0]).get("state") if isinstance(c, dict) else None
    if state == "Available":
        ok("agent is Available"); break
    time.sleep(10)
else:
    fail(f"agent state is still {state}", "wait a minute and check AI Toolkit > Agents; Cloud Connect must be linked")
