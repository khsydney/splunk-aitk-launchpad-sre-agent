"""One-off (26 Oct 2026): AI Toolkit agent TukTukPaySRE on the EC2 Splunk, through the AI Toolkit API
(POST /servicesNS/admin/Splunk_ML_Toolkit/mltk/agents). LLM: connection splunk_hosted_gpt_oss_120b (Splunk Hosted
Models, OpenAI GPT-OSS 120B, through the Cloud Connect tenant). MCP: o11y_cloud_us1 with every tool it lists (all
read-only). The agent runs in Splunk's cloud runtime (AWS AgentCore). Idempotent: skips if the agent exists.
Run:  python3 -I setup-aitk-agent.py
"""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "lib"))
from stack import S, BASE  # noqa: E402

NS = BASE + "/en-US/splunkd/__raw/servicesNS/admin/Splunk_ML_Toolkit/mltk/"
H = {**S.h, "Content-Type": "application/json"}
NAME = "TukTukPaySRE"
SYSTEM_PROMPT = """You are the SRE (site reliability engineering) assistant for TukTukPay, a simulated Thai payment gateway used in a workshop. All latencies, outages and payments are simulated.

Scope (the Observability Cloud org is shared with other teams):
- Only use APM environment tuktukpay-demo (sf_environment / deployment.environment = tuktukpay-demo). Never report on other environments.
- Only use detectors whose names start with "TukTukPay [tuktukpay-demo]". When searching alerts or incidents, always pass that detector name.
- Services: checkout-api, risk-engine, payment-router, acquirer-sim (acquirers acq-kbank, acq-uob, acq-cimb, acq-alipayplus, acq-itmx), ledger, webhook-dispatcher, merchant-copilot, shopping-agent, wallet-sim, merchant-sim.

Method: start from the alert or symptom; check service health, errors and latency; follow dependencies to the service where the fault starts (the alerting service is often not the root cause); confirm with traces or metrics. Give numbers and time ranges. Say plainly what you could not check.

You are read-only: you cannot change anything. End with: what is broken, where, since when, the evidence, and the recommended action for a human to approve."""

st, b = S._req(NS + "agents?output_mode=json", headers=S.h, timeout=60)
if st == 200 and NAME in b:
    sys.exit(f"agent {NAME} already exists; not changed")
st, b = S._req(NS + "mcp_connection?output_mode=json", headers=S.h, timeout=60)
conn = next(c for c in json.loads(b) if c.get("name") == "o11y_cloud_us1")
tools = [t["name"] if isinstance(t, dict) else t for t in conn.get("tools", [])]
body = {
    "name": NAME,
    "description": "TukTukPay war-room SRE assistant: investigates tuktukpay-demo alerts in Splunk Observability Cloud (read-only).",
    "system_prompt": SYSTEM_PROMPT,
    "llm": {"connection_name": "splunk_hosted_gpt_oss_120b", "provider": "Splunk Hosted Models", "model": "OpenAI GPT-OSS 120B",
            "temperature": 0.2, "max_tokens": 5000, "reasoning_effort": "medium"},
    "mcps": [{"name": "o11y_cloud_us1", "tools": tools, "approval_required_tools": []}],
    "knowledge_bases": [],
}
st, b = S._req(NS + "agents", json.dumps(body).encode(), H, timeout=180)
print("create agent ->", st, b[:400])
