"""AI Toolkit agent TukTukPaySREClaude (27 Oct 2026): Claude Sonnet 5.5 with a Bits-AI-style hypothesis tree. Idempotent.

1. LLM connection `anthropic_sonnet_5_5` (provider Anthropic, model claude-sonnet-5-5); key = ANTHROPIC_API_KEY from the
   repo-root .env, sent only in the request body (stored encrypted by the AI Toolkit). Tested first (`test_connection`).
2. Agent TukTukPaySREClaude (agent names must be alphanumeric — the cloud runtime rejects "-"): copies TukTukPaySRE's current instructions (v15), MCP tools and timeout, and replaces the
   checklist with a hypothesis-tree method (competing hypotheses, validated / invalidated / inconclusive, "why?"
   children under validated ones up to depth 3, invalidated branches pruned) plus a "Hypothesis tree" answer section.
   TukTukPaySRE itself is not changed.
Run: python3 -I setup-aitk-claude-agent.py [update] [checklist]
   `checklist` creates the control agent TukTukPaySREClaudeChecklist (same model, TukTukPaySRE's instructions unchanged).
"""
import json, pathlib, re, sys, urllib.request
ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "lib"))
from stack import S, BASE  # noqa: E402

NS = BASE + "/en-US/splunkd/__raw/servicesNS/admin/Splunk_ML_Toolkit/mltk/"
CONN, MODEL, AGENT, SOURCE = "anthropic_sonnet_4_5", "claude-sonnet-4-5-20250929", "TukTukPaySREClaude", "TukTukPaySRE"
PLAIN = "checklist" in sys.argv   # control for the method test: same model, TukTukPaySRE's instructions unchanged
if PLAIN:
    AGENT = "TukTukPaySREClaudeChecklist"
# Sonnet 5.5 / Opus 5.5 cannot run as AI Toolkit agents: the cloud runtime sends thinking={"type":"disabled"}, which they
# reject (HTTP 400); the connection test passes because it runs on the instance. Sonnet 4.5 works (tested 27 Oct).


def call(method, path, body=None):
    r = urllib.request.Request(NS + path, data=json.dumps(body).encode() if body is not None else None, method=method,
                               headers={**S.h, "Content-Type": "application/json"})
    try:
        with S.op.open(r, timeout=300) as x:
            return x.status, x.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def key():
    for line in (ROOT / ".env").read_text().splitlines():
        m = re.match(r"\s*ANTHROPIC_API_KEY\s*=\s*(.*)", line)
        if m:
            return m.group(1).split(" #")[0].strip().strip("\"'")
    sys.exit("ANTHROPIC_API_KEY not in .env")


METHOD = """Method: investigate as a hypothesis tree, the way an experienced SRE does. Before calling any tool, write the plan below; keep it updated as you go.
1. Orient (2-3 calls): read the incident events (onset, still active?), then requests, errors and latency of the alerting service broken down by its tags, and its dependencies as seen from the caller.
2. Branch: write 2-4 competing top-level hypotheses, H1, H2, ... Always include "the fault is inside the alerting service itself" and "a dependency it calls is failing or slow"; add "a change (release, configuration, traffic)" or "resource saturation (CPU, memory against limits)" when the evidence hints at it.
3. Test one hypothesis at a time with the single most discriminating tool call, and say which hypothesis each call tests. Mark each one validated (evidence supports it), invalidated (evidence contradicts it) or inconclusive (not measurable), citing the number that decided it.
4. Deepen: for every validated hypothesis ask "why?" and open 1-3 more specific child hypotheses (H2.1, H2.2, ...) naming a narrower component: which dependency, then which partner, instance, version, setting or field value. Do not expand invalidated branches (prune them). Stop at depth 3, or when a validated leaf names the component precisely and no narrower hypothesis can be tested.
5. Evidence a leaf must have before you call it the root cause: at least two independent signals, one metric or trace AND one log. For logs, run `| fieldsummary maxvals=5` on the warn and error events of the services involved, then compare each identifying field's values in those events with the same field over all events of that service: a value rare overall but common among bad events is the suspect. For traces, take a trace ID from the exemplar tool, open the full trace and list the calls to other services in time order (target from url.full or server.address, including any identifier in the path) with duration and result: the first call that failed or was slow is where the fault starts; later calls to another target are retries or fallbacks, i.e. effects. Make sure a fallback target has its own hypothesis and that it is invalidated or explained.
6. Decide: the root cause is the deepest validated leaf that is the earliest change explaining the alert. If aggregated metric tags and per-call evidence (a span's target, a log event's own fields) disagree, trust the per-call evidence and say so. Quote names exactly as tools returned them.
"""

TREE_SECTION = """2b. Hypothesis tree: a code block with every hypothesis you opened, indented by depth, each line "H<id> <statement> ... ✓ validated | ✗ invalidated | ~ inconclusive (<the deciding number or fact>)", and "◀ root cause" on the chosen leaf. Example (illustrative names only):
   ```
   order-service error rate high
   ├─ H1 order-service itself is faulty ........ ✗ invalidated (all errors are stock_timeout)
   ├─ H2 a dependency is failing ............... ✓ validated (stock-db calls 3.0 s timeout)
   │   ├─ H2.1 stock-db shard-2 ................ ✓ validated (first failing span, 100% of bad logs)  ◀ root cause
   │   └─ H2.2 stock-db shard-3 ................ ✗ invalidated (retry target, 45 ms, 0 errors)
   └─ H3 traffic surge ......................... ✗ invalidated (request rate flat)
   ```
"""


def build_prompt(base: str) -> str:
    start = base.index("Before calling any tool, write your plan as this checklist")
    end = base.index("Rules:")
    p = base[:start] + METHOD + "\n" + base[end:]
    p = p.replace("Do not answer until items 1 to 6 are done or marked failed.",
                  "Do not answer until every open hypothesis is validated, invalidated or inconclusive and the leaf evidence in step 5 was attempted (say so if a call failed).")
    anchor = "3. Evidence: a table"
    assert anchor in p, "answer format changed in the source agent"
    return p.replace(anchor, TREE_SECTION + anchor, 1)


# 1. LLM connection
st, b = call("GET", "aicommander?output_mode=json")
have = {c["name"] for c in json.loads(b).get("data", [])}
details = {"endpoint": "https://api.anthropic.com/v1/messages", "request_timeout": 200, "access_token": key()}
if CONN not in have:
    st, b = call("POST", "aicommander", {"action": "test_connection", "provider": "Anthropic", "model": MODEL, "name": CONN, "connection_details": details})
    print("test connection ->", st, json.loads(b).get("message"))
    if st != 200:
        sys.exit(1)
    st, b = call("POST", "aicommander", {"name": CONN, "provider": "Anthropic", "model": MODEL, "is_custom": False, "llm_params": {},
                                         "description": "Claude Sonnet 5.5 (Anthropic API) for TukTukPaySREClaude", "connection_details": details})
    print("create connection ->", st, json.loads(b).get("message"))
    if st != 200:
        sys.exit(1)
else:
    print("connection", CONN, "exists")

# 2. agent
st, b = call("GET", f"agents?output_mode=json&name={SOURCE}")
d = json.loads(b); src = (d[0] if isinstance(d, list) else d)
v = (src.get("versions") or src.get("details", {}).get("versions"))[0]
mcps = [{"name": m["name"], "tools": m["tools"], "approval_required_tools": m.get("approval_required_tools", [])} for m in v["tools"]["mcps"]]
body = {
    "name": AGENT,
    "description": ("TukTukPaySRE instructions (v15 checklist) on Claude Sonnet 4.5: control for the hypothesis-tree test, 27 Oct." if PLAIN else
                    "TukTukPaySRE with Claude Sonnet 4.5 and a hypothesis-tree method (comparison with the GPT-OSS agent, 27 Oct)."),
    "system_prompt": v["system_prompt"] if PLAIN else build_prompt(v["system_prompt"]),
    "llm": {"connection_name": CONN, "provider": "Anthropic", "model": MODEL, "temperature": 0.2, "max_tokens": 16000},
    "mcps": mcps, "knowledge_bases": [], "agent_timeout": v.get("agent_timeout", 900),
}
st, b = call("GET", f"agents?output_mode=json&name={AGENT}")
exists = st == 200 and AGENT in b
if exists and "update" not in sys.argv:
    print("agent", AGENT, "exists; pass 'update' to replace its instructions")
else:
    if exists:
        cur = json.loads(b); cur = cur[0] if isinstance(cur, list) else cur
        body["acl"] = ((cur.get("versions") or cur.get("details", {}).get("versions"))[0]).get("acl") or {}
    st, b = call("PUT" if exists else "POST", "agents", body)
    print(("update" if exists else "create"), "agent ->", st, b[:300])
st, b = call("GET", f"agents?output_mode=json&name={AGENT}")
a = json.loads(b); a = a[0] if isinstance(a, list) else a
av = (a.get("versions") or a.get("details", {}).get("versions") or [{}])[0]
print("agent state:", av.get("state"), "| model", av.get("llm", {}).get("model"), "| tools", [(m["name"], len(m["tools"])) for m in av.get("tools", {}).get("mcps", [])],
      "| prompt chars", len(av.get("system_prompt", "")), "| timeout", av.get("agent_timeout"))
