# Getting started

Spin up an AI SRE (site reliability engineering) agent in the Splunk AI Toolkit's **Agent Launchpad**, connected to
Splunk Observability Cloud (metrics, traces, detectors) and your Splunk logs. About **30 minutes** for the core path.

```
Core path (agent you can ask questions):        0 check → 1 tool connections → 2 agent → 3 ask it
Automatic investigations (optional):            4 detector alerts → agent      5 ML anomaly detection → agent
Extras (optional):                              SRE Agent app · own agent in a container · more detection modules
```

Everything runs from your laptop against your Splunk search head; scripts only use Splunk Web's REST API. Each step is
safe to re-run.

---

## Before you start (one-time, in Splunk Web)

| Need | Where | Why |
|---|---|---|
| **AI Toolkit 6.2+** and **Python for Scientific Computing** | Splunkbase 2890, 2882 | the agent framework |
| **Splunk Cloud Connect**, linked to a Splunk Cloud tenant | Splunkbase 8772 → its setup page (one-time passcode by e-mail) | Launchpad agents run in Splunk's cloud runtime |
| An **LLM connection** | AI Toolkit → Connections → + Connection → LLM | the model the agent uses (see below) |
| Role **`mltk_admin`** on your user | Settings → Users | to create agent connections |
| *Recommended:* **Splunk MCP Server** app + an encrypted token for a read-only user | Splunkbase 7931 | lets the agent search your logs |
| *Step 5 only:* **Splunk Infrastructure Monitoring Add-on** | Splunkbase 5247 | APM metrics in SPL (`| sim flow`) |
| An **Observability Cloud API token** (read) | Observability Cloud → Settings → Access Tokens | the agent's metrics and traces tools |
| Python 3.9+ on your laptop | — | standard library only |

**Which model?** Splunk-hosted **GPT-OSS 120B** works out of the box. **Claude Sonnet 4.5** (`claude-sonnet-4-5-20250929`)
works through an Anthropic connection and was more accurate in our tests. **Claude Sonnet / Opus 5.5 do not work in
Launchpad** (its runtime sends a thinking setting they reject) — use the container agent for those.

When you create an **Anthropic** connection, fill in the endpoint (`https://api.anthropic.com/v1/messages`) *at creation*;
editing it later drops the endpoint.

---

## Configure

```bash
git clone https://github.com/khsydney/splunk-aitk-launchpad-sre-agent.git && cd splunk-aitk-launchpad-sre-agent
cp config.env.example config.env        # git-ignored
printf 'admin\nYOUR_PASSWORD\n' > ~/.splunk_creds && chmod 600 ~/.splunk_creds
printf 'YOUR_O11Y_API_TOKEN\n'  > ~/.o11y_token    && chmod 600 ~/.o11y_token
```

Edit `config.env`. The ones you must change:

| Setting | Example | Meaning |
|---|---|---|
| `SPLUNK_WEB_URL` | `https://splunk.mycorp.com:8000` | Splunk Web as you open it |
| `O11Y_REALM` | `us1` | your Observability Cloud realm |
| `O11Y_ENVIRONMENT` | `prod` | the APM environment the agent may look at |
| `LOG_INDEX` | `app_logs` | where your application logs are |
| `LLM_CONNECTION` / `LLM_PROVIDER` / `LLM_MODEL` | `splunk_hosted_gpt_oss_120b` / `Splunk Hosted Models` / `OpenAI GPT-OSS 120B` | exactly as shown on your LLM connection |
| `AGENT_NAME` | `SREAgent` | **letters and digits only** |
| `SPLUNK_MCP_URL` (optional) | `https://splunk.mycorp.com:8089/services/mcp` | enables log tools |

---

## 0 · Check

```bash
python3 quickstart/00_check.py
```
Every line should start with ✓. Each ✗ prints the fix. Typical ones: Cloud Connect not linked, `mltk_admin` missing,
LLM connection name mistyped, wrong realm or token.

## 1 · Tool connections

```bash
python3 quickstart/01_mcp_connections.py
```
```
  ✓ created o11y_cloud with 41 tools
  ✓ created splunk_logs with 5 tools          (only if SPLUNK_MCP_URL is set)
```
In AI Toolkit → Connections the "Test" button of `o11y_cloud` shows a parsing error — expected (the gateway streams
its answers); agents work regardless.

## 2 · Agent

```bash
python3 quickstart/02_agent.py
```
```
  ✓ created agent SREAgent: 15 tools, model OpenAI GPT-OSS 120B
  ✓ agent is Available
```
Its instructions are `quickstart/prompts/sre_agent.md` (a step-by-step SRE method) with your settings filled in.
Edit the file and re-run to change them. If creation fails with only "Failed to create agent", the reason is in
`$SPLUNK_HOME/var/log/splunk/mlspl.log`.

## 3 · Ask it

```bash
python3 quickstart/03_ask_agent.py
python3 quickstart/03_ask_agent.py "Why is checkout-api slow since 10:00 UTC?"
```
Prints the answer, the tool calls and the time (typically 1–5 min). In Splunk: AI Toolkit → Agents → your agent →
chat or run history. **The core path is done.**

## 4 · Investigate detector alerts automatically (optional)

1. In Observability Cloud add a **Splunk platform** notification integration that sends to a HEC (HTTP Event
   Collector) token for `DETECTOR_ALERT_INDEX`, and add it to your detectors' notifications.
2. Then:
```bash
python3 quickstart/04_alert.py            # creates the alert, DISABLED, and checks that detector alerts arrive
python3 quickstart/04_alert.py --enable
```
Every 2 minutes it picks up firing alerts and runs the agent **once per incident**, with the detector, severity,
service and incident id in the prompt. (Splunk's "Run AI Agent" alert action does not pass these fields — the alert
calls `| aiagent` from the search instead.)

## 5 · Investigate before any detector fires: ML anomaly detection (optional)

```bash
python3 quickstart/05_ml_detection.py account      # needs O11Y_ORG_ID; checks that | sim flow returns data
python3 quickstart/05_ml_detection.py train 24     # train on the last 24 h — choose hours that were NORMAL
python3 quickstart/05_ml_detection.py alert        # created DISABLED
python3 quickstart/05_ml_detection.py enable
```
Three AI Toolkit models (log errors, APM error %, APM p90 latency per service) score every service every 2 minutes;
anything unusual starts the agent with the flagged services and their numbers. Retrain after big changes in traffic.
For wider coverage (slow drifts, memory leaks, daily patterns, new error types, business ratios, silence) see
`detection-modules/`.

---

## Extras

| You want | Go to |
|---|---|
| A **Splunk app** that shows every investigation: root cause, hypothesis tree, timeline, evidence | `splunk-app/` |
| **Claude Sonnet/Opus 5.5**, your own agent loop, sub-agents, budgets, approval policy — run from SPL | `agent-container/` (its `AGENT-README.md`) |
| More **anomaly detectors** as AI Toolkit container modules (ECOD, drift, seasonal, rules, Isolation Forest) | `detection-modules/` (`tests/test_coverage.py` shows what each catches) |
| How we tested all this, and the numbers | `docs/index.html` → https://khsydney.github.io/splunk-aitk-launchpad-sre-agent/ |
| The original lab scripts (dated, environment-specific) | `research/` |

## Remove everything

AI Toolkit → Agents → delete the agent; Connections → delete the two MCP connections; Settings → Searches, reports
and alerts → delete the two alerts; `| listmodels` → `| deletemodel sre_apm_p90` (and the other two).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `cannot log in` | `SPLUNK_WEB_URL` must be Splunk Web (port 8000 or 443), not the management port 8089 |
| `CERTIFICATE_VERIFY_FAILED` | self-signed certificate: `SPLUNK_VERIFY_TLS=false` |
| Agent run ends "Invocation request timed out" | raise `AGENT_TIMEOUT_S` (we use 900) and re-run step 2; ask narrower questions |
| Agent answer is `HTTP 400 … thinking` | a Claude 5.5 model — use Sonnet 4.5 or the container agent |
| Hosted model `HTTP 500/502` | the hosted model is overloaded; retry, or avoid many runs at the same time |
| Agent calls tools with "Invalid arguments" | normal now and then; the prompt tells it to fix and retry once |
| Step 5 `train` shows 0 minutes | no data in that window for `LOG_INDEX` / `O11Y_ENVIRONMENT` |
