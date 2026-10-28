"""Typed tool wrappers offered to the investigator (section 4). Environment, index and detector list are hard-coded;
the model never writes a URL, a token, an index term, or a free SignalFlow filter. Every result passes through
tools.clip; result rows are scrubbed of raw fields; budgets (tool calls, SPL searches) are enforced here and the
token / wall-clock budgets in investigator.py."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from . import catalogue
from .evidence import ENV, SPL_TEMPLATES, compact_trace, markers_shown, render_template
from .tools import SPLRejected, clip, guard_spl, guard_window, scrub_rows, summarise_series

MAX_TOOL_CALLS = int(os.getenv("SRE_AGENT_MAX_TOOL_CALLS", "15"))
MAX_SPL = int(os.getenv("SRE_AGENT_MAX_SPL", "6"))
WINDOWS = ["-5m", "-15m", "-30m", "-1h", "-3h", "-6h", "-24h"]
RESOLUTIONS = [10000, 60000, 300000]
METRIC_RE = re.compile(r"^(tuktukpay\.|service\.request\.|k8s\.|container\.)[A-Za-z0-9_.]+$")
DIMENSIONS = ["payment.outcome", "payment.acquirer", "payment.decline_reason", "merchant.id", "risk.model_version", "risk.decision",
              "mandate.block_reason", "agent.id", "gen_ai.token.type", "gen_ai.request.model", "sf_service", "sf_operation", "sf_httpMethod",
              "k8s.pod.name", "k8s.container.name", "k8s.deployment.name", "k8s.node.name", "webhook.merchant_id"]
ROLLUPS = ["rate", "delta", "sum", "average", "max", "latest"]
WINDOW = {"type": "string", "enum": WINDOWS, "description": "relative start of the window (stop is now)"}


WHY = {"type": "string", "description": "One sentence: which hypothesis this call tests, and what result would confirm or rule it out. Shown to the on-call engineer in the RCA flow."}


def _schema(props: dict, required: list[str]) -> dict:
    # every tool call states its purpose, so the RCA (root cause analysis) flow shows the reasoning behind each step even
    # when the model does not emit a thinking block (adaptive thinking at medium effort often skips it)
    return {"type": "object", "properties": {"why": WHY, **props}, "required": ["why"] + required, "additionalProperties": False}


TOOL_SCHEMAS = [
    {"name": "services_summary", "description": "Per-service requests, errors, root-cause errors, p50/p90/p99 and health for every APM service in the environment.", "input_schema": _schema({"window": WINDOW}, ["window"])},
    {"name": "service_dependencies", "description": "Inbound and outbound dependencies of one service with requests and latency.", "input_schema": _schema({"service": {"type": "string"}, "window": WINDOW}, ["service", "window"])},
    {"name": "apm_errors_by_tag", "description": "Error and request breakdown of one service by span tag (e.g. payment.acquirer, http.status_code).", "input_schema": _schema({"service": {"type": "string"}, "window": WINDOW}, ["service", "window"])},
    {"name": "apm_latency_by_tag", "description": "Latency breakdown of one service by span tag.", "input_schema": _schema({"service": {"type": "string"}, "window": WINDOW}, ["service", "window"])},
    {"name": "exemplar_traces", "description": "Sample traces for one service with trace ids: kind err = erroring traces, rc_err = root-cause errors, req = ordinary requests.", "input_schema": _schema({"service": {"type": "string"}, "kind": {"type": "string", "enum": ["err", "rc_err", "req"]}, "window": WINDOW}, ["service", "kind", "window"])},
    {"name": "trace", "description": "Error spans first, then the slowest spans (at most 15), of one trace by id, with the key tags (status, acquirer, BIN, peer service, exception).", "input_schema": _schema({"trace_id": {"type": "string"}}, ["trace_id"])},
    {"name": "metric_series", "description": "Time series of one metric for THIS environment (the filter is added by code), summed by the chosen dimensions. Metrics with data on this cluster: business tuktukpay.payments.count, tuktukpay.payments.declines, tuktukpay.risk.decisions, tuktukpay.agent_mandates, tuktukpay.agent_tasks, tuktukpay.copilot.tool_calls (by outcome, gen_ai.tool.name), tuktukpay.copilot.guardrail_events; APM service.request.count, service.request.duration.ns.p90 / .median; Kubernetes k8s.container.restarts, k8s.deployment.desired / .available, k8s.pod.phase, k8s.container.cpu_limit / memory_limit, container.cpu.usage, container.memory.usage (there is no container.cpu.utilization; kubelet stats arrive every 20 s, so use resolution_ms 60000 or more). Copilot token and cost metrics and webhook delivery metrics currently have no data: use the logs (gen_ai.usage.* fields, webhook.* events) instead. Output is downsampled with per-series first/last/min/max/change.",
     "input_schema": _schema({"metric": {"type": "string", "description": "metric name, e.g. tuktukpay.payments.count, service.request.duration.ns.p90, k8s.container.restarts"},
                              "by": {"type": "array", "items": {"type": "string", "enum": DIMENSIONS}, "description": "dimensions to sum by (may be empty)"},
                              "rollup": {"type": "string", "enum": ROLLUPS}, "window": WINDOW, "resolution_ms": {"type": "integer", "enum": RESOLUTIONS}}, ["metric", "by", "rollup", "window", "resolution_ms"])},
    {"name": "spl_template", "description": "Run a pre-aggregated log query template on index=tuktukpay. Templates: " + ", ".join(sorted(SPL_TEMPLATES)), "input_schema": _schema({"name": {"type": "string", "enum": sorted(SPL_TEMPLATES)}, "window": WINDOW}, ["name", "window"])},
    {"name": "spl", "description": "Run your own aggregated SPL on index=tuktukpay. The index is pinned by code. Allow-listed commands: stats, timechart, top, rare, tstats, chart, table <fields>, eval, where, rex field=<f>, dedup, sort, head, bin. Must aggregate; _raw and message are refused; no OR/NOT/IN in the first stage.", "input_schema": _schema({"query": {"type": "string"}, "window": WINDOW}, ["query", "window"])},
]


@dataclass
class ToolSet:
    mcp: object
    splunk: object
    marker_mode: bool = True
    calls: int = 0
    spl_calls: int = 0
    tainted: list[str] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)   # transcript of tool calls for evidence-id resolution
    outputs: dict = field(default_factory=dict)      # tool_use id -> result text (memory only; read by the eval scorer)

    def __post_init__(self):
        self.marker_mode = markers_shown(self.marker_mode)

    def schemas(self) -> list[dict]:
        return sorted(TOOL_SCHEMAS, key=lambda t: t["name"])  # deterministic order (prompt caching)

    def dispatch(self, call_id: str, name: str, args: dict) -> str:
        self.calls += 1
        if self.calls > MAX_TOOL_CALLS:
            return self._err(call_id, name, args, f"tool budget exhausted ({MAX_TOOL_CALLS} calls): conclude now")
        try:
            data, note = self._run(name, args)
            env = clip(name, data, note=note)
        except SPLRejected as e:
            return self._err(call_id, name, args, f"rejected: {e}")
        except Exception as e:  # noqa: BLE001
            return self._err(call_id, name, args, f"{type(e).__name__}: {e}"[:300])
        self.tainted.extend(env.injection_flags)
        text = env.to_text()
        self.log.append({"id": call_id, "tool": name, "args": args, "ok": True, "truncated": env.truncated, "chars": len(text)})
        self.outputs[call_id] = text
        return text

    def _err(self, call_id, name, args, msg) -> str:
        self.log.append({"id": call_id, "tool": name, "args": args, "ok": False, "error": msg})
        self.outputs[call_id] = json.dumps({"tool": name, "error": msg})
        return self.outputs[call_id]

    def _run(self, name: str, a: dict):
        w = guard_window(a.get("window", "-15m")) if name != "trace" else "-15m"
        tr = {"start": w, "stop": "now"}
        if name == "services_summary":
            return self.mcp.services_summary(ENV, w), ""
        if name == "service_dependencies":
            r = self.mcp.call("o11y_get_apm_service_dependencies", {"environment_name": ENV, "service_name": str(a["service"])[:64], "time_range": tr})
            return r.json() or r.text, ""
        if name in ("apm_errors_by_tag", "apm_latency_by_tag"):
            tool = "o11y_get_apm_service_errors_and_requests" if name == "apm_errors_by_tag" else "o11y_get_apm_service_latency"
            r = self.mcp.call(tool, {"environment_name": ENV, "service_name": str(a["service"])[:64], "time_range": tr})
            data = r.json() or {"text": r.text}
            if isinstance(data, dict) and isinstance(data.get("summary"), dict):   # drop 10-second valueByTime arrays
                data["summary"] = {k: (v.get("value") if isinstance(v, dict) and "value" in v else v) for k, v in data["summary"].items()}
            return data, "valueByTime series removed; use metric_series for time series"
        if name == "exemplar_traces":
            kind = a.get("kind") if a.get("kind") in ("err", "rc_err", "req") else "err"
            r = self.mcp.call("o11y_get_apm_exemplar_traces", {"environment_name": ENV, "service_name": str(a["service"])[:64], "exemplar_type": kind, "time_range": tr})
            if r.is_error:
                raise ValueError(r.text[:200])
            return r.json() or {"text": r.text}, ""
        if name == "trace":
            tid = str(a["trace_id"])
            if not re.fullmatch(r"[0-9a-fA-F]{16,32}", tid):
                raise ValueError("trace_id must be 16–32 hex characters")
            r = self.mcp.call("o11y_get_apm_trace_tool", {"trace_id": tid})
            if r.is_error:
                raise ValueError(r.text[:200])
            # a full trace is ~100 KB and was head-truncated into an invalid JSON string; keep error and slowest spans
            return compact_trace(r.json() or {}), "error spans first, then the slowest spans (at most 15)"
        if name == "metric_series":
            metric = str(a["metric"])
            if not METRIC_RE.match(metric):
                raise ValueError("metric must start with tuktukpay., service.request., k8s. or container.")
            by = [d for d in (a.get("by") or []) if d in DIMENSIONS]
            rollup = a.get("rollup") if a.get("rollup") in ROLLUPS else "sum"
            res = int(a.get("resolution_ms", 60000))
            if res not in RESOLUTIONS:
                raise ValueError(f"resolution_ms must be one of {RESOLUTIONS}")
            filt = (catalogue.APM_FILTER if metric.startswith("service.request.")
                    else catalogue.K8S_FILTER if metric.startswith(("k8s.", "container."))
                    else catalogue.ENV_FILTER)
            prog = f"data('{metric}', filter={filt}, rollup='{rollup}').sum(by={json.dumps(by)}).publish()"
            return summarise_series(self.mcp.signalflow(prog, w, "now", res)["series"]), f"program built by code: {prog}"
        if name in ("spl_template", "spl"):
            self.spl_calls += 1
            if self.spl_calls > MAX_SPL:
                raise ValueError(f"SPL budget exhausted ({MAX_SPL} searches)")
            if name == "spl_template":
                if not self.marker_mode and a["name"] == "config_changes":
                    raise ValueError("config_changes is hidden (SRE_AGENT_MARKERS=show to allow)")
                spl = render_template(a["name"], w)   # template text is ours; only the (validated) window came from the model
            else:
                spl = guard_spl(str(a["query"]), catalogue.INDEX)
                if not self.marker_mode and ("config.changed" in spl or "feature_flag" in spl):
                    raise ValueError("config.changed / feature_flag fields are hidden (SRE_AGENT_MARKERS=show to allow)")
            r = self.splunk.splunk_run_query(spl, earliest_time=w, max_results=100)
            return {"query": r["query"], "results": scrub_rows(r["results"]), "result_count": r.get("result_count"), "truncated": r.get("truncated"),
                    "messages": [m.get("text", "")[:200] for m in (r.get("messages") or []) if m.get("type") in ("ERROR", "WARN")]}, ""
        raise ValueError(f"unknown tool {name}")
