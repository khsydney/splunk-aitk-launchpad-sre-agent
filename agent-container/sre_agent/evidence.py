"""Deterministic evidence collector (section 3.2 step 2). Code builds the first bundle before the model sees anything;
every section is redacted, scanned and clipped by tools.clip. SPL templates are pre-aggregated (tens of rows).

Config-change markers (event=config.changed: the chaos flag names) are hidden unless SRE_AGENT_MARKERS=show, so the
model diagnoses from telemetry instead of reading the flag that was flipped; `--no-marker` hides them in every case.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from . import catalogue
from .cancel import check_current as _stop_point
from .tools import clip, summarise_series

ENV = os.getenv("DEPLOYMENT_ENVIRONMENT", "tuktukpay-demo")
INDEX = catalogue.INDEX
MARKERS = os.getenv("SRE_AGENT_MARKERS", "hide").lower()   # show | hide (default)


def markers_shown(marker_mode: bool = True) -> bool:
    return bool(marker_mode) and MARKERS == "show"

# detector name fragment -> affected service (for evidence scoping)
DETECTOR_SERVICE = [("payment-router", "payment-router"), ("checkout-api", "checkout-api"), ("risk-engine", "risk-engine"),
                    ("ledger", "ledger"), ("merchant-copilot", "merchant-copilot"), ("copilot", "merchant-copilot"),
                    ("merchant-sim", "merchant-sim"), ("wallet-sim", "wallet-sim"), ("Know-Your-Agent", "wallet-sim"),
                    ("mandate", "checkout-api"), ("agent-initiated", "checkout-api"), ("approval rate", "payment-router"),
                    ("webhook", "webhook-dispatcher"), ("Kubernetes", None), ("container", None)]

SPL_TEMPLATES = {
    "events_by_service": "search index={index} earliest={earliest} | stats count by source event | sort -count | head 60",
    "errors_by_type": "search index={index} earliest={earliest} error.type=* | stats count by source error.type | sort -count | head 40",
    "config_changes": "search index={index} earliest={earliest} event=config.changed | stats earliest(_time) as first latest(_time) as last count by source feature_flag.name feature_flag.enabled | sort -last | head 30",
    "timeouts_by_acquirer_bin": "search index={index} earliest={earliest} source=payment-router (event=acquirer.timeout OR event=route.failover) | stats count by event payment.acquirer route.backup_acquirer payment.card.bin | sort -count | head 30",
    "declines_by_reason": "search index={index} earliest={earliest} event=payment.declined | stats count by payment.decline_reason payment.acquirer | sort -count | head 30",
    "mandate_blocks_by_reason": "search index={index} earliest={earliest} event=mandate.blocked | stats count by mandate.block_reason peer.service | sort -count | head 30",
    "risk_decisions": "search index={index} earliest={earliest} source=risk-engine event=risk.* | stats count avg(risk.inference_ms) as avg_inference_ms by event risk.model_version | sort -count | head 30",
    "copilot_loop": "search index={index} earliest={earliest} source=merchant-copilot (event=copilot.* OR event=guardrail.*) | stats count by event gen_ai.tool.name | sort -count | head 30",
    "pool_and_webhook": "search index={index} earliest={earliest} (event=db.pool.* OR event=ledger.write_* OR event=webhook.* OR event=merchant.webhook_error) | stats count by source event merchant.id | sort -count | head 30",
    "memory_and_crash": "search index={index} earliest={earliest} (event=memory.* OR event=service.crashed OR event=ledger.write_failed) | stats count latest(process.memory.rss_mb) as rss_mb latest(container.memory.utilization_pct) as mem_pct latest(error.type) as error_type latest(deployment.release) as release by source event | sort -count | head 30",
    "impact_by_outcome": "search index={index} earliest={earliest} (event=payment.approved OR event=payment.declined OR event=payment.failed) | stats count sum(payment.amount) as amount by event payment.acquirer payment.currency | sort -count | head 30",
    "impact_by_merchant": "search index={index} earliest={earliest} (event=payment.declined OR event=payment.failed OR event=acquirer.timeout) | stats count sum(payment.amount) as amount by merchant.id event | sort -count | head 20",
    "first_seen": "search index={index} earliest={earliest} (severity=warn OR severity=error) | stats min(_time) as first max(_time) as last count by source event | eval minutes_since_last=round((now()-last)/60, 1), first=strftime(first, \"%Y-%m-%dT%H:%M:%SZ\"), last=strftime(last, \"%Y-%m-%dT%H:%M:%SZ\") | sort first | head 25",
    "kya_registry": "search index={index} earliest={earliest} (event=kya.registry_unavailable OR mandate.block_reason=mandate_kya_unavailable) | stats count by source event peer.service error.type | sort -count",
}
NO_MARKER_TEMPLATES_HIDDEN = {"config_changes"}  # hidden unless markers are shown
ONSET_WINDOW = "-1h"   # first_seen looks further back than the incident window so the onset is inside it
TRACE_TAGS = ("error", "otel.status_code", "http.response.status_code", "http.status_code", "payment.acquirer", "payment.card.bin",
              "route.failover", "route.attempts", "peer.service", "exception.type", "error.type", "db.system")
METRIC_SECTIONS = ("services_summary", "payments_", "dependencies_", "exemplar_", "trace_", "metric_", "apm_")


def compact_trace(d: dict, top: int = 15) -> dict:
    """A full trace is ~100 KB; keep the slowest spans and every error span with a few tags the investigator needs."""
    spans = (d or {}).get("spans") or []
    rows = []
    for s in spans:
        tags = {t.get("key"): t.get("value") for t in s.get("tags", []) if t.get("key") in TRACE_TAGS}
        err = str(tags.pop("error", "")).lower() == "true" or tags.get("otel.status_code") == "ERROR"   # the raw tag is a string
        rows.append({"service": s.get("serviceName"), "operation": s.get("operationName"), "duration_ms": round((s.get("duration") or 0) / 1000, 1),
                     "error": err, **tags})
    rows.sort(key=lambda r: (not r["error"], -r["duration_ms"]))
    return {"trace_id": spans[0].get("traceID") if spans else None, "span_count": len(spans), "spans": rows[:top]}


def signal_of(evidence_id: str, tool_log: list[dict] | None = None) -> str:
    """'log', 'metric_trace' or '' (unknown) for a bundle section name or an investigator tool_use id."""
    eid = str(evidence_id or "")
    for entry in tool_log or []:
        if entry.get("id") == eid:
            return "log" if entry.get("tool") in ("spl", "spl_template") else "metric_trace"
    if eid.startswith("spl"):
        return "log"
    if eid.startswith(METRIC_SECTIONS):
        return "metric_trace"
    return ""


def render_template(name: str, earliest: str = "-15m") -> str:
    return SPL_TEMPLATES[name].format(index=INDEX, earliest=earliest)


SCOPE_RE = re.compile(r"\[services in scope: ([a-z0-9, -]+)\]")


def affected_services(detector_names: list[str]) -> list[str]:
    """Services for the per-service deep dive: every service an operator question lists in its
    "[services in scope: a, b]" hint (console pseudo-incidents), then the first match per detector name."""
    out = []
    for d in detector_names:
        m = SCOPE_RE.search(d)
        for svc in (x.strip() for x in (m.group(1).split(",") if m else [])):
            if re.fullmatch(r"[a-z0-9-]{1,64}", svc) and svc not in out:
                out.append(svc)
    for d in detector_names:
        for frag, svc in DETECTOR_SERVICE:
            if frag.lower() in d.lower() and svc and svc not in out:
                out.append(svc)
                break
    return out


@dataclass
class Bundle:
    sections: dict = field(default_factory=dict)
    tainted: list[str] = field(default_factory=list)
    tool_calls: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, name: str, tool: str, data, note: str = ""):
        env = clip(tool, data, note=note)
        self.sections[name] = env.to_text()
        self.tainted.extend(env.injection_flags)
        self.tool_calls += 1

    def as_text(self) -> str:
        return "\n\n".join(f"### {k}\n{v}" for k, v in self.sections.items())


def collect(mcp, splunk, detector_names: list[str], window: str = "-15m", marker_mode: bool = True) -> Bundle:
    b = Bundle()
    marker_mode = markers_shown(marker_mode)
    svcs = affected_services(detector_names)
    _stop_point("evidence collection (services summary)")
    try:
        b.add("services_summary", "o11y_get_apm_services_summary", mcp.services_summary(ENV, window))
    except Exception as e:  # noqa: BLE001
        b.errors.append(f"services_summary: {e}")
    _stop_point("evidence collection (payments by outcome)")
    try:
        sf = mcp.signalflow(f"data('tuktukpay.payments.count', filter={catalogue.ENV_FILTER}, rollup='rate').sum(by=['payment.outcome','payment.acquirer']).publish()", window)
        b.add("payments_by_outcome_acquirer", "o11y_execute_signalflow_program", summarise_series(sf["series"]))
    except Exception as e:  # noqa: BLE001
        b.errors.append(f"signalflow payments: {e}")
    for svc in svcs[:2]:
        _stop_point(f"evidence collection (dependencies of {svc})")
        try:
            r = mcp.call("o11y_get_apm_service_dependencies", {"environment_name": ENV, "service_name": svc, "time_range": {"start": window, "stop": "now"}})
            b.add(f"dependencies_{svc}", "o11y_get_apm_service_dependencies", r.json() or r.text[:4000])
        except Exception as e:  # noqa: BLE001
            b.errors.append(f"dependencies {svc}: {e}")
    for svc in svcs[:2]:   # same two services as the dependency deep dive
        _stop_point(f"evidence collection (traces of {svc})")
        try:
            r = mcp.call("o11y_get_apm_exemplar_traces", {"environment_name": ENV, "service_name": svc, "exemplar_type": "err", "time_range": {"start": window, "stop": "now"}})
            ex = (r.json() or {}).get("items", []) if not getattr(r, "is_error", False) else []
            b.add(f"exemplar_traces_{svc}", "o11y_get_apm_exemplar_traces",
                  [{k: e.get("item", {}).get(k) for k in ("traceId", "initiatingService", "durationMicros", "serviceSpanCounts")} for e in ex[:3]])
            if ex:
                t = mcp.call("o11y_get_apm_trace_tool", {"trace_id": ex[0]["item"]["traceId"]})
                b.add(f"trace_{svc}_error", "o11y_get_apm_trace_tool", compact_trace(t.json() or {}),
                      note="slowest and error spans of the first erroring trace")
        except Exception as e:  # noqa: BLE001
            b.errors.append(f"traces {svc}: {e}")
    templates = ["events_by_service", "errors_by_type", "impact_by_outcome", "impact_by_merchant", "first_seen"] + (["config_changes"] if marker_mode else [])
    for name in templates:
        w = ONSET_WINDOW if name == "first_seen" else window
        _stop_point(f"evidence collection (log query {name})")
        try:
            r = splunk.splunk_run_query(render_template(name, w), earliest_time=w, max_results=60)
            rows = r["results"] if marker_mode else [x for x in r["results"] if x.get("event") != "config.changed"]
            b.add(f"spl_{name}", "splunk_run_query", {"query": r["query"], "results": rows, "result_count": r.get("result_count")})
        except Exception as e:  # noqa: BLE001
            b.errors.append(f"spl {name}: {e}")
    if b.errors:
        b.sections["collector_errors"] = "\n".join(b.errors)
    return b
