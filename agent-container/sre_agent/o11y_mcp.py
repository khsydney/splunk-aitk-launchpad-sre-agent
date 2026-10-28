"""Client for the hosted Splunk Observability Cloud MCP (Model Context Protocol) gateway.

Streamable-HTTP JSON-RPC, no SDK needed. Verified against "Unified MCP Gateway 3.4.2" (realm us1,
20 Oct 2026): every tool takes ONE nested object `arguments: {"params": {...}}`; `time_range` is
`{"start": "-30m", "stop": "now"}`; APM tools want `environment_name`. 19 tools by default, 41 with
`X-SPLUNK-O11Y-TOOL-SETS: apm,metrics,detectors,dashboards` (unknown set names -> 0 tools).

Environment: SPLUNK_O11Y_TOKEN (API token, never printed), SPLUNK_REALM (default us1),
SPLUNK_MCP_GATEWAY_URL (default region-pdx10 for us1), SPLUNK_O11Y_TOOL_SETS.
"""

from __future__ import annotations

import json
import os
import time
import re
from dataclasses import dataclass, field

import httpx

DEFAULT_URL = "https://region-pdx10.api.scs.splunk.com/system/mcp-gateway/v1/"
DEFAULT_TOOL_SETS = "apm,metrics,detectors,dashboards"


class MCPError(RuntimeError):
    pass


@dataclass
class ToolResult:
    name: str
    text: str
    is_error: bool = False
    raw: dict = field(default_factory=dict)

    def json(self):
        """Parsed JSON body when the tool returned JSON text, else None."""
        try:
            return json.loads(self.text)
        except (json.JSONDecodeError, TypeError):
            return None


class O11yMCP:
    """Minimal MCP client: initialize(), list_tools(), call(name, params)."""

    def __init__(self, url: str | None = None, realm: str | None = None, token: str | None = None,
                 tool_sets: str | None = None, timeout: float = 90.0):
        self.url = url or os.getenv("SPLUNK_MCP_GATEWAY_URL", DEFAULT_URL)
        self.realm = (realm or os.getenv("SPLUNK_REALM", "us1")).strip()
        if not re.fullmatch(r"[a-z]{2}\d", self.realm):
            raise MCPError("SPLUNK_REALM must look like us1 / au0")
        self.token = token or os.getenv("SPLUNK_O11Y_TOKEN") or ""
        if not self.token:
            raise MCPError("SPLUNK_O11Y_TOKEN is not set")
        self.tool_sets = tool_sets if tool_sets is not None else os.getenv("SPLUNK_O11Y_TOOL_SETS", DEFAULT_TOOL_SETS)
        self.http = httpx.Client(timeout=timeout)
        self.session_id: str | None = None
        self._next_id = 0
        self._tools: list[dict] | None = None

    # ------------------------------------------------------------------ transport
    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-SF-REALM": self.realm,
            "X-SF-TOKEN": self.token,
        }
        if self.tool_sets:
            h["X-SPLUNK-O11Y-TOOL-SETS"] = self.tool_sets
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _rpc(self, method: str, params: dict) -> dict:
        self._next_id += 1
        body = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        res = self.http.post(self.url, headers=self._headers(), content=json.dumps(body))
        if res.status_code >= 400:
            raise MCPError(f"gateway HTTP {res.status_code}: {res.text[:300]}")
        sid = res.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        text = res.text
        messages = [json.loads(line[5:]) for line in text.splitlines() if line.startswith("data:")]
        if not messages:
            messages = [json.loads(text)]
        msg = messages[-1]
        if "error" in msg:
            raise MCPError(f"{method}: {msg['error']}")
        return msg.get("result", {})

    # ------------------------------------------------------------------ MCP methods
    def initialize(self) -> dict:
        info = self._rpc("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "tuktukpay-sre-agent", "version": "0.1"},
        })
        return info.get("serverInfo", info)

    def list_tools(self) -> list[dict]:
        if self._tools is None:
            if self.session_id is None:
                self.initialize()
            self._tools = self._rpc("tools/list", {}).get("tools", [])
        return self._tools

    def call(self, name: str, params: dict) -> ToolResult:
        from .audit import mcp_call
        if self.session_id is None:
            self.initialize()
        t0 = time.time()
        try:
            result = self._rpc("tools/call", {"name": name, "arguments": {"params": params}})
        except Exception as e:  # noqa: BLE001
            mcp_call("o11y-mcp-gateway", name, {"params": params}, t0, False, error=f"{type(e).__name__}: {e}")
            raise
        text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        mcp_call("o11y-mcp-gateway", name, {"params": params}, t0, not result.get("isError"), len(text))
        return ToolResult(name=name, text=text, is_error=bool(result.get("isError")), raw=result)

    # ------------------------------------------------------------------ conveniences used by the agent
    def signalflow(self, program: str, start: str = "-15m", stop: str = "now", resolution_ms: int = 60000) -> dict:
        """Run a SignalFlow program; returns {"series": [{"dims": {...}, "points": [(ts_ms, value), ...]}]}."""
        r = self.call("o11y_execute_signalflow_program",
                      {"program": program, "time_range": {"start": start, "stop": stop}, "resolution_ms": resolution_ms})
        data = r.json() or {}
        meta = data.get("metadata", {})
        series: dict[str, list] = {tsid: [] for tsid in meta}
        for ts, values in sorted(data.get("timeseries", {}).items(), key=lambda kv: int(kv[0])):
            for tsid, v in values.items():
                series.setdefault(tsid, []).append((int(ts), v))
        return {"series": [{"dims": {k: v for k, v in meta.get(tsid, {}).items() if not k.startswith("sf_")},
                            "points": pts} for tsid, pts in series.items()],
                "job_id": data.get("job_id")}

    def services_summary(self, environment: str, start: str = "-15m", stop: str = "now") -> list[dict]:
        r = self.call("o11y_get_apm_services_summary", {"environment_name": environment, "time_range": {"start": start, "stop": stop}})
        data = r.json() or {}
        out = []
        for s in data.get("services", []):
            req = (s.get("requestCount") or {}).get("value") or 0
            err = (s.get("errorCount") or {}).get("value") or 0
            out.append({
                "service": s["service"]["name"], "health": s.get("health"),
                "requests": req, "errors": err, "error_rate": (err / req) if req else 0.0,
                "p50_ms": ((s.get("requestDurationMicrosP50") or {}).get("value") or 0) / 1000,
                "p90_ms": ((s.get("requestDurationMicrosP90") or {}).get("value") or 0) / 1000,
                "p99_ms": ((s.get("requestDurationMicrosP99") or {}).get("value") or 0) / 1000,
                "link": (s["service"].get("link") or {}).get("url"),
            })
        return out

    def open_alerts(self, detector_names: list[str], start: str = "-24h", stop: str = "now") -> list[dict]:
        """Open alerts for OUR detectors only (the org is shared; a bare query returns other teams' alerts)."""
        alerts = []
        for name in detector_names:
            r = self.call("o11y_search_alerts_or_incidents", {"time_range": {"start": start, "stop": stop}, "detector_name": name})
            data = r.json() or {}
            for a in data.get("alerts", []):
                if a.get("active", True):
                    alerts.append({
                        "detector": a.get("detector"), "detector_id": a.get("detectorId"), "incident_id": a.get("incidentId"),
                        "severity": a.get("severity"), "since": a.get("anomaly_state_update_iso_8601_date_time"),
                        "properties": a.get("customProperties", {}), "link": (a.get("link") or {}).get("url"),
                    })
        return alerts
