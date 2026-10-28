"""Record and replay the agent's data-plane calls for the evaluation set.

Recording wraps the live clients: every Observability Cloud MCP (Model Context Protocol) call and every Splunk query is
kept with its result, keyed by tool and arguments, after sanitising (redaction as for the model, plus private network
details: IP addresses, AWS (Amazon Web Services) host names and account numbers). Replay serves the same results to the
same code, so an investigation can be re-run offline with the mock or a real model. A call that was never recorded
raises NotRecorded; the tool layer turns that into an error result for the model and the eval report counts it.

Fixtures go into the public repository: `leaks()` is the check the tests run over every committed fixture.
"""

from __future__ import annotations

import copy
import json
import re
import time

from .evidence import TRACE_TAGS
from .o11y_mcp import O11yMCP, ToolResult
from .redact import redact

SCHEMA = 1

# --------------------------------------------------------------------------- sanitising (public repository)
_SUBS = [
    (re.compile(r"\b\d{12}(?=\.dkr\.ecr\.)"), "[ACCOUNT]"),                       # ECR (Elastic Container Registry) image host
    (re.compile(r"(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)\d{12}"), r"\1[ACCOUNT]"),
    (re.compile(r"\b[\w.-]+\.(?:elb\.amazonaws\.com|compute\.internal|amazonaws\.com|sslip\.io|splunkcloud\.com|signalfx\.com)\b"), "[HOST]"),
    (re.compile(r"\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b"), "ip-[IP]"),            # EC2 (Elastic Compute Cloud) node names
    (re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), "[IP]"),
    (re.compile(r"/Users/[^/\s\"]+"), "/Users/[USER]"),
]
LEAK_PATTERNS = {
    "ipv4": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "ec2_node_ip": re.compile(r"\bip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b"),
    "aws_account": re.compile(r"\b\d{12}\.dkr\.ecr\.|arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}"),
    "aws_or_splunk_host": re.compile(r"(elb\.amazonaws\.com|compute\.internal|sslip\.io|splunkcloud\.com|signalfx\.com)"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "auth_token": re.compile(r"(Bearer|Splunk)\s+[A-Za-z0-9._-]{16,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "home_path": re.compile(r"/Users/(?!\[USER\])"),
}


def sanitise_text(s: str) -> str:
    s = redact(s)
    for rx, rep in _SUBS:
        s = rx.sub(rep, s)
    return s


def sanitise(o):
    """String leaves only, so numbers stay numbers and the document stays valid JSON."""
    if isinstance(o, dict):
        return {sanitise_text(k) if isinstance(k, str) else k: sanitise(v) for k, v in o.items()}
    if isinstance(o, list):
        return [sanitise(v) for v in o]
    if isinstance(o, tuple):
        return [sanitise(v) for v in o]
    if isinstance(o, str):
        return sanitise_text(o)
    return o


def leaks(text: str) -> list[str]:
    return sorted(name for name, rx in LEAK_PATTERNS.items() if rx.search(text))


def _shrink_trace(text: str) -> str:
    """A raw trace is ~100 KB. Keep only what evidence.compact_trace reads (it is the only consumer)."""
    try:
        d = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
    spans = [{"traceID": s.get("traceID"), "serviceName": s.get("serviceName"), "operationName": s.get("operationName"),
              "duration": s.get("duration"), "tags": [t for t in s.get("tags", []) if t.get("key") in TRACE_TAGS]}
             for s in (d or {}).get("spans") or []]
    return json.dumps({"spans": spans}, ensure_ascii=False)


def _shrink_apm(text: str) -> str:
    """The same transform toolset.py applies to these two tools before anything reaches the model (summary values
    only, 10-second valueByTime arrays dropped). Idempotent, so replay through the toolset gives the same result."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
    if isinstance(data, dict) and isinstance(data.get("summary"), dict):
        data["summary"] = {k: (v.get("value") if isinstance(v, dict) and "value" in v else v) for k, v in data["summary"].items()}
    return json.dumps(data, ensure_ascii=False)


SHRINK = {"o11y_get_apm_trace_tool": _shrink_trace, "o11y_get_apm_service_errors_and_requests": _shrink_apm,
          "o11y_get_apm_service_latency": _shrink_apm}


def _mcp_key(tool: str, params) -> str:
    return "mcp|" + tool + "|" + json.dumps(params, sort_keys=True, default=str)


def _splunk_key(query: str, earliest: str, latest: str) -> str:
    return "splunk|" + " ".join(query.split()) + "|" + str(earliest) + "|" + str(latest)


class NotRecorded(LookupError):
    pass


# --------------------------------------------------------------------------- recording
class Recorder:
    """Wraps live clients in place. `mcp.call` is replaced on the instance, so services_summary and signalflow (which
    call self.call) are recorded too."""

    def __init__(self, mcp, splunk):
        self.calls: dict[str, dict] = {}
        self.mcp, self.splunk = mcp, splunk
        live_call, live_query = mcp.call, splunk.splunk_run_query

        def call(name, params):
            r = live_call(name, params)
            key = _mcp_key(name, params)
            if key not in self.calls:   # first answer wins (the bundle's call is the one the investigation saw)
                text = SHRINK[name](r.text) if name in SHRINK else r.text
                self.calls[key] = {"kind": "mcp", "tool": name, "params": params, "is_error": bool(r.is_error), "text": text}
            return r

        def run_query(query, earliest_time="-15m", latest_time="now", wait_s=90, max_results=200):
            key = _splunk_key(query, earliest_time, latest_time)
            if key not in self.calls:
                full = live_query(query, earliest_time=earliest_time, latest_time=latest_time, wait_s=wait_s, max_results=1000)
                self.calls[key] = {"kind": "splunk", "query": query, "earliest": earliest_time, "latest": latest_time, "result": full}
            return _sliced(self.calls[key]["result"], max_results)

        mcp.call = call
        splunk.splunk_run_query = run_query

    def fixture(self, meta: dict) -> dict:
        calls = []
        for c in self.calls.values():
            c = copy.deepcopy(c)
            if c["kind"] == "mcp":
                try:   # sanitise inside the JSON so placeholders never break it
                    c["text"] = json.dumps(sanitise(json.loads(c["text"])), ensure_ascii=False)
                except (json.JSONDecodeError, ValueError):
                    c["text"] = sanitise_text(c["text"])
                c["params"] = sanitise(c["params"])
            else:
                c["result"] = sanitise(c["result"])
                c["query"] = sanitise_text(c["query"])
            calls.append(c)
        calls.sort(key=lambda c: (c["kind"], c.get("tool", ""), json.dumps(c.get("params", c.get("query")), sort_keys=True), c.get("earliest", "")))
        return {"schema": SCHEMA, **sanitise(meta), "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "calls": calls}


def _sliced(result: dict, max_results: int) -> dict:
    out = copy.deepcopy(result)
    rows = out.get("results") or []
    out["results"] = rows[:max_results]
    if out.get("result_count") is not None:
        out["truncated"] = out["result_count"] > max_results
    return out


# --------------------------------------------------------------------------- replay
class ReplayMCP:
    """Serves recorded Observability Cloud results. Borrows the live client's conveniences, which only use self.call."""

    services_summary = O11yMCP.services_summary
    signalflow = O11yMCP.signalflow

    def __init__(self, fixture: dict):
        self.calls = {_mcp_key(c["tool"], c["params"]): c for c in fixture["calls"] if c["kind"] == "mcp"}
        self.misses: list[str] = []

    def call(self, name: str, params: dict) -> ToolResult:
        c = self.calls.get(_mcp_key(name, sanitise(params)))
        if c is None:
            self.misses.append(f"{name} {json.dumps(params, sort_keys=True, default=str)[:160]}")
            raise NotRecorded(f"not recorded in the eval fixture: {name}")
        return ToolResult(name=name, text=c["text"], is_error=c["is_error"])


class ReplaySplunk:
    backend_name = "replay"

    def __init__(self, fixture: dict):
        self.calls = {_splunk_key(c["query"], c["earliest"], c["latest"]): c for c in fixture["calls"] if c["kind"] == "splunk"}
        self.misses: list[str] = []

    def splunk_run_query(self, query: str, earliest_time: str = "-15m", latest_time: str = "now", wait_s: int = 90, max_results: int = 200) -> dict:
        c = self.calls.get(_splunk_key(sanitise_text(query), earliest_time, latest_time))
        if c is None:
            self.misses.append(f"spl {earliest_time}: {' '.join(query.split())[:160]}")
            raise NotRecorded("not recorded in the eval fixture: this SPL query (replay serves recorded queries only)")
        return _sliced(c["result"], max_results)
