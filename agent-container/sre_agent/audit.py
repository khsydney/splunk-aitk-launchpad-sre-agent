"""Structured audit events: one JSON line per event on stderr and, when SRE_AUDIT_HEC_URL and SRE_AUDIT_HEC_TOKEN
(or SRE_AUDIT_CREDS_FILE) are set, the same record to the dedicated HEC index tuktukpay_agent_audit (that HEC token can
write only there; the agent's sre_agent search role cannot read it). Never logs
secrets, prompts or raw tool output — hashes only."""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import sys
import time

import httpx

_HEC_URL = os.getenv("SRE_AUDIT_HEC_URL")
_HEC_TOKEN = os.getenv("SRE_AUDIT_HEC_TOKEN")
_CREDS = os.getenv("SRE_AUDIT_CREDS_FILE")   # sre_agent_creds.txt: line 3 audit HEC token, line 5 HEC URL
if _CREDS and not (_HEC_URL and _HEC_TOKEN):
    try:
        _lines = open(_CREDS).read().splitlines()
        _HEC_TOKEN, _HEC_URL = _lines[2], _lines[4]
    except (OSError, IndexError):
        _HEC_URL = _HEC_TOKEN = None
_HEC_INDEX = os.getenv("SRE_AUDIT_HEC_INDEX", "tuktukpay_agent_audit")
QUIET = os.getenv("SRE_AGENT_QUIET", "0") == "1"
_client = httpx.Client(timeout=5, verify=os.getenv("SRE_AUDIT_HEC_VERIFY_TLS", "true").lower() == "true") if _HEC_URL else None


CURRENT_CASE: contextvars.ContextVar = contextvars.ContextVar("sre_case_id", default=None)   # set per investigation thread
_SUBSCRIBERS: list = []   # in-process listeners (the agent console streams cases live from here)
FAILURES = {"count": 0, "last_error": ""}   # audit writes to HEC that did not land (this process)


def subscribe(fn) -> None:
    _SUBSCRIBERS.append(fn)


def sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()


def emit(event: str, **fields) -> dict:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "t": round(time.time(), 3), "event": event, "service.name": "sre-agent", **fields}
    if not QUIET:
        print(json.dumps(rec, default=str, ensure_ascii=False), file=sys.stderr, flush=True)
    _notify(rec)
    if _client:
        try:
            r = _client.post(_HEC_URL.rstrip("/") + "/services/collector/event", headers={"Authorization": f"Splunk {_HEC_TOKEN}"},
                             json={"index": _HEC_INDEX, "sourcetype": "sre_agent:audit", "event": rec})
            if r.status_code >= 300:
                _write_failed(rec, f"HTTP {r.status_code}: {r.text[:120]}")
        except Exception as e:  # noqa: BLE001 — audit transport failure must not break the case, but it must be seen
            _write_failed(rec, f"{type(e).__name__}: {e}"[:160])
    return rec


def _notify(rec: dict) -> None:
    for fn in list(_SUBSCRIBERS):
        try:
            fn(rec)
        except Exception:  # noqa: BLE001 — a listener must never break the case
            pass


def _write_failed(rec: dict, error: str) -> None:
    """Make a lost audit record visible: always on stderr (even when SRE_AGENT_QUIET=1), counted, and streamed to the
    console. Not sent to HEC again (that is what just failed) and never carries the token."""
    FAILURES["count"] += 1
    FAILURES["last_error"] = error
    warn = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "t": round(time.time(), 3), "event": "sre.audit.write_failed",
            "service.name": "sre-agent", "case_id": rec.get("case_id") or CURRENT_CASE.get(), "lost_event": rec.get("event"),
            "error": error, "failures_total": FAILURES["count"], "index": _HEC_INDEX}
    print(json.dumps(warn, default=str, ensure_ascii=False), file=sys.stderr, flush=True)
    _notify(warn)


def mcp_call(server: str, tool: str, params, started: float, ok: bool, size: int = 0, error: str = "") -> None:
    """One raw MCP (Model Context Protocol) / REST call, attributed to the case in context (no case → not emitted)."""
    cid = CURRENT_CASE.get()
    if not cid:
        return
    try:
        p = json.dumps(params, default=str)
    except (TypeError, ValueError):
        p = str(params)
    emit("sre.mcp.call", case_id=cid, server=server, tool=tool, params=p[:1500], ms=int((time.time() - started) * 1000), ok=ok, bytes=size, error=error[:200])
