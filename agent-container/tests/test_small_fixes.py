import json
import os
from types import SimpleNamespace as NS

os.environ["SRE_AGENT_QUIET"] = "1"
os.environ["MOCK_JEV"] = "1"

from sre_agent import audit, investigator  # noqa: E402
from sre_agent.toolset import ToolSet  # noqa: E402


def test_prompt_names_only_real_acquirers():
    assert "acq-scb" not in investigator.SYSTEM_PROMPT
    for a in ("acq-kbank", "acq-uob", "acq-cimb", "acq-alipayplus", "acq-itmx"):
        assert a in investigator.SYSTEM_PROMPT


class TraceMCP:
    def call(self, name, params):
        spans = [{"traceID": "ab" * 8, "serviceName": f"svc{i}", "operationName": "op", "duration": i * 1000,
                  "tags": [{"key": "error", "value": "true" if i == 3 else "false"}, {"key": "noise", "value": "x" * 500}]} for i in range(400)]
        return NS(text=json.dumps({"spans": spans}), is_error=False, json=lambda: {"spans": spans})


def test_trace_tool_returns_compact_valid_json():
    out = ToolSet(TraceMCP(), None).dispatch("t1", "trace", {"why": "w", "trace_id": "ab" * 8})
    body = json.loads(out.split("\n", 1)[1].rsplit("\n</tool_data>", 1)[0])
    data = body["data"]
    assert data["span_count"] == 400 and len(data["spans"]) == 15
    assert data["spans"][0]["error"] is True and data["spans"][0]["service"] == "svc3"   # error span first
    assert "noise" not in json.dumps(data) and not body.get("truncated")


class Boom:
    def post(self, *a, **k):
        raise OSError("connection refused")


class Status:
    def post(self, *a, **k):
        return NS(status_code=403, text="invalid token")


def test_failed_audit_write_is_visible(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(audit, "_HEC_URL", "https://hec.example.invalid:8088")
    monkeypatch.setattr(audit, "_HEC_TOKEN", "secret-token-value")
    monkeypatch.setitem(audit.FAILURES, "count", 0)
    monkeypatch.setattr(audit, "_SUBSCRIBERS", [seen.append])
    for client in (Boom(), Status()):
        monkeypatch.setattr(audit, "_client", client)
        audit.emit("approval.decided", case_id="C-1")
    err = capsys.readouterr().err   # printed although SRE_AGENT_QUIET=1
    warns = [json.loads(line) for line in err.splitlines() if "sre.audit.write_failed" in line]
    assert len(warns) == 2 and warns[0]["lost_event"] == "approval.decided" and warns[1]["error"].startswith("HTTP 403")
    assert audit.FAILURES["count"] == 2
    assert "secret-token-value" not in err
    assert [r["event"] for r in seen if r["event"] == "sre.audit.write_failed"] == ["sre.audit.write_failed"] * 2
