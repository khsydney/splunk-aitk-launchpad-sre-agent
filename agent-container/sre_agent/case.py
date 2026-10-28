"""Case store and state machine (section 3.1). One JSON file per case under SRE_AGENT_STATE_DIR."""

from __future__ import annotations

import json
import os
import pathlib
import time
import uuid

from .audit import emit

STATES = ["open", "investigating", "proposed", "awaiting_approval", "remediating", "verifying", "resolved",
          "mitigated_awaiting_clear", "inconclusive", "escalated", "verification_failed", "closed"]
TRANSITIONS = {
    "open": {"investigating", "closed", "escalated"},
    "investigating": {"proposed", "inconclusive", "escalated", "closed"},
    "proposed": {"awaiting_approval", "remediating", "closed", "escalated"},
    "awaiting_approval": {"remediating", "closed", "escalated"},
    "remediating": {"verifying", "verification_failed", "escalated", "closed"},
    "verifying": {"resolved", "mitigated_awaiting_clear", "verification_failed", "escalated", "closed"},
    "mitigated_awaiting_clear": {"resolved", "closed"},
    "verification_failed": {"escalated", "closed"},
    "inconclusive": {"closed", "investigating"},
    "escalated": {"closed"},
    "resolved": {"closed"},
    "closed": set(),
}
# states in which a case still owns its incidents (correlation target, counts toward the concurrency cap)
ACTIVE_STATES = {"open", "investigating", "proposed", "awaiting_approval", "remediating", "verifying", "mitigated_awaiting_clear"}
STATE_DIR = pathlib.Path(os.getenv("SRE_AGENT_STATE_DIR", os.path.expanduser("~/.local/share/tuktukpay-sre-agent"))) / "cases"


def new_case(environment: str, incidents: list[dict], source: str = "poll") -> dict:
    cid = "C-" + time.strftime("%m%d%H%M", time.gmtime()) + "-" + uuid.uuid4().hex[:4]
    c = {"id": cid, "state": "open", "environment": environment, "opened_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "opened_epoch": time.time(),
         "source": source, "incidents": incidents, "unreviewed_alerts": [], "history": [], "investigation": None, "decision": None, "outcome": None, "stats": None}
    emit("sre.case.opened", case_id=cid, detectors=[i.get("detector") for i in incidents], source=source)
    save(c)
    return c


def transition(c: dict, new_state: str, **detail) -> dict:
    if new_state not in TRANSITIONS.get(c["state"], set()):
        raise ValueError(f"illegal transition {c['state']} -> {new_state}")
    c["history"].append({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "from": c["state"], "to": new_state, **detail})
    c["state"] = new_state
    emit(f"sre.case.{new_state}", case_id=c["id"], **{k: v for k, v in detail.items() if k != "investigation"})
    save(c)
    return c


def save(c: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = STATE_DIR / f"{c['id']}.json"
    path.write_text(json.dumps(c, indent=1, default=str))
    path.chmod(0o600)


def load(case_id: str) -> dict:
    return json.loads((STATE_DIR / f"{case_id}.json").read_text())


def list_cases(open_only: bool = False) -> list[dict]:
    out = []
    if STATE_DIR.exists():
        for p in sorted(STATE_DIR.glob("C-*.json")):
            c = json.loads(p.read_text())
            if not open_only or c["state"] in ACTIVE_STATES:
                out.append(c)
    return out
