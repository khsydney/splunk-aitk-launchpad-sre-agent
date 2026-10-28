"""Operator stop for a running investigation or follow-up question.

A Python thread cannot be killed from outside, so a stop is cooperative: the console (or Ctrl-C in the CLI) records a
request per case, and the investigation checks it at safe points — between evidence sections, before every model call
and every tool call, and before the escalation re-run. A call already in flight finishes first. An approved action
that is executing is never stopped halfway (the console refuses; see console.py).
"""

from __future__ import annotations

import threading

_LOCK = threading.Lock()
_REQUESTS: dict[str, str] = {}   # case id -> who asked


class Stopped(Exception):
    """Raised at a checkpoint after an operator asked to stop. `stats` carries what the run had spent so far."""

    def __init__(self, by: str, stage: str):
        super().__init__(f"stopped by {by} during {stage}")
        self.by, self.stage, self.stats = by, stage, None


def request(case_id: str, by: str) -> None:
    with _LOCK:
        _REQUESTS[case_id] = by


def requested(case_id: str | None) -> str | None:
    with _LOCK:
        return _REQUESTS.get(case_id or "")


def clear(case_id: str) -> None:
    with _LOCK:
        _REQUESTS.pop(case_id, None)


def check(case_id: str | None, stage: str) -> None:
    by = requested(case_id)
    if by:
        raise Stopped(by, stage)


def check_current(stage: str) -> None:
    """Checkpoint for code that does not carry the case id (evidence collection): uses the case in context."""
    from .audit import CURRENT_CASE
    check(CURRENT_CASE.get(), stage)
