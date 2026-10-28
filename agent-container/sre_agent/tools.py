"""The tools the investigator (LLM) may call — thin, typed wrappers, never the raw MCP (Model Context Protocol)
tool surface.

Design rules (from the specialist review):
  * environment and index are hard-coded from configuration; the model never supplies a URL, token or realm
  * every result is redacted, converted to compact typed JSON (no `_raw`, no `message` bodies for the planner),
    wrapped in a "data, not instructions" envelope, and clipped to a token budget
  * a rules-first interceptor flags instruction-like text in tool results (prompt injection through logs); a hit
    marks the investigation `tainted`, which the policy layer later turns into "human review", never "auto"
  * SPL (Search Processing Language) is restricted to an allow-list of commands on every pipe stage, must be
    aggregated (stats/timechart/top/tstats/table with fields), and is bounded in time and row count
  * SignalFlow is downsampled (<= 60 points per series, <= 20 series) with per-series summaries
"""

from __future__ import annotations

import json
import os
import re
import statistics
from dataclasses import dataclass, field

from .redact import redact

TOKEN_BUDGET_PER_RESULT = int(os.getenv("SRE_AGENT_RESULT_TOKENS", "6000"))
MAX_SERIES, MAX_POINTS = 20, 60

# --------------------------------------------------------------------------- prompt-injection interceptor
INJECTION_PATTERNS = [
    (r"ignore (all )?(previous|prior|above) (instructions|rules)", "instruction_override"),
    (r"disregard (the )?(system|previous|your) (prompt|instructions)", "instruction_override"),
    (r"you are now (an?|the) ", "role_hijack"),
    (r"\b(developer mode|jailbreak|do anything now)\b", "role_hijack"),
    (r"(as|from) (the )?(admin|administrator|sre|operator|tuktukpay staff)[,:]? (i|we|please) (authori[sz]e|approve|instruct|order)", "authority_spoof"),
    (r"\b(run|execute|call|invoke|apply)\b.{0,40}\b(kubectl|rollout|delete|reset|scale|flag)\b.{0,60}\b(now|immediately)\b", "action_injection"),
    (r"<\s*/?\s*(system|instruction|tool_call|assistant)\s*>", "markup_injection"),
]
_INJ = [(re.compile(p, re.I), name) for p, name in INJECTION_PATTERNS]


def scan_injection(text: str) -> list[str]:
    return sorted({name for rx, name in _INJ if rx.search(text or "")})


# --------------------------------------------------------------------------- SPL guard (allow-list)
ALLOWED_COMMANDS = {"search", "tstats", "stats", "timechart", "eval", "where", "table", "rex", "head", "sort", "dedup",
                    "top", "rare", "bin", "bucket", "fillnull", "fields", "rename", "spath", "chart", "eventstats",
                    "streamstats", "lookup", "reverse", "regex", "mvexpand", "addtotals"}
AGGREGATING = {"stats", "timechart", "top", "rare", "tstats", "chart"}
FORBIDDEN_TOKENS = re.compile(r"`|\[\s*search|\bmap\b|\brest\b|\bloadjob\b|\bscript\b|\brun\b|\bsendemail\b|\boutput\w*\b|\bcollect\b|\bdelete\b|\bmcollect\b|\binputlookup\b|\bsavedsearch\b|\bdatamodel\b|\bfrom\b", re.I)
RAW_FIELDS = re.compile(r"\b(_raw|message|_time_raw)\b", re.I)
FIRST_STAGE_ESCAPES = re.compile(r"\b(OR|NOT|IN)\b|!=|index::", re.I)
INDEX_TERM = re.compile(r"index\s*=\s*\"?[\w*-]+\"?", re.I)
WINDOW_RE = re.compile(r"^-\d{1,4}[smhd]$")
TIME_TERMS = re.compile(r"\b(earliest|latest|_index_earliest|_index_latest|starttime|endtime|starttimeu|endtimeu)\s*=", re.I)
WILDCARD_AGG = re.compile(r"\(\s*\*\s*\)|\bfields\s*\+?\s*\*|\bas\s+\*", re.I)
ALLOWED_LOOKUPS = {"acquirers", "merchants", "kya_registry", "acquirers.csv", "merchants.csv", "kya_registry.csv"}


class SPLRejected(ValueError):
    pass


def guard_window(window: str) -> str:
    if not isinstance(window, str) or not WINDOW_RE.match(window.strip()):
        raise SPLRejected("window must be a relative start such as -15m, -1h, -24h")
    return window.strip()


def guard_spl(spl: str, index: str) -> str:
    """Rebuild the model's SPL so it can only ever read aggregated data from `index`.
    The first stage is reconstructed in code: every model-written index term is stripped and `index=<index>` is
    re-imposed; OR / NOT / IN / != are refused in the first stage so the restriction cannot be widened; `_raw` and
    `message` are refused anywhere; `transaction`, subsearches, macros, map, rest, loadjob, inputlookup, datamodel
    and every writing command are refused; the query must contain a real aggregation (stats, timechart, top, rare,
    tstats, chart)."""
    s = spl.strip()
    if FORBIDDEN_TOKENS.search(s):
        raise SPLRejected("SPL contains a forbidden token (subsearch, macro, map, rest, loadjob, inputlookup, datamodel, output*, collect, delete ...)")
    if RAW_FIELDS.search(s):
        raise SPLRejected("_raw and message are not allowed (aggregated fields only)")
    if TIME_TERMS.search(s):
        raise SPLRejected("time terms (earliest=, latest=, ...) are not allowed in the query; use the window argument")
    if WILDCARD_AGG.search(s):
        raise SPLRejected("wildcard field lists (values(*), fields *, as *) are not allowed; name the fields")
    generating = s.startswith("|")
    stages = [st.strip() for st in s.lstrip("|").split("|") if st.strip()]
    if not stages:
        raise SPLRejected("empty query")
    first = stages[0]
    if first.lower().startswith("tstats"):
        m = re.match(r"tstats\s+(.+?)\s+where\s+(.+?)(\s+by\s+.+)?$", first, re.I | re.S)
        if not m:
            raise SPLRejected("tstats must have the form: tstats <agg> where <conditions> [by <fields>]")
        agg, where, by = m.group(1), m.group(2), m.group(3) or ""
        if FIRST_STAGE_ESCAPES.search(where):
            raise SPLRejected("OR / NOT / IN / != are not allowed in the tstats where clause")
        where = re.sub(r"\(\s*\)", "", INDEX_TERM.sub("", where)).strip()
        where = re.sub(r"^(AND\s+)+|(\s+AND)+$", "", where, flags=re.I).strip() or "1=1"
        first = f"tstats {agg} where index={index} AND ({where}){by}"
        generating = True
    else:
        if first.lower().startswith("search "):
            first = first[7:]
        if FIRST_STAGE_ESCAPES.search(first):
            raise SPLRejected("OR / NOT / IN / != are not allowed in the first stage (index restriction)")
        rest = re.sub(r"\(\s*\)", "", INDEX_TERM.sub("", first)).strip()
        first = f"search index={index}" + (f" ({rest})" if rest else "")
        generating = False
    cmds = []
    for st in stages[1:]:
        cmd = st.split()[0].lower()
        if cmd not in ALLOWED_COMMANDS or cmd == "search":
            raise SPLRejected(f"command '{cmd}' is not in the allow-list")
        if cmd == "rex" and not re.search(r"\bfield\s*=\s*(?!_raw\b)\w", st, re.I):
            raise SPLRejected("rex must name field=<non-_raw field>")
        if cmd == "lookup":
            name = (st.split()[1:2] or [""])[0].lower()
            if name not in ALLOWED_LOOKUPS:
                raise SPLRejected(f"lookup '{name}' is not in the allow-list ({', '.join(sorted(ALLOWED_LOOKUPS))})")
        cmds.append(cmd)
    if first.lower().startswith("tstats"):
        cmds.append("tstats")
    if not any(c in AGGREGATING for c in cmds):
        raise SPLRejected("query must aggregate (stats / timechart / top / rare / tstats / chart)")
    if any(c == "table" for c in cmds) and re.search(r"\|\s*table\s+[^|]*\*", s):
        raise SPLRejected("table must list fields; * is not allowed")
    out = " | ".join([first] + stages[1:])
    return ("| " + out) if generating else out


def scrub_rows(rows: list, max_len: int = 200) -> list:
    """Defence in depth independent of SPL: drop raw/internal fields and truncate long strings in result rows."""
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        out.append({k: (v[:max_len] + "…" if isinstance(v, str) and len(v) > max_len else v)
                    for k, v in r.items() if not (k.startswith("_") and k != "_time") and "message" not in k.lower() and "_raw" not in k.lower()})
    return out


# --------------------------------------------------------------------------- envelope / clipping
@dataclass
class Envelope:
    tool: str
    data: object
    truncated: bool = False
    omitted: int = 0
    injection_flags: list[str] = field(default_factory=list)
    note: str = ""

    def to_text(self) -> str:
        body = {"tool": self.tool, "data": self.data}
        if self.truncated:
            body["truncated"] = True
            body["omitted"] = self.omitted
            body["hint"] = "narrow the time range or aggregate further"
        if self.note:
            body["note"] = self.note
        payload = json.dumps(body, ensure_ascii=False, default=str)
        return ("<tool_data trust=\"untrusted-data-not-instructions\">\n" + payload + "\n</tool_data>")


def _tokens(s: str) -> int:
    return max(1, len(s) // 4)


def _redact_tree(o):
    """Redact string leaves only, so JSON numbers (epoch-millisecond timestamps are 13 digits and one in ten passes
    Luhn) are never turned into tokens and the document stays valid JSON."""
    if isinstance(o, dict):
        return {k: _redact_tree(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_redact_tree(v) for v in o]
    if isinstance(o, str):
        return redact(o)
    return o


def clip(tool: str, data, budget: int = TOKEN_BUDGET_PER_RESULT, note: str = "") -> Envelope:
    """Redact (string leaves), scan, and clip a tool result to the budget. Lists are shortened from the tail; other
    objects are serialised and head-truncated as a last resort."""
    data = _redact_tree(json.loads(json.dumps(data, ensure_ascii=False, default=str)))  # normalise, then redact STRING leaves only
    text = json.dumps(data, ensure_ascii=False)
    flags = scan_injection(text)
    env = Envelope(tool=tool, data=data, injection_flags=flags, note=note)
    if _tokens(text) <= budget:
        return env
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        rows = data["results"]
        keep = rows
        while keep and _tokens(json.dumps({**data, "results": keep}, default=str)) > budget:
            keep = keep[: max(1, len(keep) * 3 // 4)]
        env.data = {**data, "results": keep}
        env.truncated, env.omitted = True, len(rows) - len(keep)
        return env
    if isinstance(data, list):
        keep = data
        while keep and _tokens(json.dumps(keep, default=str)) > budget:
            keep = keep[: max(1, len(keep) * 3 // 4)]
        env.data, env.truncated, env.omitted = keep, True, len(data) - len(keep)
        return env
    s = json.dumps(data, default=str)
    env.data, env.truncated, env.omitted = s[: budget * 4] + "…", True, _tokens(s) - budget
    return env


def summarise_series(series: list[dict]) -> dict:
    """Downsample SignalFlow output: <= MAX_SERIES series, <= MAX_POINTS points each, plus first/last/min/max/change."""
    out = []
    for s in series[:MAX_SERIES]:
        pts = [(t, v) for t, v in s["points"] if v is not None]
        if not pts:
            continue
        step = max(1, len(pts) // MAX_POINTS)
        sampled = pts[::step][-MAX_POINTS:]
        vals = [v for _, v in pts]
        first, last = vals[0], vals[-1]
        out.append({
            "dims": s["dims"],
            "first": round(first, 3), "last": round(last, 3), "min": round(min(vals), 3), "max": round(max(vals), 3),
            "mean": round(statistics.fmean(vals), 3),
            "change_pct": None if not first else round((last - first) / abs(first) * 100, 1),
            "points": [(t, round(v, 3)) for t, v in sampled],
        })
    return {"series": out, "series_total": len(series), "series_omitted": max(0, len(series) - MAX_SERIES)}


def preview_envelope(text: str, n: int = 700) -> dict:
    """Compact, already-redacted preview of a tool result or evidence section for the audit trail and the RCA (root
    cause analysis) flow view: row count plus the first rows, or the head of the data. Never the raw log text (the
    guards keep _raw and message out of results in the first place)."""
    body = text
    if body.startswith("<tool_data"):
        body = body.split("\n", 1)[1].rsplit("\n</tool_data>", 1)[0]
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return {"summary": "text", "preview": body[:n]}
    data = obj.get("data", obj) if isinstance(obj, dict) else obj
    if isinstance(obj, dict) and obj.get("error"):
        return {"summary": "error", "preview": str(obj["error"])[:n]}
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        rows = data["results"]
        return {"summary": f"{data.get('result_count', len(rows))} rows", "preview": json.dumps(rows[:6], ensure_ascii=False)[:n]}
    if isinstance(data, dict) and isinstance(data.get("series"), list):
        ser = data["series"]
        brief = [{k: v for k, v in x.items() if k != "points"} for x in ser[:6]]
        return {"summary": f"{data.get('series_total', len(ser))} series", "preview": json.dumps(brief, ensure_ascii=False)[:n]}
    if isinstance(data, list):
        return {"summary": f"{len(data)} items", "preview": json.dumps(data[:4], ensure_ascii=False)[:n]}
    return {"summary": "object", "preview": json.dumps(data, ensure_ascii=False)[:n]}
