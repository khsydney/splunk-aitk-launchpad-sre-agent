"""Splunk platform (Splunk Enterprise on EC2 or the Splunk Cloud Show stack) behind the SAME tool names the
Splunk MCP (Model Context Protocol) Server app exposes: `splunk_run_query`, `splunk_get_indexes`.

Two back ends, chosen by environment:
  * `mcp`  — SPLUNK_MCP_CREDS_FILE (line 1 the app's encrypted token, line 2 the URL — the layout of
             sre_agent_mcp_token.txt), or SPLUNK_MCP_URL (e.g. https://<host>:8089/services/mcp) +
             SPLUNK_MCP_TOKEN (bearer). Streamable-HTTP JSON-RPC, same shape as the Observability Cloud gateway.
  * `rest` — the default while the app is not installed: log in through Splunk Web (port 443/8000, as
             lib/stack.py does) and call the web-proxied REST API /en-US/splunkd/__raw/services/...
             Credentials from SPLUNK_PLATFORM_CREDS_FILE (line 1 user, line 2 password, line 4 Splunk Web URL —
             the layout of $SPLUNK_CREDS_FILE), or SPLUNK_PLATFORM_URL + SPLUNK_PLATFORM_USER + _PASSWORD.
Nothing secret is ever printed or logged. TLS (Transport Layer Security) is verified by default (SPLUNK_PLATFORM_VERIFY_TLS=false
opts out and is audited). This adapter only refuses writing commands; the real read-only guard (index pinning, allow-list,
aggregation) is tools.guard_spl, applied by the tool set before anything reaches here.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import ssl
import time

import httpx

TOOL_NAMES = ("splunk_run_query", "splunk_get_indexes")
WRITE_COMMANDS = re.compile(r"\|\s*(collect|outputlookup|outputcsv|delete|sendemail|sendalert|mcollect|meventcollect|summaryindex|runshellscript|script)\b", re.I)


class SplunkError(RuntimeError):
    pass


def guard_spl(spl: str) -> str:
    if WRITE_COMMANDS.search(spl):
        raise SplunkError("refusing SPL with a writing command: " + WRITE_COMMANDS.search(spl).group(1))
    s = spl.strip()
    if not s.startswith("|") and not s.lower().startswith("search "):
        s = "search " + s
    return s


class _RestBackend:
    """Splunk Web form login + web-proxied REST on one pooled, keep-alive httpx client (one TLS handshake per session;
    the EC2 Splunk Web endpoint occasionally stalls a fresh handshake for the full timeout)."""

    def __init__(self):
        creds = os.getenv("SPLUNK_PLATFORM_CREDS_FILE")
        if creds:
            lines = pathlib.Path(creds).read_text().splitlines()
            self.user, self.password = lines[0], lines[1]
            self.base = (os.getenv("SPLUNK_PLATFORM_URL") or (lines[3] if len(lines) > 3 else "")).rstrip("/")
        else:
            self.user = os.getenv("SPLUNK_PLATFORM_USER", "")
            self.password = os.getenv("SPLUNK_PLATFORM_PASSWORD", "")
            self.base = os.getenv("SPLUNK_PLATFORM_URL", "").rstrip("/")
        if not (self.base and self.user and self.password):
            raise SplunkError("Splunk platform credentials missing (SPLUNK_PLATFORM_CREDS_FILE or SPLUNK_PLATFORM_URL/USER/PASSWORD)")
        self.verify = os.getenv("SPLUNK_PLATFORM_VERIFY_TLS", "true").lower() != "false"
        if self.verify:
            verify = ssl.create_default_context(cafile=os.getenv("SSL_CERT_FILE") or os.getenv("REQUESTS_CA_BUNDLE") or None)
        else:
            from .audit import emit
            emit("sre.config.insecure_tls", target=self.base.split("//")[-1].split("/")[0])
            verify = False
        self.http = httpx.Client(verify=verify, timeout=httpx.Timeout(20.0, connect=15.0), follow_redirects=False)
        self.headers: dict = {}
        self._login()

    def _req(self, method: str, url: str, data=None, params=None, retries: int = 1):
        for attempt in range(retries + 1):
            try:
                r = self.http.request(method, url, data=data, params=params, headers=self.headers)
                return r.status_code, r.text
            except (httpx.TimeoutException, httpx.TransportError) as e:
                if attempt >= retries:
                    raise SplunkError(f"{type(e).__name__} talking to Splunk Web") from e
                time.sleep(1.0)

    def _login(self):
        self._req("GET", self.base + "/en-US/account/login")
        cval = self.http.cookies.get("cval", "")
        self.headers = {"X-Requested-With": "XMLHttpRequest", "X-Splunk-Form-Key": cval}
        self._req("POST", self.base + "/en-US/account/login", data={"username": self.user, "password": self.password, "cval": cval})
        if not any(c.startswith("splunkd_") for c in self.http.cookies.keys()):
            raise SplunkError("Splunk Web login failed (check credentials file / allow list)")
        key = next((c for c in self.http.cookies.keys() if c.startswith("splunkweb_csrf_token_")), None)
        self.headers = {"X-Splunk-Form-Key": self.http.cookies.get(key, "") if key else "", "X-Requested-With": "XMLHttpRequest"}

    def get(self, path, **params):
        params.setdefault("output_mode", "json")
        return self._req("GET", f"{self.base}/en-US/splunkd/__raw{path}", params=params)

    def post(self, path, form: dict):
        form = dict(form)
        form.setdefault("output_mode", "json")
        return self._req("POST", f"{self.base}/en-US/splunkd/__raw{path}", data=form)

    def run_query(self, spl: str, earliest: str, latest: str, wait_s: int) -> dict:
        from .audit import mcp_call
        t0 = time.time()
        out = self._run_query(spl, earliest, latest, wait_s)
        mcp_call("splunk-rest", "search/jobs", {"search": spl, "earliest_time": earliest, "latest_time": latest}, t0, True, len(out.get("results", [])))
        return out

    def _run_query(self, spl: str, earliest: str, latest: str, wait_s: int) -> dict:
        st, body = self.post("/servicesNS/nobody/search/search/jobs", {"search": spl, "earliest_time": earliest, "latest_time": latest,
                                                                      "max_time": 55, "auto_cancel": 90, "max_count": 1000})
        if st not in (200, 201):
            raise SplunkError(f"search job HTTP {st}: {body[:200]}")
        sid = json.loads(body)["sid"]
        t0 = time.time()
        content = {}
        while time.time() - t0 < wait_s:
            st, body = self.get(f"/services/search/jobs/{sid}")
            content = json.loads(body)["entry"][0]["content"]
            if content.get("isDone"):
                break
            time.sleep(1.0)
        st, body = self.get(f"/services/search/jobs/{sid}/results", count=1000)
        data = json.loads(body) if st == 200 else {}
        return {"sid": sid, "results": data.get("results", []), "messages": data.get("messages", []),
                "result_count": content.get("resultCount"), "run_duration_s": content.get("runDuration")}

    def get_indexes(self) -> list[str]:
        st, body = self.get("/services/data/indexes", count=0)
        if st != 200:
            raise SplunkError(f"indexes HTTP {st}")
        return [e["name"] for e in json.loads(body)["entry"]]


class _McpBackend:
    def __init__(self):
        lines = pathlib.Path(os.environ["SPLUNK_MCP_CREDS_FILE"]).read_text().splitlines() if os.getenv("SPLUNK_MCP_CREDS_FILE") else []
        self.token = os.getenv("SPLUNK_MCP_TOKEN") or (lines[0].strip() if lines else "")
        self.url = os.getenv("SPLUNK_MCP_URL") or (lines[1].strip() if len(lines) > 1 else "")
        if not (self.url and self.token):
            raise SplunkError("Splunk MCP Server URL or token missing (SPLUNK_MCP_CREDS_FILE or SPLUNK_MCP_URL/TOKEN)")
        # connect fails fast (15 s) so a restarting Splunk surfaces as an error, not a silent hang; searches may take 90 s
        self.http = httpx.Client(timeout=httpx.Timeout(90.0, connect=15.0), verify=os.getenv("SPLUNK_PLATFORM_VERIFY_TLS", "true").lower() != "false")
        self.session_id = None
        self._id = 0
        self._rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "tuktukpay-sre-agent", "version": "0.1"}})

    def _rpc(self, method, params):
        self._id += 1
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {self.token}"}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        res = self.http.post(self.url, headers=h, json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params})
        if res.status_code >= 400:
            raise SplunkError(f"MCP server HTTP {res.status_code}: {res.text[:200]}")
        self.session_id = res.headers.get("Mcp-Session-Id", self.session_id)
        msgs = [json.loads(l[5:]) for l in res.text.splitlines() if l.startswith("data:")] or [json.loads(res.text)]
        if "error" in msgs[-1]:
            raise SplunkError(str(msgs[-1]["error"]))
        return msgs[-1].get("result", {})

    def _tool(self, name, args):
        from .audit import mcp_call
        t0 = time.time()
        try:
            r = self._rpc("tools/call", {"name": name, "arguments": args})
        except Exception as e:  # noqa: BLE001
            mcp_call("splunk-mcp-server", name, args, t0, False, error=f"{type(e).__name__}: {e}")
            raise
        text = "".join(c.get("text", "") for c in r.get("content", []))
        mcp_call("splunk-mcp-server", name, args, t0, not r.get("isError"), len(text), error=text[:200] if r.get("isError") else "")
        if r.get("isError"):
            raise SplunkError(f"{name}: {text[:300]}")
        if isinstance(r.get("structuredContent"), dict):
            return r["structuredContent"]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"text": text}

    def run_query(self, spl, earliest, latest, wait_s):
        # MCP Server 2.0 schema (verified 21 Oct): query, earliest_time, latest_time, app, workload_pool, row_limit
        data = self._tool("splunk_run_query", {"query": spl, "earliest_time": earliest, "latest_time": latest, "row_limit": 1000})
        results = data.get("results", []) if isinstance(data, dict) else data
        count = data.get("total_rows", len(results)) if isinstance(data, dict) else len(results)
        return {"sid": None, "results": results, "messages": [], "result_count": int(count), "run_duration_s": None}

    def get_indexes(self):
        data = self._tool("splunk_get_indexes", {})
        rows = (data.get("results") or data.get("indexes") or []) if isinstance(data, dict) else data
        return [i.get("name", i) if isinstance(i, dict) else i for i in rows if not (isinstance(i, dict) and i.get("disabled"))]


class SplunkPlatform:
    """Tool façade with MCP Server names. `backend` is "mcp" when SPLUNK_MCP_CREDS_FILE or SPLUNK_MCP_URL is set, else "rest"."""

    def __init__(self):
        self.backend_name = "mcp" if os.getenv("SPLUNK_MCP_URL") or os.getenv("SPLUNK_MCP_CREDS_FILE") else "rest"
        self.backend = _McpBackend() if self.backend_name == "mcp" else _RestBackend()
        self.index = os.getenv("SPLUNK_HEC_INDEX", "tuktukpay")

    def splunk_run_query(self, query: str, earliest_time: str = "-15m", latest_time: str = "now", wait_s: int = 90, max_results: int = 200) -> dict:
        spl = guard_spl(query)
        out = self.backend.run_query(spl, earliest_time, latest_time, wait_s)
        out["results"] = out["results"][:max_results]
        out["truncated"] = (out.get("result_count") or 0) > max_results if out.get("result_count") is not None else False
        out["query"] = spl
        return out

    def splunk_get_indexes(self) -> list[str]:
        return self.backend.get_indexes()
