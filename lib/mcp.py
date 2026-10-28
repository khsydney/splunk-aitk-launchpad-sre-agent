"""Minimal MCP (Model Context Protocol) client over HTTP (JSON-RPC, JSON or text/event-stream replies), standard
library only. Used to list a server's tools when creating an AI Toolkit MCP connection: the toolkit's own "list
tools" fails on servers that always answer text/event-stream (e.g. the Observability Cloud gateway)."""
import json, ssl, urllib.request


class MCP:
    def __init__(self, url, headers, verify=True, timeout=60):
        self.url, self.base_headers, self.timeout = url, dict(headers), timeout
        self.ctx = None if verify else ssl._create_unverified_context()
        self.session, self.next_id = None, 0

    def _rpc(self, method, params):
        self.next_id += 1
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **self.base_headers}
        if self.session:
            h["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}).encode(), headers=h)
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
            self.session = r.headers.get("Mcp-Session-Id") or self.session
            text = r.read().decode()
        msgs = [json.loads(l[5:]) for l in text.splitlines() if l.startswith("data:")] or [json.loads(text)]
        if "error" in msgs[-1]:
            raise RuntimeError(f"{method}: {msgs[-1]['error']}")
        return msgs[-1].get("result", {})

    def list_tools(self):
        self._rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "aitk-sre-quickstart", "version": "1"}})
        return self._rpc("tools/list", {}).get("tools", [])
