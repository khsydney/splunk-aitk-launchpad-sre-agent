"""Service-map topology for alert correlation (design section 5.1): which of our services sit on one call path
(caller → callee), so the trigger puts an upstream symptom and its downstream cause into one case. Built from the APM
(Application Performance Monitoring) service map through the Observability Cloud MCP (Model Context Protocol)
gateway and cached; falls back to the map recorded on EKS (Amazon Elastic Kubernetes Service) on 21 Oct 2026."""

from __future__ import annotations

import os
import time
from collections import deque

ENV = os.getenv("DEPLOYMENT_ENVIRONMENT", "tuktukpay-demo")
MAX_HOPS = int(os.getenv("SRE_AGENT_TOPOLOGY_HOPS", "2"))
CACHE_S = int(os.getenv("SRE_AGENT_TOPOLOGY_CACHE_S", "600"))
# Our application services. Left out on purpose: the traffic generator (merchant-storefront calls everything, so
# everything would connect) and stores/brokers (redis:*, postgresql:*; a queue decouples failures).
SERVICES = {"checkout-api", "risk-engine", "payment-router", "acquirer-sim", "ledger", "merchant-sim",
            "merchant-copilot", "wallet-sim", "webhook-dispatcher"}
# caller → callees, from o11y_get_apm_service_dependencies in the recorded eval fixtures (EKS, 21 Oct 2026)
STATIC_EDGES = {"checkout-api": {"risk-engine", "payment-router", "ledger", "wallet-sim"},
                "payment-router": {"acquirer-sim"}, "merchant-copilot": {"ledger"}, "webhook-dispatcher": {"merchant-sim"}}
DIM_KEYS = ("sf_service", "service.name", "k8s.deployment.name", "k8s.container.name", "k8s.pod.name")


class Graph:
    def __init__(self, edges: dict[str, set[str]], source: str):
        self.edges, self.source = edges, source

    def path(self, a: str, b: str, max_hops: int | None = None) -> list[str] | None:
        """Shortest caller → callee path from a to b with at most max_hops edges."""
        max_hops = MAX_HOPS if max_hops is None else max_hops
        q = deque([[a]])
        while q:
            p = q.popleft()
            if len(p) > 1 and p[-1] == b:
                return p
            if len(p) - 1 >= max_hops:
                continue
            for n in sorted(self.edges.get(p[-1], ())):
                if n not in p:
                    q.append(p + [n])
        return None

    def related(self, xs, ys, max_hops: int | None = None) -> list[str] | None:
        """Shortest call path between any service of xs and any of ys, in either direction; [s] for a shared service."""
        best = None
        for x in xs:
            for y in ys:
                if x == y:
                    return [x]
                for p in (self.path(x, y, max_hops), self.path(y, x, max_hops)):
                    if p and (best is None or len(p) < len(best)):
                        best = p
        return best

    def downstream_most(self, svcs) -> list[str]:
        """Services of svcs with no other service of svcs downstream of them: the first root-cause candidates."""
        s = list(dict.fromkeys(svcs))
        return [a for a in s if not any(b != a and self.path(a, b, len(SERVICES)) for b in s)]

    def check_next(self, svcs, max_hops: int | None = None) -> list[dict]:
        """Silent services downstream of the root-cause candidates, nearest first. A caller often records its callee's
        failures (Act 1: payment-router logs the acquirer timeouts, acquirer-sim reports 0 errors), so the real cause
        may never alert."""
        alerting, out = set(svcs), []
        for cand in self.downstream_most(svcs):
            for target in sorted(SERVICES - alerting):
                p = self.path(cand, target, max_hops)
                if p and target not in [x["service"] for x in out]:
                    out.append({"service": target, "path": p})
        return sorted(out, key=lambda x: (len(x["path"]), x["service"]))

    def summary(self, svcs) -> dict:
        return {"root_candidates": self.downstream_most(svcs), "check_next": self.check_next(svcs), "graph": self.source}


def static_graph() -> Graph:
    return Graph({k: set(v) for k, v in STATIC_EDGES.items()}, "static")


_cache: dict = {"at": 0.0, "graph": None}


def _norm(name) -> str | None:
    """`ledger:8084` (an inferred node) → `ledger`; anything that is not one of our services → None."""
    base = str(name or "").split(":", 1)[0]
    return base if base in SERVICES else None


def edges_from_dependencies(service: str, payload: dict) -> set[tuple[str, str]]:
    out = set()
    for d in (payload or {}).get("inboundDependencies") or []:
        a = _norm((d.get("service") or {}).get("name"))
        if a and a != service:
            out.add((a, service))
    for d in (payload or {}).get("outboundDependencies") or []:
        b = _norm((d.get("service") or {}).get("name"))
        if b and b != service:
            out.add((service, b))
    return out


def fetch_graph(mcp, now: float | None = None) -> Graph:
    """Graph from the live service map (one gateway call per service), cached CACHE_S. Some calls failed → live edges
    plus the static map; none succeeded (or the first two failed) → the static map, cached too, so a gateway outage
    does not stall every poll."""
    now = time.time() if now is None else now
    if _cache["graph"] is not None and now - _cache["at"] < CACHE_S:
        return _cache["graph"]
    edges: dict[str, set[str]] = {}
    ok = fails = 0
    for svc in sorted(SERVICES):
        try:
            r = mcp.call("o11y_get_apm_service_dependencies",
                         {"environment_name": ENV, "service_name": svc, "time_range": {"start": "-30m", "stop": "now"}})
            payload = None if r.is_error else r.json()
        except Exception:  # noqa: BLE001 — the static map covers any gateway failure
            payload = None
        if not isinstance(payload, dict):
            fails += 1
            if fails >= 2 and ok == 0:
                break
            continue
        ok += 1
        for a, b in edges_from_dependencies(svc, payload):
            edges.setdefault(a, set()).add(b)
    if not ok or not edges:
        g = static_graph()
    elif fails:
        for a, bs in STATIC_EDGES.items():
            edges.setdefault(a, set()).update(bs)
        g = Graph(edges, "service_map+static")
    else:
        g = Graph(edges, "service_map")
    _cache.update(at=now, graph=g)
    return g


def current_graph(now: float | None = None) -> Graph:
    """The graph last fetched by `watch` or the console's refresher if under 3 × CACHE_S old, else the static map.
    Never calls the gateway, so investigations, eval replays and tests stay offline."""
    now = time.time() if now is None else now
    g = _cache["graph"]
    return g if g is not None and now - _cache["at"] < 3 * CACHE_S else static_graph()


def services_from_dimensions(dims: dict) -> list[str]:
    """Our services named by an incident's dimensions (trigger.ours() keeps them per input, nested one level)."""
    flat: dict[str, str] = {}

    def walk(d):
        for k, v in (d or {}).items():
            if isinstance(v, dict):
                walk(v)
            else:
                flat.setdefault(k, str(v))
    walk(dims)
    out = []
    for k in DIM_KEYS:
        v = flat.get(k, "")
        for s in sorted(SERVICES, key=len, reverse=True):
            if (v == s or v.startswith(s + "-")) and s not in out:   # pod names: ledger-7c9f8-abcde
                out.append(s)
                break
    return out
