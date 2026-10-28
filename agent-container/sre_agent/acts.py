"""Ground truth for the seven war-room acts: what is injected, which detector should fire, the smoking-gun
log events, the expected root cause and the surgical fix. This is the agent's evaluation set (replay-style, like
Datadog's incident scenarios) and the source of the mock investigator's scripted answers. Facts from
services/chaos-controller/app.py, docs/log-schema.md and docs/ai-troubleshooting.md; never shown to the LLM
during a live investigation (that would be cheating), only used to score it afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Act:
    name: str
    title: str
    flags: tuple[str, ...]
    affected_service: str
    detectors: tuple[str, ...]            # detector names (without the "TukTukPay [env] " prefix) expected to fire
    evidence_events: tuple[str, ...]      # log `event` values that prove the root cause
    root_cause: str                       # one sentence, the ground truth
    root_cause_keywords: tuple[str, ...]  # scoring: an investigation is "right" when it names these
    fix_flag: str | None                  # chaos flag whose disabling removes the fault (None = Kubernetes fix)
    kubernetes_fix: str | None = None
    notes: str = ""
    root_cause_services: tuple[str, ...] = ()   # scoring: accepted `root_cause_service` values (substring, lower case)


ACTS: dict[str, Act] = {a.name: a for a in [
    Act("act1", "Acquirer timeout and failover during the 11.11 spike",
        ("festival_spike", "acquirer_kbank_timeout"), "payment-router",
        ("payment-router error rate above 5%", "payment-router p90 latency above 1s", "approval rate below 85%"),
        ("acquirer.timeout", "route.failover", "acquirer.host_unresponsive", "config.changed"),
        "Acquirer acq-kbank hangs (3.2 s) for BIN 457173 / THB; payment-router times out at 2.5 s and fails over to acq-uob, whose THB approval is poor (do_not_honor declines). Not a checkout-api bug.",
        ("kbank", "timeout", "failover"), "acquirer_kbank_timeout", root_cause_services=("acquirer-sim", "acq-kbank")),
    Act("act2", "Risk model v3 canary: slow and over-declining",
        ("festival_spike", "risk_model_drift"), "risk-engine",
        ("risk-engine p90 latency above 100ms", "container CPU at its limit (throttling)"),
        ("config.changed", "risk.inference_slow", "risk.canary_inference", "risk.declined"),
        "A 20 % canary of the CPU-heavy risk model v3 was enabled: inference rises to ~200 ms, the pod pins its 500m CPU limit, and v3 declines wallet IDR/PHP payments with wallet_geo_risk_v3.",
        ("v3", "canary", "risk"), "risk_model_drift", root_cause_services=("risk-engine",)),
    Act("act3", "Copilot tool loop and prompt injection",
        ("copilot_tool_loop", "copilot_prompt_injection"), "merchant-copilot",
        ("copilot token burn above 20k tokens/min", "copilot guardrail blocked an action", "merchant-copilot p90 latency above 5s"),
        ("copilot.tool_loop_suspected", "copilot.max_iterations", "guardrail.prompt_injection_suspected", "guardrail.action_blocked"),
        "The merchant copilot re-calls get_payment until the iteration cap (tokens and latency ×6–12) while injected merchant questions try to trigger refund_payment, which the action guardrail blocks.",
        ("tool loop", "iteration", "injection"), "copilot_tool_loop", root_cause_services=("merchant-copilot",)),
    Act("act4", "Agent mandate violations and a poisoned listing",
        ("agent_traffic_surge", "agent_mandate_violations", "catalog_prompt_injection", "festival_spike"), "checkout-api",
        ("agent mandate blocks above 10% of AMP payments",),   # agent-decline detector excludes governance declines since 21 Oct
        ("mandate.blocked", "catalog.untrusted_listing_served", "risk.declined"),
        "checkout-api correctly blocks AMP agent payments that violate their mandates (over limit, replay, invalid signature, expired, merchant not allowed, KYA untrusted) and risk v2 declines unverified agents; governance working, not an outage.",
        ("mandate", "block"), None, notes="Expected outcome: no remediation; explain and close (agent_mandate_violations is the injected flag, not a fix).", root_cause_services=("none", "checkout-api", "shopping-agent")),
    Act("act4b", "KYA registry unavailable",
        ("agent_traffic_surge", "kya_registry_down"), "wallet-sim",
        ("Know-Your-Agent registry unavailable", "wallet-sim error rate above 20%"),
        ("kya.registry_unavailable", "mandate.blocked"),
        "The KYA (Know-Your-Agent) registry behind wallet-sim returns 503, so every AMP payment is blocked with mandate_kya_unavailable; checkout-api fails closed correctly. Fix wallet-sim's dependency, not checkout-api.",
        ("kya", "registry", "wallet-sim"), "kya_registry_down", root_cause_services=("wallet-sim", "kya")),
    Act("act5", "Ledger pool starvation and a flaky merchant webhook",
        ("ledger_db_slow", "webhook_merchant_flaky"), "ledger",
        ("ledger p90 latency above 400ms", "webhook dead-letters"),
        ("db.pool.reconfigured", "db.pool.wait", "ledger.write_slow", "webhook.dead_lettered", "merchant.webhook_error"),
        "Two independent faults: the ledger connection pool was reconfigured to 2 (pool wait + slow INSERT), and merchant lazada-th's webhook endpoint fails 40 % of deliveries, producing dead-letters.",
        ("pool", "lazada", "webhook"), "ledger_db_slow", notes="Second fix flag: webhook_merchant_flaky (merchant-side; replaying dead-letters is human-approved).", root_cause_services=("ledger",)),
    Act("act6", "Ledger memory leak and OOMKilled restarts",
        ("ledger_memory_leak", "festival_spike"), "ledger",
        ("container memory above 85% of its limit", "Kubernetes container restarted"),
        ("memory.pressure", "ledger.write_failed"),
        "A non-evicting settlement cache in the ledger release leaks ~6 MiB/s until the 384Mi limit, OOMKilled, restart loop. Raising the limit only buys minutes; roll the release back.",
        ("memory", "leak", "ledger"), "ledger_memory_leak", kubernetes_fix="kubectl -n tuktukpay rollout undo deployment/ledger (stands for the release roll-back)", root_cause_services=("ledger",)),
    Act("act7", "wallet-sim 1.7.0 crash loop",
        ("agent_traffic_surge", "wallet_crash_loop"), "wallet-sim",
        ("Kubernetes container restarted", "Kubernetes deployment below desired replicas", "wallet-sim error rate above 20%"),
        ("service.crashed",),
        "Bad rollout wallet-sim 1.7.0: schema migration kya_agents_v2 is missing, the process exits with code 3 seconds after start, CrashLoopBackOff.",
        ("1.7.0", "migration", "crash"), "wallet_crash_loop", kubernetes_fix="kubectl -n tuktukpay rollout undo deployment/wallet-sim", root_cause_services=("wallet-sim",)),
]}


# Healthy-baseline case for the evaluation set (false-positive check): nothing is injected, so the right answer is
# "nothing to fix". Kept out of ACTS so the CLI and the console do not offer it as a war-room act.
BASELINE = Act("baseline", "Healthy baseline (no fault injected)", (), "none",
               ("approval rate below 85%",), (),
               "Nothing is injected; any alert is noise. The agent should find no fault and propose no_action or inconclusive.",
               ("none",), None, root_cause_services=("none",))
EVAL_CASES: dict[str, Act] = {**ACTS, "baseline": BASELINE}


def expected_actions(act: Act) -> set[str]:
    """Catalogue action types that count as the right fix: the flag revert and, where the act has one, the Kubernetes
    roll-back it stands for; no_action when the act is governance working (no fix flag, no Kubernetes fix)."""
    out = set()
    if act.fix_flag:
        out.add("chaos.flag_off:" + act.fix_flag)
    if act.kubernetes_fix and "deployment/" in act.kubernetes_fix:
        out.add("k8s.rollout_undo:" + act.kubernetes_fix.split("deployment/")[1].split()[0])
    return out or {"no_action"}


def score_root_cause(act: Act, text: str) -> dict:
    """Keyword hit rate of an investigation summary against the act's ground truth (cheap, deterministic)."""
    low = text.lower()
    hits = [k for k in act.root_cause_keywords if k.lower() in low]
    return {"act": act.name, "hits": hits, "misses": [k for k in act.root_cause_keywords if k not in hits],
            "score": len(hits) / len(act.root_cause_keywords)}
