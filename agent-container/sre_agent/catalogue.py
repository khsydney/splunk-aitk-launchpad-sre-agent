"""The static remediation catalogue (section 6 of workshop/10-ai-sre-agent-design.md). This file IS the policy:
changing a tier is a reviewed git change, never a runtime learning rule. The LLM chooses an action by enum name;
the executor builds every request from this table — the model never supplies a URL, method, body or command.

Tiers: auto_eligible (may run automatically only when the policy mode is auto-demo and state corroborates),
ask (always needs a human), human_only (dry-run first, never automatic), forbidden (no approval overrides).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

INDEX = "tuktukpay"
ENV_FILTER = "filter('deployment.environment','tuktukpay-demo')"
APM_FILTER = "filter('sf_environment','tuktukpay-demo') and not filter('sf_dimensionalized','*')"
K8S_CLUSTER = os.getenv("K8S_CLUSTER", "tuktukpay-eks")
# Kubernetes metrics carry no deployment.environment; the shared org has other clusters with the same deployment names
# (verified 21 Oct: k8s-checkout-api-oom also runs checkout-api), so every k8s/container query pins cluster + namespace.
K8S_FILTER = f"filter('k8s.cluster.name','{K8S_CLUSTER}') and filter('k8s.namespace.name','tuktukpay')"

# Flags that are faults (revertible) versus scenario load / adversarial-input flags (never "remediated").
FAULT_FLAGS = ("acquirer_kbank_timeout", "risk_model_drift", "copilot_tool_loop", "kya_registry_down",
               "ledger_db_slow", "webhook_merchant_flaky", "ledger_memory_leak", "wallet_crash_loop", "router_failover_disabled")
FORBIDDEN_FLAGS = ("festival_spike", "agent_traffic_surge", "catalog_prompt_injection", "copilot_prompt_injection",
                   "agent_mandate_violations", "traffic_paused")
KNOWN_FLAGS = FAULT_FLAGS + FORBIDDEN_FLAGS
DEPLOYMENTS = ("acquirer-sim", "checkout-api", "ledger", "merchant-copilot", "merchant-sim", "merchant-storefront",
               "payment-router", "risk-engine", "shopping-agent", "wallet-sim", "webhook-dispatcher")


@dataclass(frozen=True)
class Verification:
    immediate: str                     # human-readable layer-1 check (state, within ~10 s)
    outcome_kind: str                  # "spl" | "signalflow" | "none"
    outcome_query: str                 # SPL or SignalFlow program; {earliest} is substituted for SPL
    outcome_condition: str             # "zero" | "below:<n>" | "available_equals_desired"
    timeout_s: int = 120
    description: str = ""


@dataclass(frozen=True)
class Action:
    name: str                          # enum, e.g. chaos.flag_off:acquirer_kbank_timeout
    kind: str                          # chaos.flag_off | k8s.rollout_undo | k8s.patch_limits | copilot.cap_iterations | router.reroute | webhook.dlq_replay | no_action
    target: str
    tier: str                          # auto_eligible | ask | human_only | forbidden | automatic
    blast_radius: str
    real_world: str
    verification: Verification
    implemented: bool = True
    notes: str = ""


def _spl_zero(event_filter: str, extra: str = "") -> str:
    return f"search index={INDEX} earliest={{earliest}} {event_filter} {extra} | stats count"


ACTIONS: dict[str, Action] = {}


def _add(a: Action):
    ACTIONS[a.name] = a


_add(Action("chaos.flag_off:acquirer_kbank_timeout", "chaos.flag_off", "acquirer_kbank_timeout", "auto_eligible", "one acquirer route rule",
            "route BIN 457173 / THB off acq-kbank",
            Verification("GET /flags shows acquirer_kbank_timeout disabled", "spl", _spl_zero("event=acquirer.timeout source=payment-router"), "zero", 300,
                         "acquirer.timeout events stop (two clean 30 s windows within 180 s of the fix)")))
_add(Action("chaos.flag_off:risk_model_drift", "chaos.flag_off", "risk_model_drift", "auto_eligible", "risk-engine",
            "roll the risk model v3 canary back to 0 %",
            Verification("GET /flags shows risk_model_drift disabled", "spl", _spl_zero("event=risk.inference_slow source=risk-engine"), "zero", 210,
                         "risk.inference_slow events stop")))
_add(Action("chaos.flag_off:copilot_tool_loop", "chaos.flag_off", "copilot_tool_loop", "auto_eligible", "merchant-copilot",
            "cap copilot iterations / fix the tool loop",
            Verification("GET /flags shows copilot_tool_loop disabled", "spl", _spl_zero("event=copilot.tool_loop_suspected"), "zero", 300,
                         "no new tool-loop detections")))
_add(Action("chaos.flag_off:kya_registry_down", "chaos.flag_off", "kya_registry_down", "auto_eligible", "wallet-sim",
            "restore the KYA (Know-Your-Agent) registry dependency",
            Verification("GET /flags shows kya_registry_down disabled", "spl", _spl_zero("event=mandate.blocked mandate.block_reason=mandate_kya_unavailable"), "zero", 210,
                         "mandate_kya_unavailable blocks stop")))
_add(Action("chaos.flag_off:ledger_db_slow", "chaos.flag_off", "ledger_db_slow", "auto_eligible", "ledger",
            "revert the connection-pool size change",
            Verification("GET /flags shows ledger_db_slow disabled", "spl", _spl_zero("event=db.pool.wait source=ledger"), "zero", 210, "pool waits stop")))
_add(Action("chaos.flag_off:webhook_merchant_flaky", "chaos.flag_off", "webhook_merchant_flaky", "auto_eligible", "one merchant's webhook deliveries",
            "merchant endpoint fixed; stop hot retries",
            Verification("GET /flags shows webhook_merchant_flaky disabled", "spl", _spl_zero("event=webhook.dead_lettered"), "zero", 300, "no new dead-letters")))
_add(Action("chaos.flag_off:ledger_memory_leak", "chaos.flag_off", "ledger_memory_leak", "auto_eligible", "ledger",
            "roll the ledger release back (non-evicting cache)",
            Verification("GET /flags shows ledger_memory_leak disabled", "signalflow",
                         f"data('k8s.container.restarts', filter=filter('k8s.container.name','ledger') and {K8S_FILTER}, rollup='delta').sum().publish()",
                         "zero", 300, "no further restarts for the window")))
_add(Action("chaos.flag_off:wallet_crash_loop", "chaos.flag_off", "wallet_crash_loop", "auto_eligible", "wallet-sim",
            "roll wallet-sim 1.7.0 back",
            Verification("GET /flags shows wallet_crash_loop disabled", "signalflow",
                         f"A=data('k8s.deployment.available', filter=filter('k8s.deployment.name','wallet-sim') and {K8S_FILTER}).sum(); B=data('k8s.deployment.desired', filter=filter('k8s.deployment.name','wallet-sim') and {K8S_FILTER}).sum(); (B-A).publish()",
                         "zero", 300, "available replicas equal desired")))
_add(Action("chaos.flag_off:router_failover_disabled", "chaos.flag_off", "router_failover_disabled", "auto_eligible", "payment-router",
            "re-enable acquirer failover", Verification("GET /flags shows router_failover_disabled disabled", "spl", _spl_zero("event=payment.failed source=payment-router"), "zero", 180)))
for dep in DEPLOYMENTS:
    _add(Action(f"k8s.rollout_undo:{dep}", "k8s.rollout_undo", dep, "ask", f"deployment {dep}", "roll the release back",
                Verification("rollout status complete", "signalflow",
                             f"A=data('k8s.deployment.available', filter=filter('k8s.deployment.name','{dep}') and {K8S_FILTER}).sum(); B=data('k8s.deployment.desired', filter=filter('k8s.deployment.name','{dep}') and {K8S_FILTER}).sum(); (B-A).publish()",
                             "zero", 300, "available equals desired"),
                notes="precondition: the previous ReplicaSet template differs from the current one (on EKS today they are identical: undo would change nothing)"))
    _add(Action(f"k8s.patch_limits:{dep}", "k8s.patch_limits", dep, "ask", f"deployment {dep}", "raise the memory limit (buys minutes, not a fix)",
                Verification("deployment patched", "none", "", "none", 0), implemented=False))
_add(Action("copilot.cap_iterations", "copilot.cap_iterations", "merchant-copilot", "ask", "merchant-copilot", "configuration change",
            Verification("config applied", "none", "", "none", 0), implemented=False))
_add(Action("router.reroute", "router.reroute", "payment-router", "ask", "one card range", "re-route a BIN to another acquirer",
            Verification("route table updated", "none", "", "none", 0), implemented=False, notes="needs a new router endpoint"))
_add(Action("webhook.dlq_replay", "webhook.dlq_replay", "webhook-dispatcher", "human_only", "merchant receives events again (non-idempotent)",
            "replay dead-letters after the merchant endpoint is fixed", Verification("DLQ depth", "none", "", "none", 0), implemented=False))
_add(Action("no_action", "no_action", "-", "automatic", "none", "explain and notify; the platform is behaving as designed",
            Verification("none", "none", "", "none", 0)))
for flag in FORBIDDEN_FLAGS:
    _add(Action(f"chaos.flag_off:{flag}", "chaos.flag_off", flag, "forbidden", "-", "scenario load or adversarial-input flag, not a fault",
                Verification("none", "none", "", "none", 0), implemented=False, notes="forbidden: not a fault"))


# Verification deadlines in seconds after the fix, as documented in workshop/10-ai-sre-agent-design.md section 6
# (set explicitly here so the table and the code cannot drift; tests/test_guards.py pins them).
DEADLINES = {"acquirer_kbank_timeout": 180, "risk_model_drift": 210, "copilot_tool_loop": 240, "kya_registry_down": 210,
             "ledger_db_slow": 210, "webhook_merchant_flaky": 240, "ledger_memory_leak": 300, "wallet_crash_loop": 300,
             "router_failover_disabled": 180}
for _a in list(ACTIONS.values()):
    _t = DEADLINES.get(_a.target) if _a.kind == "chaos.flag_off" else (300 if _a.kind == "k8s.rollout_undo" else None)
    if _t is not None:
        ACTIONS[_a.name] = Action(**{**_a.__dict__, "verification": Verification(**{**_a.verification.__dict__, "timeout_s": _t})})


def action_enum_for_model() -> list[str]:
    """The choices offered to the LLM: implemented, non-forbidden actions plus no_action and inconclusive."""
    return sorted(a.name for a in ACTIONS.values() if a.tier != "forbidden" and a.implemented) + ["inconclusive"]


# Who gets paged for a root-cause service (the war-room brief's "Page team"). Kit teams; a real estate reads this
# from its service catalogue / CMDB (configuration management database).
OWNERS = {
    "acquirer-sim": "Acquiring & Routing", "payment-router": "Acquiring & Routing",
    "checkout-api": "Checkout Platform", "merchant-storefront": "Merchant Integrations", "merchant-sim": "Merchant Integrations",
    "risk-engine": "Risk & Fraud", "ledger": "Ledger & Settlement", "webhook-dispatcher": "Ledger & Settlement",
    "merchant-copilot": "AI Platform", "shopping-agent": "Agentic Commerce", "wallet-sim": "Agentic Commerce",
}


def owner_of(service: str | None) -> str:
    return OWNERS.get(str(service or ""), "SRE on-call (no owner mapped)")
