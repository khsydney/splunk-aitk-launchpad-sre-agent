# SRE (site reliability engineering) agent: sub-agent hypothesis tree — plan (27 Oct 2026)

the owner's go: 27 Oct ("gogogo"). Goal: Datadog Bits-AI-style hypothesis branching inside our own agent (`services/sre-agent`), run from the AI (artificial intelligence) Toolkit container, with the checks that the Launchpad prompt-only tree lacked (Act 4b: it accepted leftover evidence from Act 7).

## Design
- New `sre_agent/branching.py`, selected with `SRE_AGENT_METHOD=tree` (default stays `loop`, today's single loop). Mock provider unchanged.
- **Planner** (`SRE_AGENT_PLANNER_MODEL`, default Claude Opus 5.5, adaptive thinking): reads the evidence bundle the code already collects (orientation) and writes 2–4 competing hypotheses, each with a test plan. Always includes "fault inside the alerting service" and "a dependency it calls".
- **Workers** (`SRE_AGENT_WORKER_MODEL`, default Claude Sonnet 5.5): one per hypothesis, run in parallel threads (max 4). Each has its own tool set with a small budget (4 tool calls, 2 SPL (Search Processing Language) searches) and returns: verdict (validated / invalidated / inconclusive), evidence with ids, the most specific component implicated, `last_seen_utc` of the signal, and 0–3 narrower child hypotheses when validated.
- **Code checks on every "validated"** (not the model's word): (1) evidence cites a metric-or-trace signal AND a log signal (same rule as `evidence_gap`); (2) `last_seen_utc` within 5 minutes (min) of the case opening, else marked "stale / leftover" and invalidated. A failed check downgrades the verdict and says why.
- **Deepen**: for up to 2 validated branches below depth 3, children become new workers (parallel). Total budget: 240 s (seconds), 12 workers.
- **Decide**: planner model gets the checked tree and writes the normal Investigation JSON (same schema, so policy, approval, console and container stay unchanged). Code attaches `tree` (id, parent, depth, statement, status, check notes, evidence) to the investigation.
- No model escalation for `tree` (the planner is already Opus). Splunk searches: at most 2 in flight across workers (lock), Observability Cloud calls run in parallel.
- Audit: `sre.tree.branch` / `sre.tree.verdict` / `sre.tree.check` events per node; costs summed into the case stats.

## Steps
1. `branching.py` + wiring (`investigator.investigate`, `engine` escalation skip) + unit tests with a fake model client (checks, stale downgrade, depth, budget).
2. Offline eval: 9 replay fixtures, `loop` vs `tree` (correctness, cost, time).
3. Container: add `tree` column, rebuild `tuktukpay/sre-agent-aitk`, run one live act through `| fit AITKContainer`.
4. Console tree view if time allows. Docs: CHANGELOG, PROJECT-STATUS, CLAUDE.md, write-up page.
