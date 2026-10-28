# Research scripts (lab history)

These are the scripts used while building and evaluating the agent in the TukTukPay lab (26–28 Oct 2026). They are
kept for reference and reproducibility, **not as the supported setup** — use `quickstart/` for that.

They assume the lab: service names, the war-room fault panel (`CHAOS` URL), detector names, an `sre_agent` MCP token
file next to the script, and the agent package in `agent-container/`. Read each file's header before running one.

| Folder | What |
|---|---|
| `launchpad/` | first agent and MCP connection setup, the tuning harness (`aitk-tuning.py`), side-by-side agent comparison, the hypothesis-tree method test |
| `detection/` | the first ML anomaly alert, the Infrastructure Monitoring add-on setup, the live act test, the enhancement test, and the model bake-off (`bakeoff/`) |
| `agent-container/` | the live test of the container agent, single loop vs. sub-agent tree |
