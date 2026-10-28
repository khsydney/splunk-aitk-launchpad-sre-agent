# Anomaly detection coverage — plan (28 Oct 2026)

the owner: "make sure to cover what ECOD (Empirical-Cumulative-distribution-based Outlier Detection) isn't good at; find all possible cases and models; create containers". Status: **plan, waiting for the owner's go** (CLAUDE.md working style). Evidence so far: `workshop/CHANGELOG.md` 28 Oct (act test, bake-off, combinations).

## 1. Cases ECOD alone does not cover, and what covers each

| # | Case (payments example) | Why ECOD misses or misfires | Cover with | Runs where |
|---|---|---|---|---|
| 1 | **Sudden spike or drop across several signals** (acquirer timeouts, error burst) | — (ECOD's strength) | **ECOD** per service, all signals | DSDL (Data Science and Deep Learning) module `tuktuk_ecod` |
| 2 | **Slow drift / leak** (memory climbing for hours, latency creeping 1 % per hour) | each minute is judged alone; a slow climb stays "normal" until extreme | **trend + change-point**: rolling Theil–Sen slope vs. normal slope, CUSUM (cumulative sum) of residuals, and **time-to-limit** for resources with a limit (memory vs. limit) | DSDL module `tuktuk_drift` |
| 3 | **Level shift that becomes the new normal** (new release 20 % slower, stays slower) | after the first minutes the shifted level looks ordinary to a short window; ECOD trained on old data keeps flagging forever or misses the onset | **change-point** (CUSUM / Page–Hinkley) marks the onset once; retraining absorbs the new level | `tuktuk_drift` |
| 4 | **Daily / weekly patterns** (lunch peak, payday, 11.11 sale) | no notion of time: a normal busy hour looks anomalous, a problem in a quiet hour looks normal | **seasonal baseline**: STL (seasonal-trend decomposition) residuals now; Prophet when ≥ 2 weeks of history; time-of-day features for ECOD | DSDL module `tuktuk_seasonal` |
| 5 | **Unusual combinations of normal values** (normal traffic and normal latency, but CPU high; errors low but retries high) | scores each signal independently | **Isolation Forest** (multivariate, captures interactions), 2 consecutive minutes | DSDL module `tuktuk_iforest` |
| 6 | **Very quiet services / low counts** (normally 0 errors; 1 harmless warning) | one event is an extreme tail value | **Poisson count test** (is the count unlikely given the normal rate?) + minimum size (≥ 5 events or ≥ x % change) | DSDL module `tuktuk_rules` |
| 7 | **New error types / new services** (`kya.registry_unavailable` never seen before) | no training data → no score | **novelty rule**: an error-level event type not seen in the training period, ≥ 3 per minute | `tuktuk_rules` (needs the known-event list, saved at training) |
| 8 | **Business KPIs (key performance indicators)** (approval rate drop, mandate blocks, refunds) | only if the ratio is an input; small denominators are noisy | **proportion test** (binomial: is this share unlikely given the normal share and today's volume?) on decline %, mandate-block %, approval % | `tuktuk_rules`; ratios also feed ECOD's "business" service |
| 9 | **Missing data / silence** (a service stops logging or reporting: crash, network split) | no rows = nothing to score | **heartbeat rule**: expected signal absent for N minutes (requests or logs fall to 0 when normally > 0) | `tuktuk_rules` |
| 10 | **Restarts / crash loops** (OOM (out-of-memory) kill, bad release) | restarts are sparse spikes | any restart counts (count rule), plus ECOD input | `tuktuk_rules` |
| 11 | **Planned changes** (deploy, load test, batch job) | look like anomalies | **suppression windows** (KV (key-value) store lookup of planned changes) and deploy markers lower severity | SPL (Search Processing Language) in the alert |
| 12 | **Where does it start?** (caller vs. callee) | ECOD's biggest change is usually a caller | **call-graph ranker** (deepest flagged service) | alert SPL / ranker step |
| 13 | **Faults outside our signals** (partner outage only seen as declines; security abuse) | not in the inputs | keep Observability Cloud detectors and SLOs (service-level objectives); business ratios (case 8) | Observability Cloud (unchanged) |
| 14 | **Model ageing** (traffic grows, new normal) | thresholds go stale | **retrain** weekly on recent clean minutes (scheduled search), keep the previous model for rollback | scheduled `| fit` |

Not planned now (documented limits): log-message text anomalies beyond structured `event` names (needs log template mining or embeddings — the image has `llm_rag_log_encoder`, unproven), multi-day seasonality (needs weeks of data), root cause beyond the call graph (the agent does that).

## 2. Containers

- **One detection container** `tuktuk-detect` (image `tuktukpay/anomaly-aitk:<date>`, based on Splunk's `mltk-container-golden-cpu:5.2.1`, which already has PyOD, scikit-learn, statsmodels, Prophet), separate from the agent container `tuktuk-sre`, on `127.0.0.1:5001`, 2 API workers, model files on a Docker volume.
- Modules (each with `init / fit / apply / save / load / summary`, scaling inside, one model per service, joblib persistence that works — the shipped notebooks' `load()` is broken): `tuktuk_ecod`, `tuktuk_iforest`, `tuktuk_drift`, `tuktuk_seasonal`, `tuktuk_rules`.
- Registered in the toolkit as model stanzas pointing at `https://localhost:5001` (the agent container keeps `5000`).
- Every module returns the same columns per (minute, service): `score`, `flag`, `reason` (which signal, which test), so the alert can combine them.

## 3. How the alert uses them

1. Every 2 min: build the per-minute feature table for the last ~90 min (logs, APM via `| sim flow`, restarts, business).
2. `| apply` each module; a service is anomalous if ECOD flags it, or IF (2 min), drift, seasonal or a rule flags it.
3. Call-graph ranker → one row: likely origin + driving reasons (e.g. "ledger: memory slope 6 MiB/s, time to limit 4 min; APM errors 12 %").
4. Throttle per fault (marker written when the agent starts), suppression windows, then `| aiagent` (or the container agent).
The three `DensityFunction` models are retired only after the new alert passes the act re-test.

## 4. Testing

- **Acts 1–7 (live)** for cases 1, 7, 8, 10, 12.
- **Synthetic injections** into recorded quiet data for what the acts do not exercise: slow ramp (case 2), step that persists (3), shifted daily curve (4), swapped-correlation minutes (5), single events on a quiet service (6), dropped signal (9), planned window (11). Each module must catch its case and not raise false alarms on the 17 quiet overnight hours.
- Report: per case × module matrix (caught / missed / false alarms per day).

## 5. Effort and order

1. Modules + unit tests in the container image (offline, no live change) — about half a day.
2. Synthetic-injection test matrix + the overnight false-alarm check — about 2 hours.
3. New alert (disabled), replay, then live act re-test — about 2 hours including panel time.
4. Switch over, retire the old models, docs and the write-up page.

## Open questions for the owner

- Seasonality needs history: Prophet only after ~2 weeks of data (EKS (Amazon Elastic Kubernetes Service) has run since 20 Oct; the panel history resets when its pod restarts). Start with STL on what exists?
- Retrain weekly automatically, or only on demand?
- Planned-change windows: who enters them (a small form in the SRE Agent app, or a lookup file)?
