# Eval Clinic v4 Result Analysis

## Run Identity

- Output directory: `evaluation_artifacts/eval_clinic_v4`
- Dataset: `data/sample/clinic_telehealth_flows_xgb.csv`
- Config: `config/settings.clinic_scenario_xgb.yaml`
- Batch Loop: Gemini `gemini-3-flash-preview`
- Real Time Loop: XGBoost binary router, XGBoost multiclass attack-family hint, Ollama Tier 1 `gemma4:e4b`
- Total flows: 300, across 2026-05-02 to 2026-05-04 KST
- Labels: 270 benign, 30 malicious
- Gemini external API use was explicitly approved by the user for this run.

This is the first full clinic evaluation that avoids `mock_prob` and routes with
the trained binary XGBoost model. Previous v1-v3 runs used the prompt-control
clinic CSV where ML behavior was manually shaped through `mock_prob`.

## Aggregate Result

| Metric | v4 |
|---|---:|
| auto_dismiss | 278 |
| tier1_llm | 11 |
| auto_alert | 11 |
| final benign | 278 |
| final alert | 22 |
| fallback verdicts | 0 |
| true positives | 20 |
| false positives | 2 |
| true negatives | 268 |
| false negatives | 10 |
| precision | 0.909 |
| recall | 0.667 |
| F1 | 0.769 |
| accuracy | 0.960 |

The system stayed operationally clean: no Tier 2 fallback, no Tier 1 fallback,
and no uncertain verdicts. The cost profile was also small:

| Token/Cost | v4 |
|---|---:|
| Tier 2 Gemini prompt tokens | 19,168 |
| Tier 2 Gemini completion tokens | 10,686 |
| Tier 2 Gemini total tokens | 29,854 |
| Estimated Gemini cost | $0.041642 |
| Tier 1 Ollama calls | 11 |
| Tier 1 Ollama total tokens | 23,609 |

## ML Baseline Impact

The model-only baselines were weaker than the final pipeline:

| Baseline | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| ML only, threshold 0.95 | 9 | 2 | 21 | 0.818 | 0.300 | 0.439 |
| ML only, threshold 0.50 | 14 | 2 | 16 | 0.875 | 0.467 | 0.609 |
| Final pipeline | 20 | 2 | 10 | 0.909 | 0.667 | 0.769 |

Tier 2 watchlist routing and Tier 1 review recovered 6 additional malicious
flows beyond the 0.50 ML-only baseline without adding more false positives.
That is the strongest positive signal in this run: the presentation-first
architecture still adds value after replacing mock routing with real XGBoost
probabilities.

## Comparison With Mock Runs

| Run | Data/ML mode | auto_dismiss | tier1_llm | auto_alert | Precision | Recall | F1 | FP | FN | Tier 1 calls |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| v1 | mock_prob prompt-control | 244 | 41 | 15 | 0.469 | 0.767 | 0.582 | 26 | 7 | 41 |
| v2 | mock_prob guarded | 270 | 15 | 15 | 1.000 | 0.567 | 0.723 | 0 | 13 | 15 |
| v3 | mock_prob tuned guardrails | 269 | 16 | 15 | 0.967 | 0.967 | 0.967 | 1 | 1 | 16 |
| v4 | full-feature XGBoost | 278 | 11 | 11 | 0.909 | 0.667 | 0.769 | 2 | 10 | 11 |

The comparison is not fully apples-to-apples. v1-v3 used manually shaped
`mock_prob`, including 15 obvious attack flows intentionally placed above the
auto-alert threshold. v4 uses real XGBoost probabilities from full feature
vectors, so lower recall is expected. The important comparison is not whether
v4 beats v3 directly, but whether the architecture still improves over real ML
alone. It does.

v4 also lowered Tier 1 workload: 11 LLM calls versus 16 in v3 and 41 in v1.
That is good for cost and latency, but it also means the binary router becomes
the dominant recall limiter. The 10 missed malicious flows were all
auto-dismissed before Tier 1 could inspect them.

## Error Analysis

False positives:

| Flow | Route | ML prob | Category hint | Watchlist | Note |
|---|---|---:|---|---|---|
| `xgb-d01-benign-patient-portal-http-041` | auto_alert | 0.995453 | DDoS | P1-20260511-002 | Benign HTTP portal row looked like DDoS to the model. |
| `xgb-d02-benign-patient-portal-http-045` | auto_alert | 0.995453 | DDoS | P1-20260511-001 | Same high-confidence benign false positive pattern. |

Both false positives came from the binary model's high-confidence auto-alert
path, not from watchlist threshold lowering. `fp_adjusted_by_watchlist` was 0.

False negatives:

| Pattern | Count | Route | ML probability range |
|---|---:|---|---|
| `Infilteration` DNS tunnel burst | 3 | auto_dismiss | 0.0778 to 0.0874 |
| `Infilteration` metadata service access | 3 | auto_dismiss | 0.0296 to 0.0718 |
| `Infilteration` backup exfil HTTPS | 3 | auto_dismiss | 0.1746 to 0.2304 |
| `Infilteration` VPN follow-up | 1 | auto_dismiss | 0.1746 |

All 10 false negatives are `Infilteration` family flows. The multiclass hint
never ran for them because they were below the low routing threshold. Some
matched watchlist context, but the watchlist item was either context-only or the
ML score stayed below the priority-1 lowering threshold.

By attack family, v4 detected:

| Attack family | Detected | Missed | Notes |
|---|---:|---:|---|
| Brute_Force_-Web | 6 | 0 | Routed to Tier 1, all alerted. |
| SQL_Injection | 6 | 0 | Split between auto_alert and Tier 1, all alerted. |
| SSH-Bruteforce | 3 | 0 | Auto-alerted with BruteForce hint. |
| DDOS_attack-HOIC | 3 | 0 | Auto-alerted with DDoS hint. |
| Infilteration | 2 | 10 | Main recall gap. |

## Interpretation

v4 validates the full-feature path mechanically and behaviorally:

- The pipeline used real XGBoost binary routing rather than `mock_prob`.
- Multiclass hints appeared on `auto_alert` and `tier1_llm` paths.
- SHAP top5 appeared on `tier1_llm` reports, where it is used as LLM evidence.
- Gemini Tier 2 generated watchlists, memory, and briefs for each day without fallback.
- SQLite, HTML reports, per-day metrics, and aggregate metrics were all written.

The main weakness is recall on low-scoring `Infilteration` scenarios. This is
not primarily a Tier 1 prompt problem because Tier 1 never saw those flows. It
is a routing problem at the boundary between the binary model and watchlist
threshold-lowering policy.

## Recommendations

1. Add an explicit evaluation slice for `Infilteration` low-probability attacks.
   The current full-feature set reveals a realistic blind spot that mock_prob
   hid.

2. Consider a targeted review policy for known weak families or high-value
   destinations when ML probability is between 0.15 and 0.30. This should be
   constrained by strong Tier 2 trigger evidence to avoid returning to v1-style
   false positives.

3. Revisit the feature projection for DNS tunnel, metadata access, and backup
   exfil scenarios. If their source NF-CICIDS2018 feature vectors are too
   benign-looking after clinic projection, the scenario is still useful, but it
   should be documented as a stress test for context-aware routing rather than
   an expected ML win.

4. Keep v3 as the prompt/guardrail target and v4 as the model-backed realism
   target. v3 proves the LLM/watchlist behavior under controlled ML scores; v4
   exposes the actual routing recall ceiling.
