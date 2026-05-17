# Clinic v5 Dynamic Threshold Result Analysis

## Run

- Output: `evaluation_artifacts/eval_clinic_v5_dynamic_threshold`
- Dataset: `data/sample/clinic_telehealth_flows_xgb.csv`
- Config: `config/settings.clinic_scenario_xgb.yaml`
- Scope: 3 KST days, 300 flows, Gemini Tier 2, Ollama Tier 1
- Tier 2 max tokens: 8192

The first attempt with the default 4096 Tier 2 output-token cap stopped on day 2
because the Gemini response was truncated and could not be parsed as JSON. The
saved result in this folder is the clean rerun with the higher cap and no Tier 2
fallback.

## Aggregate Metrics

| Metric | Value |
|---|---:|
| Total flows | 300 |
| Routes | auto_dismiss 277, tier1_llm 12, auto_alert 11 |
| Verdicts | benign 277, alert 22, uncertain 1 |
| Alert TP / FP / TN / FN | 20 / 2 / 268 / 10 |
| Final alert precision | 0.909 |
| Final alert recall | 0.667 |
| Review recall | 0.700 |
| Tier 1 calls | 12 |
| Tier 2 Gemini tokens | 31,400 |
| Estimated Gemini cost | USD 0.04545 |

## Dynamic Threshold Findings

The dynamic review-threshold layer fired once:

| Flow | ML prob | Effective threshold | Result |
|---|---:|---:|---|
| `xgb-d01-attack-vpn-followup-infiltration-091` | 0.174556 | 0.10 | routed to Tier 1 and alerted |

This recovered one malicious flow that would otherwise have remained below the
normal `priority_1_llm_threshold` of 0.20. It added no dynamic-threshold false
positives in this run.

## Caveats

- Final alert recall is unchanged from the prior XGBoost clinic v4 baseline
  because only one low-score malicious flow was recovered, while ten malicious
  flows still ended as false negatives.
- One Tier 1 call produced an LLM JSON parse fallback:
  `xgb-d02-attack-vpn-followup-infiltration-091`.
- The two false positives were watchlist matches with `asset_service` strength,
  not watchlist-adjusted routing or dynamic-threshold false positives.

## Saved Artifacts

- `summary.md`
- `summary_metrics.json`
- `soc_events.sqlite`
- `day01_2026-05-02/`, `day02_2026-05-03/`, `day03_2026-05-04/`
- Per-day Tier 2 watchlist, brief, memory artifacts
- Per-flow HTML reports
