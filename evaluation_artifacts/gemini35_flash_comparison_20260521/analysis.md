# Gemini 3.5 Flash Evaluation Comparison

Date: 2026-05-21 KST

## Runs Preserved

- Clinic previous: `evaluation_artifacts/eval_clinic_v6_review_strength_sync_8192`
- Clinic failed 8192 attempt: `evaluation_artifacts/eval_clinic_v7_gemini35_flash_20260521`
- Clinic completed: `evaluation_artifacts/eval_clinic_v7_gemini35_flash_16384_20260521`
- Dynamic CVE previous: `evaluation_artifacts/eval_dynamic_cve_v2_review_strength_sync_8192`
- Dynamic CVE completed: `evaluation_artifacts/eval_dynamic_cve_v3_gemini35_flash_16384_20260521`
- Structured comparison: `evaluation_artifacts/gemini35_flash_comparison_20260521/comparison_metrics.json`

## Verification

- Docker could not be used in this desktop session because access to `npipe:////./pipe/docker_engine` was denied.
- I used the Codex bundled Python plus workspace-local temporary dependencies under `.tmp/eval_deps`; the repository files under `.ml_deps` were not permission-reset or modified.
- Test result: `101 passed in 19.69s`.

## Logic Change Under Test

The current worktree changes do not alter the Tier 1 router, queue policy, watchlist matcher, or dynamic-threshold algorithm. The functional change being evaluated here is the Tier 2 model switch from `gemini-3-flash-preview` to `gemini-3.5-flash` across settings, provider defaults, runners, tests, and evaluator defaults. The evaluator pricing constants also changed from `$0.50/$3.00` per 1M input/output tokens to `$1.50/$9.00`, so reported Gemini cost is not directly comparable as a pure usage signal.

One operational side effect appeared immediately: the clinic run with the old 8192 max output budget failed because Gemini returned truncated JSON. The completed runs therefore use `--tier2-max-tokens 16384`. That means the quality comparison mainly reflects the new model behavior, while cost and completion-token totals also reflect the larger output allowance.

## Clinic Scenario

| Metric | Previous | New | Change |
|---|---:|---:|---:|
| Alert TP | 26 | 24 | -2 |
| Alert FP | 0 | 1 | +1 |
| Alert FN | 4 | 6 | +2 |
| Alert precision | 1.000 | 0.960 | -0.040 |
| Alert recall | 0.867 | 0.800 | -0.067 |
| Alert F1 | 0.929 | 0.873 | -0.056 |
| Review recall | 1.000 | 0.967 | -0.033 |
| Tier 1 calls | 15 | 16 | +1 |
| Tier 2 tokens | 32821 | 44204 | +11383 |
| Estimated Tier 2 cost | $0.047053 | $0.243381 | $0.196328 |

Day-level clinic behavior:

| Day | Previous TP/FP/FN | New TP/FP/FN | Tier 1 calls |
|---|---:|---:|---:|
| 1 | 8/0/2 | 8/0/2 | 5 -> 5 |
| 2 | 9/0/1 | 8/1/2 | 5 -> 6 |
| 3 | 9/0/1 | 8/0/2 | 5 -> 5 |

Interpretation: the clinic result regressed modestly. Previous Gemini preview output produced perfect review recall and no FP. Gemini 3.5 Flash missed one malicious flow even at review level and created one false alert from a `threat_source` match. The router did not change, and dynamic threshold stayed at zero in both runs, so the difference is attributable to Tier 2 curation content and Tier 1 prompt context created from that content. The new model also wrote much longer Tier 2 output, raising Tier 2 completion tokens from 12,257 to 23,610.

The one clinic FP was `d02-benign-employee-vpn-014`: a benign employee VPN flow with ML probability 0.27 that went to Tier 1 and was elevated to `alert` after matching `P1-20260521-001`. This is not a dynamic-threshold problem; it is a Tier 2 context/Tier 1 interpretation problem.

## Dynamic CVE Scenario

| Metric | Previous | New | Change |
|---|---:|---:|---:|
| Alert TP | 87 | 90 | +3 |
| Alert FP | 153 | 2 | -151 |
| Alert FN | 13 | 10 | -3 |
| Alert precision | 0.362 | 0.978 | +0.616 |
| Alert recall | 0.870 | 0.900 | +0.030 |
| Alert F1 | 0.512 | 0.938 | +0.426 |
| Review recall | 0.920 | 0.920 | +0.000 |
| Tier 1 calls | 224 | 65 | -159 |
| Dynamic threshold applied | 138 | 15 | -123 |
| Dynamic threshold FP alerts | 120 | 0 | -120 |
| Dynamic threshold FN recovered | 15 | 15 | +0 |
| Tier 2 tokens | 78393 | 106237 | +27844 |
| Estimated Tier 2 cost | $0.089772 | $0.526863 | $0.437092 |

Day-level dynamic behavior:

| Day | Previous TP/FP/FN | New TP/FP/FN | Tier 1 calls | Dynamic threshold |
|---|---:|---:|---:|---:|
| 1 | 17/30/3 | 19/1/1 | 44 -> 12 | 29 -> 5 |
| 2 | 17/31/3 | 17/1/3 | 43 -> 12 | 29 -> 3 |
| 3 | 17/30/3 | 17/0/3 | 45 -> 13 | 27 -> 2 |
| 4 | 18/31/2 | 18/0/2 | 49 -> 17 | 27 -> 3 |
| 5 | 18/31/2 | 19/0/1 | 43 -> 11 | 26 -> 2 |

High-value dynamic slices:

| Slice | Previous alert recall | New alert recall | Previous flow count | New flow count |
|---|---:|---:|---:|---:|
| CVE-2025-24813 | 0.923 | 0.923 | 13 | 13 |
| CVE-2024-47575 | 1.000 | 1.000 | 7 | 7 |
| Low-ML contextual attacks | 0.750 | 0.750 | 32 | 32 |
| Infilteration family | 0.825 | 0.825 | 40 | 40 |

Interpretation: dynamic CVE improved dramatically. The previous run had already proved that broad `review_candidate` routing could recover low-ML attacks, but it also created a DNS false-positive wave: 153 alert FPs, 151 from `review_candidate`, all concentrated on `P1-SOURCE-PATTERN-DNS-TUNNEL-BURST`. In the new run, Gemini 3.5 Flash generated narrower watchlist content. Tier 1 calls fell from 224 to 65, dynamic-threshold applications fell from 138 to 15, dynamic-threshold FP alerts fell from 120 to 0, and total alert FPs fell from 153 to 2 while alert recall still rose from 0.870 to 0.900.

The two remaining dynamic-CVE FPs were `xgb-d01-benign-workstation-web-browsing-038` and `xgb-d02-benign-workstation-web-browsing-039`. Both were high-ML-probability benign web-browsing rows (`ml_prob=0.99545`) that took the `auto_alert` route. They were not caused by the low dynamic threshold and did not come from the earlier DNS-tunnel `review_candidate` failure mode.

The expected effect is therefore mixed by scenario. For dynamic CVE, the model switch achieved the desired operational effect very clearly: it preserved or improved recall while removing the broad DNS FP failure mode. For clinic, the same switch reduced quality slightly: fewer malicious alerts, one review miss, and one FP. This suggests Gemini 3.5 Flash is better at the larger, changing source-corpus curation problem, but not automatically better for the smaller clinic memory-cycle prompt.

## Cost And Runtime Notes

The new completed runs use a larger `maxOutputTokens` budget because the first clinic 8192 run returned truncated JSON. That is itself an important compatibility finding: the new model may need a higher output ceiling or stricter prompt/output compaction. Reported costs increased for two reasons: output grew, and the evaluator pricing constants were tripled. The dynamic run still reduced Tier 1 local workload substantially, from 540,305 Tier 1 tokens to 201,424, even though Tier 2 Gemini output grew.

## Conclusion

Use `gemini-3.5-flash` cautiously. It is a clear win for the dynamic CVE scenario because it fixes the earlier broad DNS watchlist failure mode without sacrificing recall. It is not a universal win: clinic quality regressed from the previous preview-model run. The next hardening step should be to constrain Tier 2 output size and add watchlist quality checks that explicitly reject overlong or under-scoped items before the realtime loop consumes them.
