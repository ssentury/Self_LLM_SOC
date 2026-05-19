# Review Strength Sync Evaluation Analysis

Date: 2026-05-19 KST

## Runs Preserved

- Clinic baseline: `evaluation_artifacts/eval_clinic_v5_dynamic_threshold`
- Clinic new run: `evaluation_artifacts/eval_clinic_v6_review_strength_sync_8192`
- Dynamic CVE baseline: `evaluation_artifacts/eval_dynamic_cve_v1_dynamic_threshold`
- Dynamic CVE new run: `evaluation_artifacts/eval_dynamic_cve_v2_review_strength_sync_8192`
- Structured comparison: `evaluation_artifacts/review_strength_sync_comparison_20260519/comparison_metrics.json`
- This analysis: `evaluation_artifacts/review_strength_sync_comparison_20260519/analysis.md`

The first clinic rerun at the default `tier2-max-tokens=4096` is also preserved at
`evaluation_artifacts/eval_clinic_v6_review_strength_sync`. It stopped on day 2
because Gemini returned a truncated JSON object and the evaluator correctly refused
to accept deterministic fallback. The completed runs use `tier2-max-tokens=8192`.

## Commands

```powershell
docker compose run --rm -e 26_AISecApp_Project_GEMINI_API_KEY app python scripts/evaluate_clinic_memory_cycle.py --output evaluation_artifacts/eval_clinic_v6_review_strength_sync_8192 --tier2-max-tokens 8192 --clean
docker compose run --rm -e 26_AISecApp_Project_GEMINI_API_KEY app python scripts/evaluate_dynamic_cve_memory_cycle.py --output evaluation_artifacts/eval_dynamic_cve_v2_review_strength_sync_8192 --tier2-max-tokens 8192 --clean
docker compose run --rm app python -m pytest
```

`pytest` result: 97 passed in 14.37s.

## Logic Change Summary

The recent changes made the realtime loop more willing to review medium-strength
Tier 2 watchlist matches:

- `REVIEWABLE_MATCH_STRENGTHS` now includes `review_candidate` and
  `behavioral_review`, not only stronger matches such as `behavior`,
  `threat_source`, and `policy_violation`.
- `match_watchlist()` marks `trigger_matched=true` when the best machine-readable
  hint strength is in that reviewable set.
- `route_flow()` uses the shared `REVIEWABLE_MATCH_STRENGTHS` set plus
  `trigger_matched` and `not context_only` before lowering the Tier 1 review
  threshold.
- Queue priority now uses the same watchlist reviewability gate as the router.
- Tier 2 watchlist quality enforcement can synthesize source-wide DNS and metadata
  patterns with low `routing_policy.review_threshold` values, including 0.04 for
  critical source-wide DNS and metadata patterns.

Expected effect: more low-ML but contextually important attacks should reach Tier 1.
Risk: source-wide or weakly scoped patterns can send too much benign traffic to
Tier 1 and make the LLM over-alert because the prompt says Tier 2 curated it.

## Clinic Scenario Result

The clinic scenario improved cleanly.

| Metric | Baseline | New | Change |
|---|---:|---:|---:|
| Final alert TP | 20 | 26 | +6 |
| Final alert FP | 2 | 0 | -2 |
| Final alert FN | 10 | 4 | -6 |
| Final alert precision | 0.909 | 1.000 | +0.091 |
| Final alert recall | 0.667 | 0.867 | +0.200 |
| Final alert F1 | 0.769 | 0.929 | +0.159 |
| Review recall | 0.700 | 1.000 | +0.300 |
| Tier 1 calls | 12 | 15 | +3 |

Day-level result:

| Day | Old TP/FP/FN | New TP/FP/FN | Old review FN | New review FN |
|---|---:|---:|---:|---:|
| 1 | 7/1/3 | 8/0/2 | 3 | 0 |
| 2 | 6/1/4 | 9/0/1 | 3 | 0 |
| 3 | 7/0/3 | 9/0/1 | 3 | 0 |

Interpretation:

- The intended effect is visible here. More malicious context flows reached
  non-benign review, and false positives disappeared.
- The extra Tier 1 cost is small: 12 to 15 calls.
- Dynamic threshold use did not increase in this run, so the improvement is mostly
  from better Tier 2 watchlist content plus the realtime loop recognizing more
  reviewable match strengths.

## Dynamic CVE Scenario Result

The dynamic CVE scenario shows a strong recall gain but an unacceptable precision
regression.

| Metric | Baseline | New | Change |
|---|---:|---:|---:|
| Final alert TP | 70 | 87 | +17 |
| Final alert FP | 2 | 153 | +151 |
| Final alert FN | 30 | 13 | -17 |
| Final alert precision | 0.972 | 0.362 | -0.610 |
| Final alert recall | 0.700 | 0.870 | +0.170 |
| Final alert F1 | 0.814 | 0.512 | -0.302 |
| Review recall | 0.710 | 0.920 | +0.210 |
| Tier 1 calls | 44 | 224 | +180 |
| Dynamic threshold applied | 0 | 138 | +138 |
| Dynamic-threshold attack recoveries | 0 | 15 | +15 |
| Dynamic-threshold FP alerts | 0 | 120 | +120 |

Window-level behavior:

| Window | Old alert recall | New alert recall | Old FP | New FP |
|---|---:|---:|---:|---:|
| Days 1-2 | 0.625 | 0.850 | 2 | 61 |
| Days 3-5 | 0.750 | 0.883 | 0 | 92 |

High-value slices improved:

| Slice | Baseline alert recall | New alert recall |
|---|---:|---:|
| CVE-2025-24813 attacks | 0.769 | 0.923 |
| CVE-2024-47575 attacks | 1.000 | 1.000 |
| Low-ML contextual attacks | 0.094 | 0.750 |
| Infilteration family | 0.300 | 0.825 |

The expected recall effect is very clear, especially for low-ML contextual attacks.
But the result is not operationally acceptable because most of the gain came with
a large benign DNS false-positive wave.

## Root Cause of Dynamic CVE FP Regression

The new false positives are highly concentrated:

- `fp_by_match_strength`: `review_candidate=151`, `asset_only=2`
- `fp_by_watchlist_item`: `P1-SOURCE-PATTERN-DNS-TUNNEL-BURST=153`
- detailed drilldown:
  `evaluation_artifacts/review_strength_sync_comparison_20260519/dynamic_fp_root_cause_deep_dive.md`

The detailed drilldown shows the FP set is not only DNS-like traffic:

| FP family | Count |
|---|---:|
| workstation DNS | 116 |
| workstation NTP | 35 |
| workstation web browsing | 2 |

The decisive issue is the interaction between broad source-scoped watchlist
items and current detection-hint semantics. The generated DNS item contains broad
workstation source CIDRs in `target_assets`, then repeats those same CIDRs as a
`src_ip in_cidr` detection hint. The matcher does not require all detection hints
to match as an AND group. It collects any matching hint, then derives
`match_strength` from the matched subset.

That means a normal workstation flow can match `P1-SOURCE-PATTERN-DNS-TUNNEL-BURST`
through the source CIDR alone. The other intended discriminators, such as
`dst_port == 53`, `protocol == 17`, external destination, and repeated DNS
activity, do not all need to match for the item to become a `review_candidate`.
This is why 35 NTP flows and 2 web-browsing flows also landed under the DNS-tunnel
watchlist item.

The route then becomes operationally expensive because the item carries
`routing_policy.review_threshold: 0.04`. Of the 153 FP alerts, 151 were watchlist
adjusted, 120 used the dynamic 0.04 threshold, and the median ML probability was
only about 0.086. Tier 1 then receives a Tier 2-curated DNS-tunnel context and
often turns that context into an alert.

Sample dynamic-threshold composition:

| Applied row type | Count |
|---|---:|
| Benign -> alert | 120 |
| Malicious Infilteration -> alert | 15 |
| Benign -> uncertain | 3 |

So the new logic did expose low-ML attacks, but it also exposed a contract bug:
source-wide hints are currently allowed to act like standalone triggers. The DNS
source-wide item should either be conjunctive, require a grouped set of service
and behavior hints, or stay context-only until a stronger discriminator is present.

## Conclusion

Clinic: expected effect is successful. The new logic improves recall and precision
with only a small Tier 1 call increase.

Dynamic CVE: expected recall effect is visible, but the result is not acceptable.
The broad DNS review candidate turns normal workstation DNS/NTP/web traffic into
Tier 1 work and then alerts. The main next fix should not be to remove
`review_candidate` globally. It should narrow source-wide DNS routing:

- support explicit AND/grouped detection hints for Tier 2 watchlist items,
- prevent `src_ip in_cidr` from acting as the only reviewable trigger when the
  same CIDR is already the source-side `target_assets` scope,
- require an approved-resolver allowlist or suspicious destination/known-bad
  resolver signal,
- require stronger behavior such as unusually high bytes/packets, many distinct
  destinations, or abnormal DNS-specific features,
- raise DNS source-wide `review_threshold` above 0.04, or
- mark broad DNS source-wide items as `context_only` unless another threat-source
  or behavioral signal also matches.

That would preserve the low-ML attack recall gains while reducing the 153 DNS false
alerts.
