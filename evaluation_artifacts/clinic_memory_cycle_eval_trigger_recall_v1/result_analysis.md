# Clinic Memory Cycle Trigger Recall v1 Result Analysis

## Run Identity

- Run date: 2026-05-10
- Scenario: clinic telehealth 3-day memory cycle
- Output folder: `evaluation_artifacts/clinic_memory_cycle_eval_trigger_recall_v1`
- Tier 2 provider: Gemini, `gemini-3-flash-preview`
- Tier 1 provider: local Ollama, `gemma4:e4b`
- Flow count: 300 total, 30 malicious, 270 benign
- Source boundary: Tier 2 consumed organization/security source snapshots. Tier 1 consumed only realtime flow/ML/activity evidence plus Tier 2-curated watchlist/brief artifacts.

## Aggregate Result

| Metric | Previous guardrails v3 | Trigger recall v1 |
|---|---:|---:|
| Final alert TP | 17 | 29 |
| Final alert FP | 0 | 1 |
| Final alert FN | 13 | 1 |
| Final alert recall | 0.567 | 0.967 |
| Final alert precision | 1.000 | 0.967 |
| Review recall | 0.700 | 1.000 |
| Tier 1 calls | 15 | 16 |
| Watchlist hits | 88 | 158 |
| Adjusted by watchlist | 2 | 13 |
| Watchlist linter warnings | 0 | 3 |

The primary target improved: context-dependent malicious alert count increased from the earlier 2/15 baseline to 14/15. All 15 context-dependent malicious flows reached at least review.

## False Positive

One benign flow became a final alert:

```text
flow_id: d02-benign-employee-vpn-014
src_ip: 192.0.2.44
dst: 203.0.113.20:443
ml_prob: 0.27
adjusted_by_watchlist: true
watchlist_matched: P1-20260510-001
match_strength: threat_source
```

This is the expected tradeoff from recall tuning: external VPN traffic matching the stronger Tier 2 VPN trigger can over-alert when the benign employee VPN source looks similar to suspicious external pressure. The FP count is low, but this trigger should be tuned by adding more precise known-bad source conditions or normal employee VPN allow guidance.

## Linter Warnings

Three P1 items were marked context-only because they still lacked strong machine-readable triggers after validation/enrichment:

```text
priority_1:P1-CLINIC-METADATA-005
priority_1:P1-20260510-004
priority_1:P1-CLINIC-IMDS-005
```

These warnings are useful rather than fatal: weak P1 content is preserved as context, but it does not lower routing thresholds as a strong trigger.

## Cost And Tokens

```text
Tier 2 Gemini tokens: prompt 19,733 / completion 11,805 / total 31,538
Estimated Gemini cost: $0.0452815
Tier 1 Ollama tokens: prompt 25,775 / completion 5,992 / total 31,767
Tier 1 API cost: $0.00
```

## Conclusion

The LLM+validator approach achieved the intended recall improvement without sending raw source files to Tier 1. The remaining issue is one VPN false positive caused by an aggressive strong trigger. The next tuning step should narrow VPN trigger matching while preserving repeated-source and known-bad-source recall.
