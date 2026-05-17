# Regional Care Dynamic CVE v1 Result Analysis

## Run

- Output: `evaluation_artifacts/eval_dynamic_cve_v1_dynamic_threshold`
- Dataset: `data/sample/regional_care_dynamic_cve_flows_xgb.csv`
- Config: `config/settings.regional_care_dynamic_cve_xgb.yaml`
- Scope: 5 KST days, 1000 flows, Gemini Tier 2, Ollama Tier 1
- Tier 2 max tokens: 8192

## Aggregate Metrics

| Metric | Value |
|---|---:|
| Total flows | 1000 |
| Routes | auto_dismiss 926, tier1_llm 44, auto_alert 30 |
| Verdicts | benign 926, alert 72, uncertain 2 |
| Alert TP / FP / TN / FN | 70 / 2 / 898 / 30 |
| Final alert precision | 0.972 |
| Final alert recall | 0.700 |
| Review recall | 0.710 |
| Tier 1 calls | 44 |
| Tier 2 Gemini tokens | 73,507 |
| Estimated Gemini cost | USD 0.08505 |

## Timeline Metrics

| Window | Alert recall | Alert precision | Watchlist hits | Watchlist-adjusted routes |
|---|---:|---:|---:|---:|
| Days 1-2 pre-change | 0.625 | 0.926 | 98 | 8 |
| Days 3-5 post-change | 0.750 | 1.000 | 170 | 10 |

The staged source changes improved post-change recall without adding alert false
positives. This supports the Batch Loop story: Tier 2 source refreshes helped
after the Tomcat and FortiManager updates. The improvement is not from the new
dynamic threshold layer, though.

## CVE Slices

| Slice | Attack flows | Alert recall | Benign control FPR |
|---|---:|---:|---:|
| CVE-2025-24813 Tomcat | 13 | 0.769 | 0.000 |
| CVE-2024-47575 FortiManager | 7 | 1.000 | 0.000 |

FortiManager coverage was strong. Tomcat coverage missed three attacks: two
`app-host-followup-egress` flows and one `tomcat-lab-api-probe` flow. The
Tomcat misses are still useful because they show that the scenario is not just
"CVE present means alert"; post-exploit egress and lower-score probes still need
better routing coverage.

## Dynamic Threshold Findings

The dynamic review-threshold layer did not fire:

| Metric | Value |
|---|---:|
| Dynamic threshold applied | 0 |
| Dynamic threshold false positives | 0 |
| Dynamic threshold FN recovered | 0 |

This means the latest routing-policy improvement had no measurable recall effect
on this 5-day scenario. Watchlist-adjusted routing still happened 18 times, but
all of it came from the existing priority-1 threshold path rather than the new
lower dynamic threshold path.

## Main Recall Gap

The remaining misses are concentrated in low-ML contextual attacks:

| Slice | Flow count | Alert recall |
|---|---:|---:|
| Low-ML contextual attacks | 32 | 0.094 |
| Infilteration family | 40 | 0.300 |

Missed/uncertain malicious scenarios:

| Scenario | Missed or uncertain | Notes |
|---|---:|---|
| `dns-tunnel-burst` | 10 | No watchlist match; target-asset model does not cover internal-to-external DNS well. |
| `metadata-service-access` | 8 | Some matches exist, but ML scores are often below even the current dynamic floor. |
| `backup-exfil-https` | 6 | Watchlist matches are asset/service-like, not strong egress behavior triggers. |
| `app-host-followup-egress` | 2 | Tomcat-related follow-up egress matched the CVE item but did not route to Tier 1. |
| `workstation-domain-smb` | 2 | No watchlist match; lateral SMB behavior is uncovered. |
| `tomcat-lab-api-probe` | 1 | Low-score Tomcat probe did not route despite CVE context. |
| `vpn-password-spray` | 1 | Routed to Tier 1 but fell back to uncertain due to LLM JSON parse failure. |

False positives were low and not caused by watchlist routing:

| Flow | Reason |
|---|---|
| `xgb-d01-benign-workstation-web-browsing-038` | ML auto-alert at 0.995453 |
| `xgb-d02-benign-workstation-web-browsing-039` | ML auto-alert at 0.995453 |

## Interpretation

The dynamic CVE scenario is healthier than the clinic run for the presentation
story: post-change recall rises from 0.625 to 0.750, CVE-specific benign control
FPR stays at 0, and FortiManager coverage is perfect in this run. The weak point
is the same architectural gap seen in clinic, only clearer: the realtime loop
still misses many low-score egress and lateral movement behaviors before Tier 1
can inspect them.

The next implementation work should not globally lower thresholds. It should
add narrow, source-backed strong triggers for:

- internal DNS clients querying non-approved external DNS repeatedly;
- sensitive internal assets making unusual external HTTPS egress;
- metadata service access with a lower special-case review floor;
- internal workstation/domain SMB anomalies;
- post-CVE app-host egress after Tomcat exposure.

That is the path most likely to improve recall without damaging the currently
strong precision.
