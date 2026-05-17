# Dynamic CVE Miss Root-Cause Analysis

## Bottom Line

The main bottleneck is routing, but the immediate failure is not just "the
threshold was too high." Most missed malicious flows did not have a strong,
machine-readable Tier 2 watchlist trigger that the router was allowed to trust.

For the 30 malicious non-alert outcomes:

| Root cause | Count | Meaning |
|---|---:|---|
| Tier 2 did not create a relevant routable strong trigger | 17 | DNS tunnel, most metadata, workstation-domain SMB had no watchlist match. |
| Tier 2 created context but only as weak asset/service match | 9 | Backup exfil, Tomcat follow-up egress, and one Tomcat probe matched only asset/port context. |
| Router threshold/policy was too conservative | 2 | Metadata access had strong match, but effective threshold stayed at 0.20. |
| Tier 1 failure after routing | 1 | VPN password spray reached Tier 1 but JSON parsing failed and became uncertain. |
| Other low-score miss | 1 | Metadata access below any current reasonable floor. |

This means dynamic review thresholding is important, but it only helps after
Tier 2 has produced a strong observable trigger. In this run, dynamic threshold
was applied 0 times.

## Cause 1: Tier 2 Did Not Build the Right Attack Scenario or Flow Conditions

Strong evidence:

- `dns-tunnel-burst`: 10/10 missed.
- `workstation-domain-smb`: 2/2 missed.
- Most `metadata-service-access` misses after day 1 had no watchlist match.

The Tier 2 artifacts did discuss Tomcat, FortiManager, backup, and some metadata
risk, but they did not consistently model network-wide egress behaviors:

- internal workstation -> external DNS `8.8.8.8:53`;
- workstation -> domain-controller SMB anomaly;
- internal host -> metadata service after day 1;
- sensitive internal asset -> unknown external HTTPS.

This is a Tier 2/source-to-watchlist coverage gap. The current watchlist shape is
still biased toward "important target asset receives suspicious traffic."

## Cause 2: Tier 2 Produced Context, But the Evidence Was Not Specific Enough

Examples:

| Scenario | Watchlist result |
|---|---|
| `backup-exfil-https` | Matched `backup-nas` and port 443, but only `asset_service`; no strong "backup NAS external egress" behavior trigger. |
| `app-host-followup-egress` | Matched Tomcat item by source asset and HTTPS egress, but only `asset_service`. |
| `tomcat-lab-api-probe-182` | Matched Tomcat asset and 8443, but did not match a strong scanner/source/repetition condition. |

Tier 2 often wrote the right idea in prose:

- "post-exploit egress from API hosts";
- "known scanner";
- "backup system tampering";
- "metadata access should be suspicious."

But those ideas were not always converted into structured detection hints that
the router classifies as `behavior`, `threat_source`, or `policy_violation`.

The linter caught one concrete Tomcat issue:

```text
reason/escalation mentions known bad source but no src_ip/known_bad_source hint exists.
```

So cause 2 is real: Tier 2 understood part of the story, but its machine-readable
artifact was weaker than its human-readable explanation.

## Cause 3: Router/Policy Did Not Lower Enough Even When It Had a Strong Match

This appeared mainly in day 1 metadata access:

| Flow | ML prob | Match | Effective threshold | Result |
|---|---:|---|---:|---|
| `xgb-d01-attack-metadata-service-access-149` | 0.071840 | `threat_source` | 0.200000 | auto-dismiss |
| `xgb-d01-attack-metadata-service-access-158` | 0.029637 | `threat_source` | 0.200000 | auto-dismiss |

The watchlist item had `routing_policy.review_threshold: 0.05`, but the router
kept the effective threshold at 0.20. The likely reason is the policy safety
guard: `max_threshold_drop: 0.1` does not allow dropping from 0.20 to 0.05.

This is a useful safety guard, but it means metadata access needs either:

- a metadata-specific allowed floor/drop policy; or
- a source-backed item with a valid `max_threshold_drop` that actually permits
  the intended review threshold.

## Cause 4: Tier 1 Failed After a Good Route

One malicious flow reached Tier 1:

| Flow | Route | ML prob | Result |
|---|---|---:|---|
| `xgb-d01-attack-vpn-password-spray-042` | `tier1_llm` | 0.477110 | `uncertain` due to JSON parse failure |

This is not the main recall bottleneck, but it is avoidable. A one-shot JSON
repair/retry path would likely recover this kind of failure without lowering
routing thresholds or increasing false positives.

## What This Means for the Next Patch

Do not globally lower `threshold_low` or `priority_1_llm_threshold`.

The next patch should improve Tier 2-to-router contracts:

1. Add first-class egress triggers:
   - sensitive source asset -> unknown external HTTPS;
   - affected API host -> external HTTPS after CVE exposure;
   - backup NAS -> external HTTPS.

2. Add DNS tunnel trigger support:
   - internal/workstation source CIDR;
   - destination port 53;
   - destination IP not in approved internal DNS;
   - repeated same-source DNS behavior.

3. Add metadata special handling:
   - `169.254.169.254:80`;
   - internal source CIDR;
   - lower allowed dynamic review floor or corrected `max_threshold_drop`.

4. Require Tier 2 to express prose claims as structured hints:
   - if the reason says "known scanner", require `src_ip` or known-bad-source hint;
   - if the reason says "egress", require source asset + external destination/port hints.

5. Add Tier 1 JSON repair/retry:
   - only for parse failure;
   - no second opinion on valid verdicts.

Expected recall upside is concentrated in:

- 10 DNS tunnel misses;
- 6 backup exfil misses;
- 8 metadata misses;
- 2 Tomcat app-host egress misses;
- 2 workstation-domain SMB misses.

These are the misses that routing currently prevents Tier 1 from seeing.
