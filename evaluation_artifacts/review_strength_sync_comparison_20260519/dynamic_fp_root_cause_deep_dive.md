# Dynamic CVE FP Deep Dive

False positive alerts: 153

## Concentration

- By flow family: `{'workstation-dns': 116, 'workstation-ntp': 35, 'workstation-web-browsing': 2}`
- By watchlist item: `{'P1-SOURCE-PATTERN-DNS-TUNNEL-BURST': 153}`
- By match strength: `{'review_candidate': 151, 'asset_only': 2}`
- By route: `{'tier1_llm': 151, 'auto_alert': 2}`
- Dynamic threshold FP count: 120
- Non-dynamic FP count: 33

## ML Probability

- Bands: `{'0.04-0.08': 69, '0.08-0.12': 47, '0.20-0.30': 31, '>=0.95': 2, '0.12-0.20': 4}`
- Summary: `{'min': 0.0452466756105423, 'p25': 0.06871240586042404, 'mean': 0.12507985230364832, 'p50': 0.08567103743553162, 'p75': 0.11367304623126984, 'max': 0.9954527616500854}`
- Effective thresholds: `{'0.04': 151, '0.2': 2}`
- Top matched conditions: `{'target_assets.cidr 10.60.100.0/24 contains flow.src_ip': 153, "src_ip in ['10.60.100.0/24', '10.60.100.20/30', '10.60.100.40/29', '10.60.100.60/29', '10.60.100.80/29', '10.60.100.95/28']": 153, 'protocol == 17': 151, 'dst_port == 53': 116, 'target_assets.cidr 10.60.100.95/28 contains flow.src_ip': 40, 'target_assets.cidr 10.60.100.80/29 contains flow.src_ip': 16, 'target_assets.cidr 10.60.100.40/29 contains flow.src_ip': 15, 'target_assets.cidr 10.60.100.60/29 contains flow.src_ip': 14, 'target_assets.cidr 10.60.100.20/30 contains flow.src_ip': 8, "dst_ip not in ['10.60.100.0/24', '10.60.100.20/30', '10.60.100.40/29', '10.60.100.60/29', '10.60.100.80/29', '10.60.100.95/28', '10.60.20.0/24', '10.60.30.0/24', '10.60.35.0/24', '10.60.40.0/24', '10.60.50.0/24', '10.60.60.0/24', '203.0.113.0/24']": 2}`

## Network Shape

- Top source IPs: `{'10.60.100.94': 9, '10.60.100.82': 7, '10.60.100.84': 6, '10.60.100.92': 6, '10.60.100.90': 6, '10.60.100.34': 4, '10.60.100.27': 4, '10.60.100.21': 3, '10.60.100.46': 3, '10.60.100.29': 3, '10.60.100.58': 3, '10.60.100.86': 3, '10.60.100.22': 3, '10.60.100.59': 3, '10.60.100.39': 3, '10.60.100.28': 3, '10.60.100.88': 3, '10.60.100.47': 3, '10.60.100.32': 3, '10.60.100.36': 3}`
- Top destination IPs: `{'10.60.60.5': 116, '10.60.60.15': 35, '198.51.100.152': 2}`

## Root Cause

The FP set is mostly normal workstation infrastructure traffic, not just
actual DNS-tunnel-like traffic: 116 workstation DNS flows, 35 workstation NTP
flows, and 2 workstation web browsing flows.

The decisive bug is the interaction between broad source-scoped watchlist
items and current detection-hint semantics. The watchlist item contains
`target_assets` for broad workstation CIDRs and also includes a `src_ip
in_cidr` detection hint over the same workstation CIDRs. The matcher does
not require all detection hints to match as an AND group. It collects any
matching hints, then derives the best match strength from the matched subset.
As a result, a normal workstation flow can match the DNS-tunnel item through
the source CIDR hint alone, even when `dst_port == 53`, UDP, external
destination, or repeated-DNS behavior did not all match.

Because that item carries `routing_policy.review_threshold: 0.04`, many
benign workstation flows with ML probabilities around 0.05-0.10 are routed
to Tier 1. Tier 1 then receives a Tier 2-curated DNS-tunnel context and often
emits `alert`. This is not random LLM noise; it is a deterministic
routing/context failure caused by broad source scope, OR-style hint matching,
and the newly trusted `review_candidate` path.

## Representative Samples

- xgb-d01-benign-workstation-dns-001: ml=0.063, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-002: ml=0.058, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-004: ml=0.062, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-006: ml=0.052, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-009: ml=0.106, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-010: ml=0.083, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-012: ml=0.069, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-014: ml=0.066, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-016: ml=0.067, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
- xgb-d01-benign-workstation-dns-018: ml=0.077, threshold=0.04, dst=10.60.60.5:53/17, item=P1-SOURCE-PATTERN-DNS-TUNNEL-BURST, strength=review_candidate
