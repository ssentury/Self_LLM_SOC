# Dynamic CVE Scenario Design

## Purpose

This document defines the next evaluation scenario after the current clinic full
test. The goal is not only to improve pipeline metrics, but to make the
scenario itself credible enough to defend in the presentation.

The scenario keeps the presentation-first architecture:

- Tier 2 reads organization/security sources and previous feedback.
- Tier 2 produces Watchlist & Contexts, Attack Surface Memory, and a readable
  summary.
- Tier 1 receives only realtime flow evidence, ML/SHAP evidence, recent
  activity, and Tier 2-curated artifacts.
- Tier 1 must not receive raw assets, CVE feed, threat feed, or policy dumps.

Working scenario name:

```text
regional_care_dynamic_cve_5day
```

## Non-Negotiable Data Generation Rules

These rules come from the presentation scenario-generation strategy and must be
treated as part of the scenario contract.

### ML Feature Preservation

- The XGBoost-backed dataset must use the source-compatible NF-CICIDS2018-v3
  feature contract.
- The generated CSV must not contain `mock_prob`.
- Model features should be copied from real source rows.
- Scenario projection may replace only topology and scheduling fields such as
  `flow_id`, IP addresses, selected service ports, and timestamps.
- `PROTOCOL` should be preserved whenever possible. If a protocol override is
  unavoidable, it must be treated as a projection exception and justified in
  the manifest.
- Every changed port or protocol projection must be recorded in a manifest with:
  source row index, source label, source attack, source port, output port, and
  scenario reason.
- If a desired scenario cannot be represented by a defensible source attack
  family, do not invent the feature vector. Either drop the scenario or mark it
  as a future-data gap.

### Benign Data

- Benign flows should come from source-order contiguous benign windows in
  NF-CICIDS2018-v3.
- The generator may choose windows by destination service class, but should not
  cherry-pick isolated benign rows that merely make the metrics convenient.
- Benign profiles must include routine business noise, not only important
  server traffic.
- Normal traffic to CVE-affected assets must remain present after the CVE feed
  changes. Otherwise the test cannot measure over-alerting.

### Attack Data

- Attack flows must preserve real attack-label feature characteristics from
  NF-CICIDS2018-v3.
- Attack labels should be mapped to scenario assets by service semantics:
  SQL injection to DB/API paths, SSH brute force to admin/SSH paths, web attack
  labels to web/API entry points, DDoS to public web/API assets, and
  Infilteration to post-compromise, metadata, DNS tunnel, and exfiltration
  paths.
- The scenario may override IP, timestamp, and selected service ports to match
  the organization topology, but the manifest must make those overrides
  auditable.
- Attack timing should not always reuse the exact same slot pattern from the
  clinic scenario.

## Scale

Target dataset:

```text
5 days
200 flows per day
1000 flows total
180 benign + 20 malicious per day
900 benign + 100 malicious total
Asia/Seoul timestamps
```

This keeps the attack ratio at 10%, matching the current clinic scenario while
doubling daily volume. It is still synthetic and evaluation-friendly, but it is
less toy-like than the current 100-flow day.

## Organization Story

The organization is a regional outpatient care network. It runs a patient portal,
appointment services, lab-result access, EHR integrations, image/archive access,
VPN, backups, and a small internal infrastructure stack. It is still a small
organization from a SOC staffing perspective, but the asset set is broader than
the original clinic scenario.

The network should include common, lower-importance workstation traffic so the
pipeline cannot overfit to a tiny set of named servers.

## Asset Model

Suggested zones and representative assets:

```text
Internet
  |
  v
DMZ public
  203.0.113.10 patient-portal-web          80/443
  203.0.113.20 vpn-gateway                 443
  203.0.113.30 appointment-api             443/8443
  203.0.113.40 partner-sftp-gateway        22

Internal app
  10.60.20.15 ehr-api                      443/8443
  10.60.20.30 lab-results-api              8443/8080
  10.60.20.35 notification-service         443

Internal DB
  10.60.30.20 ehr-postgres                 5432
  10.60.30.25 billing-mssql                1433
  10.60.30.30 lab-mysql                    3306
  10.60.30.40 reporting-warehouse          5432

Clinical systems
  10.60.35.10 pacs-image-archive           443/104
  10.60.35.20 dicom-router                 104

Backup and storage
  10.60.40.12 backup-nas                   445/22
  10.60.40.20 object-storage-gateway       443

Admin and management
  10.60.50.8 admin-jumpbox                 22/3389
  10.60.50.15 patch-management             443
  10.60.50.20 edr-management               443
  10.60.50.30 firewall-manager             541/443

Infrastructure
  10.60.60.5 internal-dns                  53
  10.60.60.10 domain-controller            88/389/445
  10.60.60.15 ntp                          123
  10.60.60.20 monitoring                   443/9100
  10.60.60.30 siem-collector               514/6514

Workstations
  10.60.100.20-10.60.100.39 reception PCs
  10.60.100.40-10.60.100.59 nurse station PCs
  10.60.100.60-10.60.100.79 doctor laptops
  10.60.100.80-10.60.100.94 billing PCs
  10.60.100.95-10.60.100.110 shared/kiosk PCs
```

The workstation pool is intentionally larger than the set of important servers.
Most workstation flows are normal DNS, SaaS, EHR, update, time sync, and file
share activity.

## Five-Day Change Schedule

The scenario should not make too many changes on day 3. The changes are staged
so Tier 2 artifact evolution can be observed without turning the organization
into a different company overnight.

### Day 1 - Baseline

- All core assets exist.
- Baseline CVE feed contains the existing clinic-style advisories:
  public portal PHP-CGI risk, VPN edge risk, and OpenSSH risk.
- Benign traffic establishes normal activity for portals, VPN, EHR, lab API,
  DNS, SaaS, backup, admin access, PACS, and workstations.
- Attacks include a balanced mix of public web probes, VPN pressure, direct DB
  probing, workstation-to-backup tampering, DNS tunnel, metadata access, and
  backup exfiltration.

### Day 2 - Stable Operations

- No source feed change.
- Similar business volume, but different source rows, workstations, and remote
  IPs from day 1.
- This day measures whether Tier 2 memory/feedback changes are reasonable even
  when the raw source inputs are stable.

### Day 3 - CVE Addition 1

Add one CVE advisory:

```text
CVE-2025-24813
Apache Tomcat path equivalence / partial PUT issue
Scenario relevance: lab-results-api and appointment-api run Tomcat-backed
services on 8443/8080.
```

Expected Tier 2 behavior:

- Add or raise watchlist items for `lab-results-api` and `appointment-api`.
- Use observable NetFlow-level hints only:
  destination asset, destination port 8080/8443, scanner/threat source, repeated
  attempts, unusual source zone, and follow-up egress from the app host.
- Do not pretend Tier 1 can see HTTP URI or partial PUT content from NetFlow
  alone.
- Keep normal staff access to lab-results API from clinic workstations as a
  likely-benign condition.

Flow effect:

- Add Tomcat-oriented web exploit probes and post-exploit follow-up flows.
- Keep ordinary lab-results API usage so the CVE does not become an automatic
  alert on any flow to the asset.

### Day 4 - Operational Drift, No New CVE

Small, realistic non-CVE changes:

- Add a small set of shared/kiosk PCs under `10.60.100.95-10.60.100.110`.
- Mark an old reporting DB endpoint as retired or restricted.
- Add one threat-feed IOC tied to the day-3 Tomcat scanning cluster.

Expected Tier 2 behavior:

- Preserve the day-3 CVE focus if flow feedback supports it.
- Add nuance rather than a large new watchlist set.
- Treat retired-asset traffic as suspicious context, but not automatically
  malicious without behavior evidence.

Flow effect:

- Include benign first-day activity from newly added kiosks.
- Include a few low-volume scans toward the retired DB endpoint.
- Include follow-up lateral movement from a potentially compromised app host,
  but keep the number small enough that day 4 is not another major event.

### Day 5 - CVE Addition 2

Add one CVE advisory:

```text
CVE-2024-47575
Fortinet FortiManager missing authentication / fgfmd daemon issue
Scenario relevance: firewall-manager is an internal management-plane asset with
TCP/541 and HTTPS management exposure.
```

Expected Tier 2 behavior:

- Add high-priority watchlist coverage for `firewall-manager`.
- Strong machine-readable hints should include destination IP, destination port
  541, source zone not in approved management ranges, and suspicious egress
  from the manager to unknown external IPs.
- Keep trusted admin-jumpbox-to-firewall-manager maintenance traffic as
  likely-benign when it happens from the right source and window.

Flow effect:

- Add management-plane attack attempts to TCP/541.
- Add post-compromise egress from `firewall-manager` to unknown external HTTPS.
- Keep normal admin/monitoring traffic to the manager so false positives are
  measurable.

## CVE Source Notes

The two staged CVE additions are chosen because they map well to realistic
network assets and observable NetFlow behavior.

- CVE-2025-24813 is documented by NVD as an Apache Tomcat issue that can lead to
  remote code execution or information disclosure under specific configuration
  conditions, and CISA lists it in KEV.
- CVE-2024-47575 is documented by NVD as a FortiManager missing-authentication
  vulnerability allowing arbitrary command/code execution via crafted requests,
  and CISA lists it in KEV.
- Source URLs:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-24813
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-24813
  - https://nvd.nist.gov/vuln/detail/CVE-2024-47575
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-47575

The scenario should describe these as source-feed updates for the simulated SOC,
not as claims about real-world disclosure order.

## Daily Flow Profile

Each day should contain 180 benign flows. Suggested benign classes:

| Class | Daily count | Notes |
|---|---:|---|
| patient portal HTTPS/HTTP | 22 | external patient traffic, mostly benign |
| appointment API | 8 | public API calls, 443/8443 |
| employee VPN | 8 | remote staff access |
| staff SaaS / cloud apps | 12 | common workstation internet traffic |
| workstation DNS | 24 | high-volume normal UDP/53 |
| workstation NTP | 8 | UDP/123 |
| EHR web/API access | 14 | workstation to EHR/API |
| lab-results API access | 8 | important negative control after day 3 |
| app-to-DB queries | 10 | approved app server to DB paths |
| backup window SMB | 8 | only from approved backup/admin sources |
| monitoring/scrape | 8 | monitoring to servers |
| admin SSH/RDP | 8 | approved admin sources only |
| PACS/DICOM access | 8 | clinical image workflows |
| partner SFTP | 4 | low-volume partner data exchange |
| EDR/patch/cloud update | 10 | normal management/update noise |
| workstation web browsing | 14 | ordinary non-critical business traffic |
| internal file share | 6 | normal SMB from workstations |

Each day should contain 20 malicious flows. Keep a mix of obvious and
context-dependent attacks:

```text
8 obvious/high-ML candidates:
  DDoS/web attack, SQL injection, SSH brute force, external DB probe

12 context-dependent candidates:
  CVE-related web probing, metadata access, DNS tunnel, backup tampering,
  lateral movement, management-plane probe, post-compromise egress
```

The exact attack mix should change by day:

| Day | Attack emphasis |
|---|---|
| Day 1 | baseline web/VPN/DB/backup/DNS/metadata coverage |
| Day 2 | same families, different source rows and timing |
| Day 3 | add Tomcat CVE probing and app-host follow-up |
| Day 4 | fewer new attacks, more follow-up and retired-asset probing |
| Day 5 | add FortiManager TCP/541 probing and management-plane egress |

## Attack Family Mapping

The generator should first look for source rows that match the desired source
label and service port. If no exact service-port match exists, it may use a
nearby attack family and record the projection override.

| Scenario behavior | Preferred source label | Output mapping |
|---|---|---|
| public web/API exploit probe | `Brute_Force_-Web` or `SQL_Injection` | portal/API 80/443/8443/8080 |
| Tomcat CVE probe | `Brute_Force_-Web` or `SQL_Injection` | lab/API 8080/8443 |
| direct DB probe | `SQL_Injection` | DB 5432/3306/1433 |
| admin SSH brute force | `SSH-Bruteforce` | jumpbox/backup SSH 22 |
| public DDoS burst | `DDOS_attack-HOIC` | public portal/API 80/443 |
| DNS tunnel | `Infilteration` | workstation to external DNS 53 |
| metadata access | `Infilteration` | internal host to 169.254.169.254:80 |
| backup exfiltration | `Infilteration` | backup/storage to external HTTPS 443 |
| FortiManager management probe | `Infilteration` or web attack family | firewall-manager 541 |
| post-compromise egress | `Infilteration` | app/manager host to unknown external 443 |

## Expected Tier 2 Artifact Evolution

This scenario should make Tier 2 changes visible and testable.

Day 1:

- Watchlist focuses on existing portal, VPN, DB, backup, metadata, and DNS
  tunnel risks.

Day 2:

- Watchlist should mostly stabilize.
- Memory should mention repeated attack families and any false positive or miss
  patterns from day 1.

Day 3:

- New or elevated watchlist items for Tomcat-backed lab/API assets.
- Brief should explain that CVE-2025-24813 is newly relevant, but should also
  preserve over-alerting guardrails for normal lab-result access.

Day 4:

- Memory should keep Tomcat risk if day-3 evidence supports it.
- Source-status and inventory drift should be preserved.
- Retired endpoint scanning should appear as context, not a broad global alert.

Day 5:

- New high-priority management-plane watchlist item for `firewall-manager`.
- Brief should explain why TCP/541 to FortiManager is materially different from
  normal admin HTTPS.
- Memory should summarize both CVE additions and their observed flow impact.

## Evaluation Slices

Do not report only aggregate precision/recall. The scenario should produce
separate slices:

- Overall precision, recall, F1, FP, FN.
- Day 1-2 pre-change metrics.
- Day 3-5 post-change metrics.
- CVE-2025-24813 attack recall and benign false-positive rate.
- CVE-2024-47575 attack recall and benign false-positive rate.
- Low-ML contextual attack recall.
- Infilteration-family recall.
- Tier 1 call count per day.
- Watchlist-hit count per day.
- Watchlist-adjusted routing count per day.
- False positives caused by watchlist threshold lowering.
- Tier 2 prompt/completion token cost per day.

## Reliability Checks

The generator and tests should verify:

- Exactly 1000 rows.
- Exactly 5 KST dates, 200 rows per date.
- Exactly 900 benign and 100 malicious rows unless intentionally changed.
- No `mock_prob` column.
- Every row satisfies the binary XGBoost feature contract.
- Source row indices are recorded in the manifest.
- Benign rows come from contiguous source-order benign windows.
- Attack rows come from real attack-label rows.
- All port/protocol projection exceptions are listed in the manifest.
- Day 3 CVE source update contains exactly one new CVE.
- Day 5 CVE source update contains exactly one additional new CVE.
- Day 4 contains no new CVE.
- Benign traffic to CVE-affected assets exists after the CVE additions.
- Trusted admin traffic to `firewall-manager` exists on day 5.
- No Tier 1 prompt path includes raw asset, policy, CVE, or threat-feed YAML.

## Overfitting Controls

- Do not reuse the current clinic IP ranges.
- Use more workstation IPs than important server IPs.
- Vary attack slots by day instead of using the same ten positions every day.
- Use multiple source candidates per attack family.
- Include benign flows that superficially match risky assets and ports.
- Include low-value workstation and file-share activity that should not drive
  watchlist generation.
- Keep CVE-specific signals tied to affected assets and source evidence, not to
  global "CVE means alert" behavior.
- Keep a manifest that makes every scenario projection auditable.

## Proposed Implementation Artifacts

The current YAML-backed provider contract can be preserved by materializing
merged daily source snapshots:

```text
config/scenarios/regional_care_dynamic_cve/
  base/
    organization.yaml
    assets.yaml
    policy.yaml
    cve_feed.yaml
    threat_feed.yaml
  overlays/
    day03_cve_tomcat.yaml
    day04_inventory_and_ioc.yaml
    day05_cve_fortimanager.yaml
  generated/
    day01/
    day02/
    day03/
    day04/
    day05/

data/sample/regional_care_dynamic_cve_flows_xgb.csv
data/sample/regional_care_dynamic_cve_flows_xgb_manifest.json
config/settings.regional_care_dynamic_cve_xgb.yaml
scripts/generate_regional_care_dynamic_cve_xgb_flows.py
scripts/evaluate_dynamic_cve_memory_cycle.py
tests/integration/test_dynamic_cve_scenario_inputs.py
```

The implementation does not need a new provider type. A small materialization
step can merge `base/` plus overlays into day-specific YAML directories that
the existing provider can read.
