# Regional Care Dynamic CVE Evaluation

## Topology

```text
Internet patients/staff/scanners
        |
        v
  203.0.113.10 patient portal       203.0.113.20 VPN gateway
  203.0.113.30 appointment API      203.0.113.40 partner SFTP
        |                                      |
        +------------- DMZ public -------------+
                       |
                       v
  10.60.20.15 EHR API          10.60.20.30 lab-results API
  10.60.30.20 EHR Postgres     10.60.30.25 billing MSSQL
  10.60.30.30 lab MySQL        10.60.40.12 backup NAS
  10.60.50.8 admin jumpbox     10.60.50.30 firewall manager
  10.60.60.5 internal DNS      10.60.100.0/24 workstation pool
```

## Aggregate Metrics

- Flows: 1000
- Routes: {'auto_dismiss': 899, 'tier1_llm': 71, 'auto_alert': 30}
- Verdicts: {'benign': 904, 'alert': 85, 'uncertain': 11}
- Final alert recall: 0.830
- Final alert precision: 0.976
- Review recall: 0.940
- Dynamic threshold applied: 21
- Dynamic threshold FP: 0
- Dynamic threshold FN recovered: 18
- Day 1-2 alert recall: 0.850
- Day 3-5 alert recall: 0.817
- CVE-2025-24813 attack recall: 0.923
- CVE-2025-24813 benign control FPR: 0.000
- CVE-2024-47575 attack recall: 1.000
- CVE-2024-47575 benign control FPR: 0.000
- Low-ML contextual attack review recall: 0.844
- Infilteration alert recall: 0.650
- Watchlist linter warnings: 9
- Tier 2 Gemini tokens: {'prompt': 56757, 'completion': 50194, 'total': 106951, 'estimated_cost_usd': 0.5368815}
- Tier 1 Ollama tokens: {'calls': 71, 'prompt': 201743, 'completion': 148850, 'total': 350593, 'api_cost_usd': 0.0}
