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
- Routes: {'auto_dismiss': 926, 'tier1_llm': 44, 'auto_alert': 30}
- Verdicts: {'benign': 926, 'alert': 72, 'uncertain': 2}
- Final alert recall: 0.700
- Final alert precision: 0.972
- Review recall: 0.710
- Dynamic threshold applied: 0
- Dynamic threshold FP: 0
- Dynamic threshold FN recovered: 0
- Day 1-2 alert recall: 0.625
- Day 3-5 alert recall: 0.750
- CVE-2025-24813 attack recall: 0.769
- CVE-2025-24813 benign control FPR: 0.000
- CVE-2024-47575 attack recall: 1.000
- CVE-2024-47575 benign control FPR: 0.000
- Low-ML contextual attack review recall: 0.094
- Infilteration alert recall: 0.300
- Watchlist linter warnings: 2
- Tier 2 Gemini tokens: {'prompt': 54189, 'completion': 19318, 'total': 73507, 'estimated_cost_usd': 0.0850485}
- Tier 1 Ollama tokens: {'calls': 44, 'prompt': 80706, 'completion': 16363, 'total': 97069, 'api_cost_usd': 0.0}
