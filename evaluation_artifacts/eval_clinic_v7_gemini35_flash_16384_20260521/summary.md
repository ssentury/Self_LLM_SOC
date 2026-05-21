# Clinic Memory Cycle Evaluation

## Topology

```text
Internet patients/staff/scanners
        |
        v
  203.0.113.10 patient portal (HTTP/HTTPS)     203.0.113.20 VPN gateway
        |                                              |
        +---------------- DMZ public -------------------+
                               |
                               v
  10.42.20.15 EHR API ---> 10.42.30.25 billing Postgres
        |                         ^
        |                         |
  clinic workstations        admin/jumpbox 10.42.50.8
  10.42.100.0/24                 |
        |                         v
        +-----> 10.42.40.12 backup NAS (SMB/SSH)
        |
        +-----> 10.42.60.5 internal DNS
        |
        +-----> 169.254.169.254 cloud metadata (should not be queried)
```

## Aggregate Metrics

- Flows: 300
- Routes: {'auto_dismiss': 269, 'auto_alert': 15, 'tier1_llm': 16}
- Verdicts: {'benign': 270, 'alert': 25, 'uncertain': 5}
- Fallbacks: {'llm': 1}
- Final alert recall: 0.800
- Final alert precision: 0.960
- Context attack alerts: 9/15
- Review recall: 0.967
- FP by watchlist match strength: {'threat_source': 1}
- FP adjusted by watchlist: 1
- Dynamic threshold applied: 0
- Dynamic threshold FP: 0
- Dynamic threshold FN recovered: 0
- Watchlist linter warnings: 5
- ML-only high-threshold recall: 0.500
- Tier 2 Gemini tokens: {'prompt': 20594, 'completion': 23610, 'total': 44204, 'estimated_cost_usd': 0.243381}
- Tier 1 Ollama tokens: {'calls': 16, 'prompt': 33443, 'completion': 6151, 'total': 39594, 'api_cost_usd': 0.0}
