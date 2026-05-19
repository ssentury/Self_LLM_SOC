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
- Routes: {'auto_dismiss': 270, 'auto_alert': 15, 'tier1_llm': 15}
- Verdicts: {'benign': 270, 'alert': 26, 'uncertain': 4}
- Fallbacks: {}
- Final alert recall: 0.867
- Final alert precision: 1.000
- Context attack alerts: 11/15
- Review recall: 1.000
- FP by watchlist match strength: {}
- FP adjusted by watchlist: 0
- Dynamic threshold applied: 0
- Dynamic threshold FP: 0
- Dynamic threshold FN recovered: 0
- Watchlist linter warnings: 2
- ML-only high-threshold recall: 0.500
- Tier 2 Gemini tokens: {'prompt': 20564, 'completion': 12257, 'total': 32821, 'estimated_cost_usd': 0.047053}
- Tier 1 Ollama tokens: {'calls': 15, 'prompt': 25519, 'completion': 6757, 'total': 32276, 'api_cost_usd': 0.0}
