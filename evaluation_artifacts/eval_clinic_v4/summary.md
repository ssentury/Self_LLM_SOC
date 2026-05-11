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
- Routes: {'auto_dismiss': 278, 'tier1_llm': 11, 'auto_alert': 11}
- Verdicts: {'benign': 278, 'alert': 22}
- Fallbacks: {}
- Final alert recall: 0.667
- Final alert precision: 0.909
- Context attack alerts: 0/0
- Review recall: 0.667
- FP by watchlist match strength: {'asset_service': 2}
- FP adjusted by watchlist: 0
- Watchlist linter warnings: 3
- ML-only high-threshold recall: 0.300
- Tier 2 Gemini tokens: {'prompt': 19168, 'completion': 10686, 'total': 29854, 'estimated_cost_usd': 0.041642}
- Tier 1 Ollama tokens: {'calls': 11, 'prompt': 19489, 'completion': 4120, 'total': 23609, 'api_cost_usd': 0.0}
