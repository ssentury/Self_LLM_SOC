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
- Verdicts: {'benign': 269, 'alert': 30, 'uncertain': 1}
- Fallbacks: {}
- Final alert recall: 0.967
- Final alert precision: 0.967
- Context attack alerts: 14/15
- Review recall: 1.000
- FP by watchlist match strength: {'threat_source': 1}
- FP adjusted by watchlist: 1
- Watchlist linter warnings: 3
- ML-only high-threshold recall: 0.500
- Tier 2 Gemini tokens: {'prompt': 19733, 'completion': 11805, 'total': 31538, 'estimated_cost_usd': 0.0452815}
- Tier 1 Ollama tokens: {'calls': 16, 'prompt': 25775, 'completion': 5992, 'total': 31767, 'api_cost_usd': 0.0}
