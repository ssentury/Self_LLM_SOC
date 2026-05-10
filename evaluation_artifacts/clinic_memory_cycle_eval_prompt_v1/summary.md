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
- Routes: {'auto_dismiss': 244, 'tier1_llm': 41, 'auto_alert': 15}
- Verdicts: {'benign': 246, 'alert': 49, 'uncertain': 5}
- Fallbacks: {}
- Final alert recall: 0.767
- Final alert precision: 0.469
- Review recall: 0.933
- ML-only high-threshold recall: 0.500
- Tier 2 Gemini tokens: {'prompt': 19401, 'completion': 8313, 'total': 27714, 'estimated_cost_usd': 0.0346395}
- Tier 1 Ollama tokens: {'calls': 41, 'prompt': 34884, 'completion': 13776, 'total': 48660, 'api_cost_usd': 0.0}
