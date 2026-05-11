# Clinic Memory Cycle 평가 결과 해석 - Trigger Recall V1

## 실행 정체성

- 실행 시점: 2026-05-10
- 시나리오: `clinic_telehealth_3day_memory_cycle`
- 출력 폴더: `evaluation_artifacts/clinic_memory_cycle_eval_trigger_recall_v1`
- Tier 2 provider: Gemini, `gemini-3-flash-preview`
- Tier 1 provider: 로컬 Ollama, `gemma4:e4b`
- 전체 flow: 300개
- 라벨 분포: malicious 30개, benign 270개
- source boundary: Tier 2가 조직/security source snapshot을 읽고, Tier 1은 realtime flow/ML/activity evidence와 Tier 2가 큐레이션한 watchlist/brief artifact만 사용했다.

## 핵심 결과

| 항목 | 이전 Guardrails V3 | Trigger Recall V1 |
|---|---:|---:|
| 최종 alert TP | 17 | 29 |
| 최종 alert FP | 0 | 1 |
| 최종 alert FN | 13 | 1 |
| 최종 alert recall | 0.567 | 0.967 |
| 최종 alert precision | 1.000 | 0.967 |
| review recall | 0.700 | 1.000 |
| Tier 1 호출 | 15 | 16 |
| watchlist hit | 88 | 158 |
| watchlist로 조정됨 | 2 | 13 |
| watchlist linter warning | 0 | 3 |

가장 중요한 목표였던 recall은 개선됐다. 문맥 의존 악성 alert 수가 이전
2/15 baseline에서 14/15로 증가했고, 문맥 의존 악성 flow 15개 모두가 최소
review 대상까지 올라왔다.

## 오탐 분석

benign flow 1개가 최종 alert가 됐다.

```text
flow_id: d02-benign-employee-vpn-014
src_ip: 192.0.2.44
dst: 203.0.113.20:443
ml_prob: 0.27
adjusted_by_watchlist: true
watchlist_matched: P1-20260510-001
match_strength: threat_source
```

이는 recall을 높이면서 생긴 예상 가능한 tradeoff다. 강화된 Tier 2 VPN trigger가
외부 VPN traffic을 더 적극적으로 잡도록 바뀌면서, 정상 직원 VPN source가
의심스러운 외부 pressure와 비슷하게 보일 때 과잉 alert가 발생할 수 있다.
FP 수는 낮지만, 이 trigger는 known-bad source 조건을 더 정밀하게 하거나 정상
직원 VPN allow guidance를 추가하는 방향으로 조정할 필요가 있다.

## 린터 경고

P1 item 3개는 validation/enrichment 이후에도 강한 machine-readable trigger가
부족해서 context-only로 표시됐다.

```text
priority_1:P1-CLINIC-METADATA-005
priority_1:P1-20260510-004
priority_1:P1-CLINIC-IMDS-005
```

이 warning은 치명적인 실패라기보다 유용한 안전장치다. 약한 P1 내용은 context로
보존하되, strong trigger가 아니면 routing threshold를 낮추는 근거로 쓰지 않는다.

## 비용과 토큰

```text
Tier 2 Gemini tokens: prompt 19,733 / completion 11,805 / total 31,538
Estimated Gemini cost: $0.0452815
Tier 1 Ollama tokens: prompt 25,775 / completion 5,992 / total 31,767
Tier 1 API cost: $0.00
```

## 결론

LLM plus validator 접근은 Tier 1에 raw source file을 넘기지 않으면서도 의도한
recall 개선을 달성했다. 남은 문제는 aggressive strong trigger 때문에 생긴 VPN
false positive 1건이다. 다음 튜닝 단계에서는 repeated-source와 known-bad-source
recall은 유지하면서 VPN trigger matching을 더 좁히는 것이 좋다.
