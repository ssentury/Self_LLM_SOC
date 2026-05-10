# Clinic Memory Cycle 평가 결과 해석 - Prompt V1

이 폴더는 일반 실행 캐시가 아니라, 명시적으로 보존하는 평가 산출물이다.
`output/` 아래의 일회성 결과를 복사해 둔 것이며, 느리고 장비 의존적인
Gemini/Ollama 평가를 매번 다시 돌리지 않고도 결과를 비교하기 위한 기준점이다.

## 실행 정체성

- 시나리오: `clinic_telehealth_3day_memory_cycle`
- 프롬프트/구조 버전: prompt v1 clinic 평가
- 입력 flow: `data/sample/clinic_telehealth_flows.csv`
- 기간: 2026-05-02부터 2026-05-04까지 KST 기준 3일
- Tier 2 provider: Gemini, `gemini-3-flash-preview`
- Tier 1 provider: 로컬 Ollama
- 전체 flow: 300개
- 라벨 분포: benign 270개, malicious 30개
- fallback: 없음

## 폴더 내용

- `summary.md`: 사람이 빠르게 읽는 집계 요약.
- `summary_metrics.json`: 전체/일자별 metric, token, latency, route/verdict 집계.
- `soc_events.sqlite`: 3일 전체 실행 결과가 들어 있는 SQLite event store.
- `day01_2026-05-02/`, `day02_2026-05-03/`, `day03_2026-05-04/`:
  일자별 flow, 실행 설정, Tier 2 watchlist/brief/memory, metric, HTML report.

## 핵심 결과

| 항목 | 결과 |
|---|---:|
| 전체 flow | 300 |
| Tier 1 호출 | 41 |
| auto dismiss | 244 |
| auto alert | 15 |
| 최종 alert | 49 |
| uncertain | 5 |
| TP / FP / TN / FN | 23 / 26 / 244 / 7 |
| alert precision | 0.469 |
| alert recall | 0.767 |
| alert F1 | 0.582 |
| review recall | 0.933 |
| Tier 2 Gemini tokens | 27,714 |
| Tier 1 Ollama tokens | 48,660 |
| Gemini 추정 비용 | $0.03464 |

## 결과 해석

Prompt V1은 recall 중심으로는 꽤 공격적으로 동작했다. 최종 alert 기준
30개 악성 중 23개를 alert로 잡았고, `uncertain`까지 review 대상으로 보면
28개를 놓치지 않았다. 즉 이 버전은 “수상한 것은 많이 올려서 사람이 보게
한다”는 방향에는 맞는다.

하지만 precision이 낮다. false positive가 26개 나왔고, alert precision은
0.469에 그쳤다. 오탐의 핵심 원인은 watchlist 의미가 너무 강하게 해석된
것이다. Tier 2가 만든 priority_1 watchlist가 “중요 자산 또는 중요 서비스에
닿는 flow”를 너무 쉽게 Tier 1 검토 대상으로 올렸고, Tier 1도 watchlist
match 자체를 공격 근거처럼 다루는 경향이 있었다.

대표적인 오탐 유형은 정상 직원 VPN 접속, 정상 patient portal HTTP/HTTPS,
monitoring portal 접근이다. 이들은 실제 조직에서는 흔히 발생할 수 있는
정상 업무 트래픽인데, V1에서는 VPN gateway 또는 patient portal이
priority_1 watchlist에 포함되어 있다는 이유만으로 과도하게 alert가 발생했다.

따라서 V1 결과는 두 가지를 보여준다.

첫째, Batch Loop와 Real Time Loop의 기본 연결은 작동했다. Tier 2가 조직,
자산, 정책, CVE, threat feed를 읽고 watchlist/brief/memory를 만들었으며,
Tier 1은 그 산출물과 flow/ML/activity evidence를 함께 사용했다. SQLite
history도 day2/day3 Tier 2 입력으로 들어갔다.

둘째, watchlist의 의미 정의가 부족했다. watchlist는 “주의 깊게 볼 범위”이지
“공격 증거”가 아닌데, V1에서는 그 경계가 약했다. 이 문제 때문에 이후
guardrail 작업에서는 watchlist item을 `target_assets`라는 scope와
`detection_hints`라는 trigger contract로 나누고, asset/service match만으로는
alert 또는 threshold lowering이 되지 않도록 바꿨다.

## 발표에서 사용할 수 있는 메시지

이 결과는 실패가 아니라 엔지니어링 근거로 설명하는 것이 맞다.

- V1은 synthetic clinic 시나리오에서 높은 review recall을 보였지만,
  watchlist-driven false positive가 많았다.
- 이 오탐은 “중요 자산을 보라”는 Tier 2 문맥이 “공격이다”라는 Tier 1
  판단으로 번지는 구조적 문제였다.
- 이후 변경은 이 문제를 줄이기 위해 watchlist를 scope plus trigger 구조로
  재정의했다.

즉 V1은 최종 성능 주장이 아니라, guardrail 개선의 출발점이 되는 기준
실험이다.

## 시나리오 신뢰도와 한계

이 시나리오는 아키텍처와 prompt behavior를 회귀 테스트하기에는 유용하다.
3일 반복 실행, Tier 2 source 입력, SQLite history, Tier 1 routing, HTML
report까지 한 번에 검증하기 때문이다.

다만 실제 SOC 성능 benchmark로 말하면 안 된다.

- flow는 실제 병원 네트워크에서 추출한 것이 아니라 손으로 만든 NetFlow-like
  synthetic row이다.
- `mock_prob`가 스크립트로 정해져 있어 ML 모델의 실제 품질을 검증하지 않는다.
- 공격 비율 10%는 현실적인 운영망보다 높다.
- 매일 같은 10개 공격 template이 반복되어 overfitting 가능성이 있다.
- bytes, packet count, TCP flag, DNS query, HTTP path/status, login failure 같은
  현실적인 증거 필드가 없다.

발표에서는 “현실 성능 입증”이 아니라 “통제된 synthetic clinic scenario로
Batch/Realtime loop와 prompt guardrail을 엔지니어링했다”고 말하는 것이
정확하다.
