# Clinic Memory Cycle 평가 결과 해석 - Guardrails V3

이 폴더는 일반 실행 캐시가 아니라, 명시적으로 보존하는 평가 산출물이다.
watchlist trigger guardrail 변경 이후 3일치 clinic telehealth full run을
보존한다. Gemini API, 로컬 Ollama 모델, 장비 속도, 실행 시점에 따라 결과
재현 비용이 크기 때문에 `evaluation_artifacts/` 아래에 승격했다.

## 실행 정체성

- 시나리오: `clinic_telehealth_3day_memory_cycle`
- 프롬프트/구조 버전: watchlist trigger guardrails v3
- 입력 flow: `data/sample/clinic_telehealth_flows.csv`
- 기간: 2026-05-02부터 2026-05-04까지 KST 기준 3일
- Tier 2 provider: Gemini, `gemini-3-flash-preview`
- Tier 1 provider: 로컬 Ollama, `gemma4:e4b`
- 전체 flow: 300개
- 라벨 분포: benign 270개, malicious 30개
- 실행 시점: 2026-05-10 KST
- fallback: 없음

## 폴더 내용

- `summary.md`: 사람이 빠르게 읽는 집계 요약.
- `summary_metrics.json`: 전체/일자별 metric, token, latency, route/verdict 집계.
- `soc_events.sqlite`: 3일 전체 실행 결과가 들어 있는 SQLite event store.
- `day01_2026-05-02/`, `day02_2026-05-03/`, `day03_2026-05-04/`:
  일자별 flow, 실행 설정, Tier 2 watchlist/brief/memory, metric, HTML report.

## V1 대비 핵심 결과

| 항목 | Prompt V1 | Guardrails V3 |
|---|---:|---:|
| Tier 1 호출 | 41 | 15 |
| 최종 alert | 49 | 17 |
| False positive | 26 | 0 |
| Alert precision | 0.469 | 1.000 |
| Alert recall | 0.767 | 0.567 |
| Review recall | 0.933 | 0.700 |
| Alert F1 | 0.582 | 0.723 |
| Watchlist threshold 조정 | 31 | 2 |
| Tier 1 tokens | 48,660 | 23,226 |
| Tier 2 Gemini tokens | 27,714 | 26,564 |
| Gemini 추정 비용 | $0.03464 | $0.03471 |

## 결과 해석

Guardrails V3는 의도한 방향으로 동작했다. V1에서 가장 큰 문제였던
watchlist-driven false positive가 26개에서 0개로 줄었다. 정상 직원 VPN 접속,
정상 patient portal HTTP/HTTPS, monitoring portal 접근이 더 이상 단순히
priority_1 watchlist 범위에 들어왔다는 이유만으로 alert가 되지 않는다.

구조적으로는 `watchlist match = 공격 증거`라는 해석을 끊은 것이 핵심이다.
V3에서는 watchlist item을 다음처럼 나누어 본다.

- `target_assets`: Tier 2가 Tier 1에게 주의 깊게 보라고 알려주는 scope.
- `detection_hints`: 실제 threshold lowering 또는 강한 match로 볼 수 있는
  machine-readable trigger.
- `alert_when`: Tier 1이 alert로 올리기 전에 확인해야 하는 추가 행동 증거.
- `likely_benign_when`: 정상 업무 트래픽으로 볼 수 있는 조건.

이 결과 Tier 1 호출은 41건에서 15건으로 줄었고, Tier 1 token도 48,660에서
23,226으로 줄었다. 비용/대기시간 관점에서는 더 현실적인 운영 형태에 가까워졌다.

대신 recall 손실이 있다. 최종 alert 기준 recall은 0.767에서 0.567로 내려갔고,
`uncertain`까지 사람이 볼 대상으로 포함한 review recall도 0.933에서 0.700으로
내려갔다. 특히 context-only 성격의 SSH brute-force, workstation-to-backup SMB,
저신뢰 web/database probe 일부가 benign 또는 uncertain으로 내려갔다.

따라서 V3는 “정밀도 우선 triage” 성격이 강하다. 작은 조직에서 alert fatigue를
줄이는 데는 유리하지만, 약한 문맥 공격까지 넓게 잡아내려면 추가 증거 필드 또는
더 좋은 Tier 2 trigger 생성이 필요하다.

## 중요한 개선 포인트

현재 결과에서 눈에 띄는 문제는 Gemini가 `alert_when`과 `likely_benign_when`을
빈 리스트로 내는 경우가 있다는 점이다. V3 prompt는 이 필드를 요구하지만, 실제
출력은 항상 충분히 채워지지 않았다. 다음 구현에서는 다음 중 하나가 필요하다.

- priority_1 item에서 `alert_when`이 비어 있으면 linter warning을 내기.
- parser 또는 post-processor에서 source의 suspicious pattern을 기반으로
  `alert_when`을 보강하기.
- Tier 2 prompt에서 `alert_when` 최소 1개를 schema-level 요구사항처럼 더 강하게
  명시하기.

이 보강을 하면 FP는 낮게 유지하면서 weak-context 공격 recall을 다시 끌어올릴
여지가 있다.

## 시나리오 특성

현재 clinic flow set은 작고 결정론적인 synthetic case이다.

- 3일, 하루 100개 flow.
- 하루 10개 malicious flow, 전체 공격 비율 10%.
- 매일 같은 10개 공격 pattern이 반복되고, `mock_prob`만 조금씩 달라진다.
- 악성 30개 중 15개는 `mock_prob > 0.95`의 명백한 ML auto-alert 공격이다.
- 나머지 15개는 Tier 1이 문맥을 보고 판단해야 하는 review-band 공격이다.
- benign traffic은 patient portal HTTP/HTTPS, employee VPN, EHR API,
  app-to-database, internal DNS, nightly backup, jumpbox SSH, SaaS,
  cloud update, monitoring traffic을 포함한다.
- Tier 2 source는 작은 telehealth 조직의 portal/VPN/EHR/billing 자산, 정책,
  CVE, threat intel을 모델링한다.

## 신뢰도 평가

이 시나리오는 엔지니어링 회귀 테스트로는 신뢰할 만하다.

- Batch Loop가 조직/security source를 읽고 curated artifact를 만드는지 본다.
- Tier 1이 raw source dump가 아니라 Tier 2 artifact를 소비하는지 본다.
- watchlist scope가 alert 근거로 오해되는지 검출한다.
- 3일 반복을 통해 SQLite history가 day2/day3 Tier 2 입력에 들어가는지 본다.

그러나 실제 SOC detection benchmark로는 부족하다.

- 실제 clinic 네트워크에서 샘플링한 flow가 아니다.
- `mock_prob`가 수동 설계되어 ML 성능을 검증하지 않는다.
- bytes, packet count, TCP flag, TLS SNI, DNS query, HTTP path/status,
  failed login count, endpoint event가 없다.
- 같은 공격 template이 반복되어 모델/프롬프트가 쉽게 맞출 수 있다.
- benign 운영 노이즈가 깨끗하고 규칙적이다.
- 공격 비율 10%는 일반 운영망보다 높다.

발표에서 가장 정확한 표현은 다음이다.

> 통제된 synthetic clinic scenario를 사용해 Batch Loop와 Real Time Loop의
> 연결, Tier 2 curated artifact, Tier 1 watchlist guardrail을 엔지니어링하고
> 회귀 테스트했다.

반대로 “실제 병원망 성능을 입증했다”는 식으로 말하면 안 된다.

## 다음 시나리오 방향

다음 synthetic scenario는 더 복잡하기만 하면 안 되고, 실제 flow와 닮아야 한다.
핵심은 현실적인 benign baseline을 먼저 만들고 그 위에 공격/조직 이벤트를
주입하는 것이다.

우선순위는 다음과 같다.

1. day2 신규 CVE 시나리오:
   day1에는 portal이 일반 위험 자산이고, day2에 새 CVE가 들어오며, day3에 관련
   exploit probe가 증가한다. Tier 2가 watchlist를 갱신하되 benign portal traffic을
   과도하게 alert하지 않는지 본다.

2. 자산 교체 시나리오:
   day2 또는 day3에 VPN gateway나 billing DB IP가 바뀐다. Tier 2가 stale asset을
   계속 감시하지 않고 새 자산으로 watchlist를 이동하는지 검증한다.

3. messy benign operations 시나리오:
   patch window, vendor scanner, VPN 실패 재시도, backup retry, monitoring probe,
   SaaS burst를 넣는다. 실제 SOC에서 중요한 FP 내성을 검증할 수 있다.

4. 더 큰 조직 시나리오:
   지점 clinic, partner VPN, IdP, cloud storage, third-party SaaS, 여러 VLAN을 넣어
   Tier 2가 복잡한 attack surface를 요약할 수 있는지 본다.

5. richer flow field 시나리오:
   duration, bytes, packets, TCP flags, DNS query category, HTTP path/status,
   login failure count 같은 증거를 추가한다. 이게 있어야 “현실적인 flow와 닮았다”는
   발표 설득력이 생긴다.

좋은 synthetic dataset은 모든 row를 완벽한 template으로 만드는 것이 아니라,
현실적인 정상 분포를 만든 뒤 그 안에 공격 이벤트를 주입해야 한다.
