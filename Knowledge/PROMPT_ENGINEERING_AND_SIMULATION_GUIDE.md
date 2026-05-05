# Prompt Engineering and Simulation Guide

이 문서는 앞으로의 대화 세션에서 반복 설명을 줄이기 위한 기준 문서입니다.
구현 명세가 아니라, Tier 2/Tier 1 LLM 산출물의 방향성과 성능 평가, 시연용
시뮬레이션 케이스를 설계할 때 따를 작업 지침입니다.

## 핵심 전제

현재 아키텍처는 MVP 수준에서 완성된 것으로 본다.

```text
Batch Loop:
  Tier 2 LLM
  -> organization/security inputs + previous feedback
  -> Watchlist & Contexts
  -> Attack Surface Memory
  -> human-readable summary
  -> 중요한 자산/위협 업데이트가 있거나 운영자가 정한 일정 주기에 실행

Real Time Loop:
  flow logs / NetFlow
  -> cheap ML binary routing
  -> selected flows only go to Tier 1 LLM
  -> Tier 1 uses flow context, ML/SHAP evidence, recent source activity,
     and Tier 2-curated artifacts
```

다음 작업의 초점은 아키텍처를 다시 설계하는 것이 아니다. 초점은 Batch Loop와
Tier 1/Tier 2 프롬프트, 산출물 형식, 평가 데이터, 시연 시나리오를 더 설득력
있고 일관된 SOC 운영 이야기로 다듬는 것이다.

## 우선순위

`IMPLEMENTATION_SPEC.md`에 남아 있는 형식은 LLM으로 생성한 프로토타입이므로 신경 쓰지 않는다.

중요한 고정 결정:

- Tier 2만 자산, 정책, CVE feed, threat feed 같은 raw organization/security
  source를 읽는다.
- Tier 1은 raw source dump를 직접 받지 않는다.
- Tier 1은 Tier 2가 큐레이션한 Watchlist & Contexts, Attack Surface Memory,
  summary와 realtime flow/ML/activity evidence만 받는다.

## Gemini 기준

Batch Loop에는 Gemini API provider가 추가되었고, Gemini로 실패 없이
Tier 2를 구동한 상태를 현재 기준으로 삼는다.

로컬 `gemma4:26b`를 억지로 구동하기 위해 넣었던 짧은 길이 제한, 보수적인 출력
제약, 지나치게 단순한 구조 제한은 Gemini API 기준의 프롬프트/산출물 설계에서는
필요하면 완화해도 된다. 다만 파서와 runtime 안정성을 해치면 안 되므로 최종
파일은 여전히 machine-readable해야 한다.

## 산출물별 목표

### Watchlist & Contexts

좋은 watchlist entry는 다음을 담아야 한다.

- 대상 자산, 서비스, 포트, zone, owner/role 같은 식별 정보
- 우선순위와 유효 기간
- 어떤 source에서 이 판단이 나왔는지에 대한 짧은 근거
- 관련 정책, CVE, threat feed, 최근 feedback/history와의 연결
- Tier 1이 올려야 하는 조건과 반대로 과민 반응하지 말아야 할 조건

### Attack Surface Memory

Attack Surface Memory는 단순 최근 경보 통계가 아니다. Tier 2가 다음 실행 주기에도
기억해야 할 공격 표면 변화와 운영상 결론을 저장하는 장기 기억에 가깝다.
클라우드 LLM의 메모리 파일처럼, 최근/중기/장기로 영역을 분리하는 것이 좋다.
기본적으로 자연어 마크다운으로 저장한다.

좋은 memory는 다음을 설명해야 한다.

- 자산별 노출 서비스와 위험도의 변화
- 반복 공격자, 반복 대상, 반복 포트, 반복 패턴
- 이전 watchlist가 실제 flow에서 hit/miss 된 결과
- Tier 2가 다음 주기에서 유지, 완화, 강화해야 할 판단

### Human-Readable Summary

Summary는 운영자와 발표 청중이 이해할 수 있는 SOC 브리핑이어야 한다. 단순히
파일 내용을 다시 나열하지 말고, 현재 조직의 보안 상태와 이번 실행 주기 판단의 이유를
짧고 명확하게 설명해야 한다.

좋은 summary는 다음 질문에 답해야 한다.

- 현재 가장 중요한 노출 자산은 무엇인가?
- 어떤 위협 환경이나 정책 조건 때문에 그 자산이 중요해졌는가?
- Tier 1이 실시간 flow에서 무엇을 특히 봐야 하는가?
- 이번 실행 주기 판단의 한계나 데이터 공백은 무엇인가?

## 프롬프트 엔지니어링 방향

프롬프트는 출력 schema만 강제하는 문서가 아니다. 모델이 SOC analyst처럼
우선순위를 정하고, 근거를 보존하고, 불확실성을 표현하도록 유도해야 한다.

Tier 2 프롬프트는 다음을 명확히 해야 한다.

- raw source를 요약 없이 복사하지 말 것
- SOC 관점에서 actionable한 watchlist/context로 큐레이션할 것
- CVE/threat feed/policy/asset/history를 서로 연결해 판단할 것
- source status, missing source, disabled source, error source를 보존할 것
- 불확실한 연결은 단정하지 말고 confidence나 limitation으로 표현할 것
- Tier 1이 사용할 수 있는 조건과 근거를 구체적으로 남길 것

추가: 먼저 각종 위협을 기반으로 예상되는 공격 시나리오를 Tier 2가 스스로 추론하여 시뮬레이션 해야 한다.
이를 기반으로 Tier 1이 실시간 flow를 볼 때 "이번 실행 주기 이 자산/서비스/행위가 왜 특별히 중요하게 취급되는가"를
빠르게 알 수 있도록 해야 한다.
핵심은 **지능의 계층화를 통해서, Tier 1이 자신의 낮은 지능으로 스스로 지나친 추론을 매번 하지 않도록 하는 것**이다.

Tier 1 프롬프트는 다음을 명확히 해야 한다.

- raw assets/CVE/policy/threat feeds를 요구하지 말 것
- ML probability, SHAP evidence, recent source activity, watchlist/context를
  함께 해석할 것
- watchlist match만으로 무조건 alert하지 말고 flow behavior와 함께 판단할 것
- benign/alert/uncertain과 severity를 안정적인 JSON으로 반환할 것
- 모델이 모르는 외부 사실을 꾸며내지 말 것

## 시뮬레이션 케이스 방향

기존 sample flow는 route smoke test로는 유용하지만, 성능 측정과 시연용으로는
부족하다. 앞으로 만들 평가/시연 데이터는 현실성 있는 조직 자산 구조, 위협 환경,
시간 흐름, 여러 공격 단계를 포함해야 한다.

좋은 시뮬레이션은 다음 요소를 가진다.

- 작은 조직이 실제로 가질 법한 자산 구성
- 내부/외부 zone, cloud/VPN/admin path, public-facing service 구분
- CVE, threat feed, policy, asset criticality가 서로 맞물리는 설정
- benign admin activity와 공격 activity가 쉽게 구분되지 않는 회색 지대
- scanning, brute force, exploitation attempt, lateral movement 같은 단계성
- ML이 애매하게 라우팅하는 케이스와 watchlist가 가치를 만드는 케이스
- Tier 1/Tier 2 구조가 raw-context baseline보다 비용 효율적임을 보일 수 있는
  충분한 flow 수와 반복 패턴

추가: 동료평가 비율이 높으므로... 중요한 것은 시연 자체가 인상적이어야 한다.
따라서 실질적인 위협(실제 케이스와 비슷한 CVE 등)을 반영하는 부분이 아주 중요하다.

## 평가 기준

성능 측정은 단순 "LLM이 그럴듯하게 말했다"가 아니라 정량/정성 기준을 함께 본다.

정량 기준:

- route별 flow 수: auto_dismiss, tier1_llm, auto_alert
- Tier 1 호출 수와 queue fallback 수
- verdict 일치율, severity 일치율
- high/critical recall
- false positive와 false negative
- JSON/schema parse 실패율
- prompt tokens, completion tokens, latency, estimated cost
- Tier 2 batch 비용 + Tier 1 N건 비용과 raw-context Tier 1-only baseline 비용의
  break-even point

정성 기준:

- watchlist reason이 실제 source와 연결되는가?
- memory가 다음 주기 의사결정에 쓸 수 있는 결론을 남기는가?
- summary가 발표/시연에서 납득 가능한 SOC 브리핑처럼 읽히는가?
- Tier 1 verdict가 ML evidence와 Tier 2 context를 균형 있게 사용했는가?
- 모델이 source에 없는 내용을 꾸며내지 않았는가?

추가: 교수님이 평가와 검증을 중요시 하시므로(그리고 청중에게 직관적이고 명확한 발표 설득력이 필요하므로),
마지막에는 생성한 테스트 케이스를 기반으로 시뮬레이션 시 비용과 탐지 성능을 중심으로 도표 형태로 만들 수 있어야 한다.

## 앞으로의 작업 원칙

산출물 형식을 바꿀 때는 먼저 역할과 평가 목적을 정한 뒤 schema를 정한다. 예전
프로토타입 형식에 맞추기 위해 의미를 희생하지 않는다.

다만 runtime 안정성은 유지한다. 사람이 읽기 좋은 설명과 machine-readable한
필드를 함께 설계한다.

문서와 구현이 달라지면 같은 작업에서 문서도 갱신한다. 폴더, 파일, pipeline
책임이 바뀌면 `Knowledge/PROJECT_STRUCTURE.md`도 함께 업데이트한다.
