# Self LLM SOC — 프로젝트 계획서 (v4)

> Mythos 이후(Post-Mythos) 시대의 소규모 조직을 위한 확장 가능한 2-티어 LLM 방어 파이프라인
>
> 플로우 로그 기반 비침습 배포, 자산 지식 활용 선제적 방어 계획 수립
>
> AI Security & Application 텀 프로젝트 제안서

---

## 0. 문서 변경 요약 (v3 → v4)

v3 대비 변경:

- **1차 목표 명시**: "ML 정확도 향상"이 아니라 **"end-to-end 파이프라인 구축"**
- **평가를 1/2/3차 구조화**: 작동성 → 컴포넌트 기여 검증 → 시연 임팩트
- **확장성 섹션 신설** (3.8): 모듈식 설계로 LLM/ML/위협 정보 소스의 plug-in 가능
- **프롬프트 엔지니어링 섹션 신설** (3.7): 메타 프롬프트 구조 + 버전 관리 프로세스
- **발표본 기준으로 구조 정렬**: Tier 1이 자산·위협·정책 컨텍스트를 층별로 직접 모두 받는 구조가 아니라, Tier 2가 생성한 **Watchlist & Contexts** 파일을 Tier 1이 참조하는 구조로 정정
- **PoC 결과 자리 마련** (부록 E): 발표 직전 작동성 사전 확인 결과 삽입 예정

---

## 1. 문제 정의

### 1.1 Mythos 이후 (2026-04): 방어의 시간 축 붕괴

2026년 4월 7일, Anthropic은 Claude Mythos 발표와 함께 **모델을 공개하지 않는** 결정을 내렸다. 사상 처음으로 AI 모델이 공개 금지되었다. 이유는 Mythos가 인간 전문가가 20시간 걸리는 32단계 기업 네트워크 공격(초기 정찰에서 완전 장악까지)을 자율적으로 10회 중 3회 완주했기 때문이다. 이전 모델은 평균 16단계를 넘지 못했다. 공개 테스트에서 Mythos는 주요 OS·웹브라우저 전반에서 **수천 개의 zero-day**를 발견했다 — 그중 하나는 27년간 탐지되지 않았던 OpenBSD 버그였다.

이 시점을 전후로 보안 업계의 핵심 가정 하나가 무너졌다: **"패치까지의 시간"이 방어자에게 주어진다**는 가정. 기존 SOC 운영은 "이런 취약점이 있다 → 며칠~몇 주 안에 패치하면 된다"는 시간적 여유 위에 서 있었다. Mythos급 도구는 시간 단위로 취약점을 식별하고 악용한다. 계약서의 "reasonable patching cadence" 문구가 집행 불가능해졌다. IMF·세계은행 봄 회의에서 금융권 규제 당국이 이 문제를 논의했고, ECB 총재는 국제 공조 안전장치를 촉구했다.

엔터프라이즈의 대응은 **Project Glasswing** — AWS, Apple, Cisco, CrowdStrike, Google, JPMorgan, Microsoft, NVIDIA 등 50여 기업이 Mythos Preview를 방어에 활용한다. 한 컨소시엄에 선택받은 기업들이 방어 지능을 공유한다.

**그렇다면 소규모 조직은?** 그들에겐 Mythos도, Glasswing 참여권도, 전담 SOC도, 월 수천 달러 XDR 구독도 없다. "AI를 방어에 빨리 도입하라"는 업계 권고가 내려왔지만, 소규모 조직에는 도입할 AI도 운영할 인력도 없다.

### 1.2 방어자에게 남은 비대칭 우위

공격자가 AI로 속도 우위를 확보한 이 시점에, 방어자에게 남은 구조적 우위는 단 하나다: **조직 내부 자산·코드·토폴로지·정책에 대한 합법적 전체 접근 권한**. 공격자는 탐색해야 알 수 있는 것을 방어자는 이미 알고 있다. 어떤 서버가 어떤 서비스를 돌리는지, 어떤 CVE에 영향받는지, 업무 시간이 언제인지, 어느 자산이 치명적인지.

이 내부 지식을 **실시간 탐지 체계에 어떻게 주입하는가**가 Post-Mythos 시대 방어의 핵심 문제다. 엔터프라이즈는 XDR 플랫폼과 전담 분석가로 이것을 한다. 본 프로젝트는 소규모 조직을 위한 **경량 대체재**를 제안한다.

### 1.3 문제 구조

1. **ML 탐지의 극단적 이분법 (실증)**: 볼륨 공격(DDoS, Brute Force)은 F1 1.0에 근접하게 탐지하지만 교활한 공격(Infiltration F1 0.45, SlowHTTPTest F1 0.00, Web 공격 F1 0.02-0.19)은 **구조적으로 놓친다** (6.1절 실증 참조).
2. **방어 전략의 실시간 반영 불가**: 새 CVE 공지, 신규 자산 추가, 위협 인텔 변경이 있어도 기존 ML IDS는 재학습 없이 반영 불가.
3. **비전문가 담당자**: 소규모 조직 담당자는 IT 겸직. 분석가 수준 리포트 해석 불가.

### 1.4 연구 질문 (1차 / 2차 / 3차 목표)

본 프로젝트는 세 층위의 목표를 명시적으로 분리한다.

**1차 목표 (구현·작동)**:
> "Post-Mythos 시대 소규모 조직을 위한 ML+2티어 LLM 트리아지 파이프라인을 9주 내 end-to-end로 구현할 수 있는가?"

**2차 목표 (검증)**:
> "Tier 2가 생성한 Watchlist & Contexts가 Tier 1 판정에 측정 가능한 기여를 하는가?"

**3차 목표 (시연·서사)**:
> "비전문가 담당자가 행동 가능한 한국어 트리아지 리포트가 생성되는가?"

각 목표는 6.2절의 평가 지표 3축에 대응한다.

---

## 2. 기술 배경 및 설계 동기

### 2.1 AI 보안 분야 트렌드 (2025-2026)

- **Agentic AI 공격 기술의 변곡점**: 2025년 11월 첫 AI 조율 사이버 스파이 캠페인 보고, 2026년 4월 Mythos 발표로 AI가 "자문"에서 "실행자"로 이행. 공격 속도·지속성·조합력 모두 구조적 변화.
- **Frontier vs Efficient 모델 양극화 가속**: Opus 4.7, GPT-4.6 급 프론티어 모델과 로컬 7B 수준 경량 모델의 비용 차이 100배 이상. 역할 분리가 실용적 필연.
- **Explainable AI for Security 수요 증가**: Mythos 대응 권고의 하나가 "자동화 방어를 위한 사고 대응 플레이북 재작성". 자동화에는 설명 가능성이 전제.
- **Underserved Deployment Contexts**: Glasswing 접근권이 없는 조직에 대한 방어 공백이 새로운 연구 축으로 부상.

### 2.2 본 프로젝트의 위치

새로운 탐지 알고리즘을 제안하지 않는다. 대신:

1. **ML 탐지의 실증적 한계 수용** — 카테고리별 극단적 성능 격차를 숨기지 않고 시스템 설계에 반영
2. **프론티어 LLM을 방어 전략 수립자로 배치** — 취약점·자산·위협 인텔을 통합 추론해 **공격자 관점의 노출 지점**을 식별하고 **실시간 판정 지침**을 생성
3. **경량 LLM을 전략 집행자로 배치** — 플로우 실시간 판정 시 프론티어 LLM이 생성한 **Watchlist & Contexts**를 참조
4. **시간 지평 분리** — 프론티어(배치, 주기적 전략 갱신) vs 경량(실시간, 이벤트 판정)
5. **확장 가능한 파이프라인 구조** — 새 LLM, 새 ML 모델, 새 위협 정보 소스를 코드 변경 없이 plug-in 가능

참신성은 알고리즘이 아닌 **"방어 지능의 계층적 위임" 아키텍처와 Post-Mythos 소규모 조직 배포 맥락의 결합**에 있다.

---

## 3. 제안 시스템

### 3.1 전체 구조

```
[Batch Loop — 중요 자산/위협 업데이트 또는 일정 주기, 프론티어 LLM]

  Tier 2 후보 입력 (아직 확정 전)
       ├─ assets.yaml (자산 카탈로그)
       ├─ cve_feed.yaml (영향 CVE 목록)
       ├─ threat_feed.yaml (IP 블랙리스트 + 업계 공지)
       └─ policy.yaml (접근 정책)
              │
              ▼ (주 1회 또는 중요 업데이트 시)
              │
  지난 주기 Tier 1 판정 통계 + 이전 watchlist hit/miss ─┐
                                                        │
                                                        ▼
  [A] Tier 2 LLM — 방어 전략 수립자 (Opus 4.7, GPT-4.6 급)
     입력: 위 후보 입력 중 확정된 소스 + 운영 피드백
     출력:
      · Batch Executive Summary (한국어, 비전문가용)
       · Attack Surface Brief — 자산·CVE·위협 인텔 기반 공격 노출 지점 서술
       · Watchlist & Contexts — Tier 1 실시간 판정 지침과 이번 주 요약 맥락
              │
              ▼
  watchlist.yaml + brief_context.md (버전 관리, Tier 1에 주입)


[Fast Loop — 실시간, 경량 LLM]

  플로우 로그 (UTM/방화벽/Zeek/NetFlow)
       │
       ▼
  [1] XGBoost 이진 분류
       │
       ├── proba < 0.30 (약 87%)     → AUTO_DISMISS (DB, QA 10%)
       ├── proba > 0.95 (약 12%)     → AUTO_ALERT 템플릿
       └── 0.30 ≤ proba ≤ 0.95 (약 0.25%)
             │
             ▼
       [2] Tier 1 입력 조립
          ├─ 플로우 요약
          ├─ ML 판정 + SHAP TOP5
          ├─ 출발지 최근 활동/직전 판정 이력
          └─ Tier 2가 생성한 Watchlist & Contexts 매칭 결과
             │
             ▼
       [B] Tier 1 LLM — 실시간 판정자 (로컬 Gemma/Qwen 7B)
          - watchlist 매칭 시 자동 격상 우선
          - Tier 2가 큐레이션한 최신 운영 맥락을 참조해 판정
          - 출력: verdict, severity, rationale_ko, recommended_action_ko
             │
             ▼
       [3] 리포트 DB 저장 (SQLite)
          Tier 2의 다음 배치 입력이 됨
```

### 3.2 왜 2티어인가 — 역할과 시간 지평의 분리

상용 SOC의 Tier 1 분석가(초동)와 Tier 3 헌터·CTI 분석가(전략·추세)는 같은 데이터를 **다른 시야**로 본다. 본 시스템은 이 구조를 LLM 계층으로 계산적으로 모방하되, Post-Mythos 시대의 특수성을 반영한다: **방어 전략은 자주 바뀌어야 한다**.

| 항목 | Tier 1 LLM (Fast Loop) | Tier 2 LLM (Batch Loop) |
|---|---|---|
| 타이밍 | 실시간 (초 단위) | 중요 자산/위협 업데이트 또는 설정된 운영 주기 |
| 입력 단위 | 단일 플로우 + ML 근거 + Tier 2 산출 맥락 | 조직 지식 후보 + 기간 통계 + 운영 피드백 |
| 판단 대상 | "이 한 건이 공격인가" | "지금 조직의 공격 노출 지점은 어디인가" |
| 핵심 기능 | 이벤트 판정 + 한국어 서술 | **방어 전략 추론 + watchlist 생성** |
| 모델 | 로컬 7B (Gemma/Qwen) | 프론티어 (Opus 4.7, GPT-4.6) |
| 비용 축 | 로컬 고빈도 (거의 0) | 주 1회 프론티어 API ($1-5/주) |
| 출력 | 이벤트 판정 + 리포트 | Summary + Attack Surface Brief + Watchlist & Contexts |

**핵심 비대칭**: Tier 1은 "지능이 낮은 대신 빠르고 공짜", Tier 2는 "지능이 높은 대신 느리고 비싸다". 이 두 속성을 **정보 흐름**으로 연결한다. Tier 2가 전략을 수립하고, Tier 1이 실시간에 집행한다.

### 3.3 Tier 1 LLM — 실시간 판정자

**Tier 1 입력** (약 1.5-2K 토큰 목표):

1. **플로우 요약**: NetFlow 주요 값을 Tier 1이 읽기 쉬운 형태로 정리
2. **ML 판정 + SHAP 근거**: 확률, 카테고리 추정, 기여 피처 TOP5
3. **운영 이력 요약**: 출발지 최근 활동과 직전 판정 이력
4. **Tier 2 Watchlist & Contexts**: 이번 주 watchlist 매칭 여부, 우선순위, brief context에서 필요한 짧은 맥락

자산 카탈로그, CVE, 위협 인텔, 정책은 Tier 1에 원천 데이터로 직접 주입하지 않는다. 발표본 기준 구조는 Tier 2가 이 정보들을 선별·요약해 **Tier 1용 Watchlist & Contexts**로 만들어 주는 방식이다.

**출력** (JSON):
```json
{
  "verdict": "alert",
  "severity": "high",
  "rationale_ko": "50-150자 한국어 서술",
  "recommended_action_ko": "30-80자 구체적 조치",
  "watchlist_matched": "priority_1: CVE-2026-XXXXX 영향 자산"
}
```

**watchlist 매칭 시 특수 처리**: Tier 1은 자체 판단보다 **Tier 2의 전략을 우선 반영**하도록 프롬프트 설계. 이는 "경량 모델이 프론티어 모델의 사전 추론을 상속받는" 핵심 메커니즘이다.

### 3.4 Tier 2 LLM — 방어 전략 수립자

Tier 2는 중요 이벤트(신규 CVE 공지, 자산 변경, 심각한 공격 탐지) 또는 설정된 운영 주기에 따라 실행된다. **프론티어 모델 사용** (Opus 4.7, GPT-4.6 급).

#### 3.4.1 입력
- Tier 2 입력은 아직 최종 확정 전이다. 발표본 기준 후보는 조직 지식(`assets.yaml`, `policy.yaml`), 외부 지식(`cve_feed.yaml`, `threat_feed.yaml`), 운영 피드백(지난 주 Tier 1 판정 통계, 이전 watchlist hit/miss, QA 샘플 결과)이다.
- 구현 문서에서는 입력 수집기를 모듈화해 후보 입력을 쉽게 켜고 끌 수 있게 한다.
- 시간 범위 (분석: 지난 7일, 유효 기간: 다음 7일)

#### 3.4.2 출력 3종

**A. Batch Executive Summary** (한국어 HTML)
- 정량 통계, 주목할 공격 흐름, 자산별 리스크, Tier 1 판정 품질, 권장 정책 조정

**B. Attack Surface Brief** (자산별 노출 지점 서술)
> "172.31.69.28 웹 애플리케이션 서버는 Apache 2.4.x 실행. CVE-2024-XXXXX 영향. 지난 주 external 접근 3.2배 증가. 예상 공격 경로: CVE 프로브 → RCE → lateral movement to 172.31.69.25 SSH 서버."

**C. Watchlist & Contexts** (Tier 1 주입용 구조화 데이터 + 짧은 맥락)
```yaml
priority_1:  # 자동 격상
  - target_assets: ["172.31.69.28"]
    reason: "CVE-2024-XXXXX Apache RCE 영향"
    detection_hints: ["dst_port in [80, 443] AND L7_PROTO=7 AND external src"]
    escalation_rule: "proba > 0.20 이면 자동 Alert"

priority_2:  # 심각도 +1
  - ...

priority_3:  # 참고
  - ...
```

#### 3.4.3 피드백 루프

Tier 2는 다음 주기에 자기 출력을 평가한다 (이전 watchlist의 hit/miss). 점진적 전략 개선의 구조.

### 3.5 AUTO_DISMISS QA 감사 + AUTO_ALERT 템플릿

- AUTO_DISMISS 10% 샘플을 Tier 2가 재판정하여 구조적 FN 측정
- AUTO_ALERT(prob > 0.95)는 LLM 호출 없이 템플릿 리포트 (실증: 99.7% 실제 attack)

### 3.6 AUTO_ALERT 템플릿 (생략 — 3.5 통합)

### 3.7 프롬프트 엔지니어링 전략 (메타 프롬프트 구조)

본 시스템은 두 LLM 레이어가 파일 산출물로 연결된다. **Tier 2가 생성한 watchlist와 brief context가 Tier 1의 입력 프롬프트 일부**가 된다. 이 메타 구조 때문에 프롬프트 엔지니어링이 두 단계로 진행된다.

#### A. 사람이 작성하는 정적 프롬프트
- **Tier 2 system prompt**: "당신은 보안 분석가다. 확정된 입력 소스와 운영 통계를 받아 다음 주기 Tier 1이 사용할 Watchlist & Contexts를 작성하라..."
- **Tier 1 system prompt**: "당신은 실시간 트리아지 분석가다. 플로우 요약, ML 근거, 운영 이력, Tier 2가 생성한 Watchlist & Contexts를 받아 판정하라..."
- **출력 스키마 강제**: JSON, 예시 포함, parser 실패 시 fallback 로직

#### B. LLM이 자동 생성하는 동적 프롬프트
- Tier 2 출력 watchlist와 brief context는 **Tier 1 입력 파일**로 구성된다.
- Tier 2가 매 주기 Watchlist & Contexts를 업데이트 → Tier 1 프롬프트 입력이 자동 갱신
- 사람이 매번 프롬프트를 손보지 않고 **방어 전략이 시스템 내에서 진화**하는 구조
- 본 프로젝트의 핵심 기여 중 하나: **메타 프롬프트 엔지니어링 (LLM이 LLM의 입력을 조정)**

#### C. 프롬프트 반복 개선 프로세스 (Git에 기록)

| 시점 | 버전 | 변경 내용 | 근거 |
|---|---|---|---|
| W11 | Tier 1 v1 | 플로우/ML/운영 이력 + Tier 2 산출물 입력 구조 | 초기 프로토타입 |
| W12 | Tier 1 v2 | JSON 출력 강제, 스키마 명시 | parser 실패율 감소 |
| W12 | Tier 1 v3 | watchlist 우선 처리 로직 | Tier 2 도입 |
| W13 | Tier 1 v4 | uncertain verdict 처리 명시 | ablation 결과 반영 |
| W14 | Tier 1 v5 | 한국어 품질 개선, 톤 조정 | 정성 평가 결과 |
| W11 | Tier 2 v1 | 기본 watchlist 생성 | 초기 |
| W13 | Tier 2 v2 | priority 분류 정교화 | hit/miss 분석 |
| W14 | Tier 2 v3 | Attack Surface Brief 추가 | 시연 임팩트 |

각 변경의 근거는 commit message와 `prompts/CHANGELOG.md`에 기록.

#### D. 프롬프트 평가 방법
- 골든 셋 50건에 대한 버전별 정답 일치율
- 프롬프트 변경이 어떤 효과(좋은/나쁜 부수효과)를 가져왔는지 정량 기록
- 최종 보고서에 프롬프트 진화 history 포함

### 3.8 확장성 설계

본 시스템은 **모듈식 plug-in 구조**로 설계한다. 9주 내 구현 범위는 한정되지만, 향후 확장이 코드 수준에서 자연스럽게 가능하도록 인터페이스를 정의한다.

#### A. LLM Provider 추상화

```python
class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str, **kwargs) -> str: ...

class OllamaProvider(LLMProvider): ...
class ClaudeAPIProvider(LLMProvider): ...
class OpenAIProvider(LLMProvider): ...
class GeminiProvider(LLMProvider): ...
```

config 파일에서 모델 변경 가능:
```yaml
tier1:
  provider: "ollama"
  model: "gemma:7b"
tier2:
  provider: "claude_api"
  model: "claude-opus-4-7"
```

**확장 가능성**: 새 LLM 출시 시 Provider 클래스 하나 추가하면 즉시 사용 가능. Tier 1은 로컬 / Tier 2는 클라우드라는 기본 구성도 변경 가능 (예: 둘 다 로컬, 둘 다 클라우드, hybrid).

#### B. ML Detector 추상화

```python
class MLDetector(ABC):
    @abstractmethod
    def predict(self, flow: FlowFeatures) -> MLResult: ...
    @abstractmethod
    def explain(self, flow: FlowFeatures) -> SHAPExplanation: ...

class XGBoostDetector(MLDetector): ...
# 미래 확장:
# class LightGBMDetector(MLDetector): ...
# class IsolationForestDetector(MLDetector): ...
# class EnsembleDetector(MLDetector): ...
```

**확장 가능성**: 새 ML 모델 학습 후 Detector 클래스 등록하면 라우팅 레이어가 그대로 작동. Ensemble 구성도 가능 (여러 Detector의 합의로 라우팅).

#### C. Threat Intelligence Source 추상화

```python
class ThreatSource(ABC):
    @abstractmethod
    def lookup_ip(self, ip: str) -> ThreatInfo: ...
    @abstractmethod
    def get_recent_advisories(self) -> list[Advisory]: ...

class StaticBlocklist(ThreatSource): ...     # MVP: yaml 파일
class GreyNoiseAPI(ThreatSource): ...        # 향후
class AbuseIPDBAPI(ThreatSource): ...        # 향후
class CVENVDFeed(ThreatSource): ...          # 향후
class CustomMISP(ThreatSource): ...          # 조직 내부 인텔
```

**확장 가능성**: 새 위협 인텔 소스 추가 시 ThreatSource 구현체 등록하면 컨텍스트 레이어가 자동으로 통합. 시연에서 임의 인텔 주입도 같은 인터페이스 활용.

#### D. Asset Catalog Source 추상화

```python
class AssetSource(ABC):
    @abstractmethod
    def lookup_asset(self, ip: str) -> AssetInfo: ...

class StaticYAMLAssets(AssetSource): ...     # MVP
class CMDBIntegration(AssetSource): ...      # 향후 — 조직 CMDB 연동
class CloudInventoryAPI(AssetSource): ...    # 향후 — AWS/GCP 자산 자동 조회
```

#### E. Report Renderer 추상화

```python
class ReportRenderer(ABC):
    @abstractmethod
    def render_event(self, event: Event) -> bytes: ...
    @abstractmethod
    def render_summary(self, period: TimePeriod) -> bytes: ...

class HTMLRenderer(ReportRenderer): ...      # MVP
class PDFRenderer(ReportRenderer): ...       # 향후
class SlackRenderer(ReportRenderer): ...     # 향후 — Slack 메시지 형식
class EmailRenderer(ReportRenderer): ...     # 향후
```

#### MVP에서 구현하는 것

각 추상 인터페이스의 **첫 구현체 1개씩**:
- LLMProvider: OllamaProvider + ClaudeAPIProvider
- MLDetector: XGBoostDetector
- ThreatSource: StaticBlocklist
- AssetSource: StaticYAMLAssets
- ReportRenderer: HTMLRenderer

**계획서의 의도**: MVP는 최소 동작 가능한 구현이지만, 인터페이스가 잡혀 있어 **새 컴포넌트 추가가 코드 수정 없이 등록만으로 가능**한 구조. 이는 본 시스템이 "9주 일회성 프로젝트"가 아니라 **지속 발전 가능한 플랫폼**임을 의미한다.

---

## 4. 자산 카탈로그, 위협 인텔, 정책

(v3와 동일 — 분량상 생략. v3 4.1-4.4 참조)

### 4.1 자산 카탈로그 (assets.yaml) — CICIDS2018 기반 문서 매핑
### 4.2 위협 인텔 (threat_feed.yaml) — 내장 + 주입 가능
### 4.3 Attack Surface Reasoning (Tier 2 내부 동작)
### 4.4 정책 (policy.yaml)

---

## 5. 데이터셋

### 5.1 주: NF-CSE-CIC-IDS2018-v3 (20.1M 플로우, 53 NetFlow 피처)
### 5.2 보조: NF-UNSW-NB15-v2 (합성 아티팩트 실증용)
### 5.3 한계 (정직한 인정)
- CICIDS2018 시간순 분할 불가 → stratified 사용
- 자산 컨텍스트는 문서 매핑
- Tier 2 kill chain 재구성 ground truth 부재
- CVE·위협 인텔은 합성

(v3 5.1-5.3과 동일 내용)

---

## 6. 평가 프로토콜

### 6.1 ML 실증 결과 (사전 수행, 본 계획서의 설계 근거)

**3-데이터셋·분할 비교**:

| 실험 | 이진 F1 | 이진 FPR | 이진 AUC | 해석 |
|---|---:|---:|---:|---|
| NF-UNSW-NB15-v2 (시간순) | 0.9995 | 0.0001 | 1.0000 | TTL 등 합성 지문 학습 |
| NF-CICIDS2018-v3 (시간순) | 0.2259 | 0.0010 | 0.6591 | 날짜별 공격 편성 한계 |
| **NF-CICIDS2018-v3 (stratified)** | **0.9700** | 0.0014 | 0.9896 | **실배포 추정 상한** |

**카테고리별 F1 (stratified)**: DDoS-HOIC ≈ 1.00, Hulk ≈ 1.00, Bot ≈ 1.00 (이상 AUTO_ALERT 템플릿 대상). **Infiltration 0.45, SlowHTTPTest 0.00, Web 공격 0.02-0.19** (이상 Tier 1 LLM 핵심 타겟).

### 6.2 평가 지표 (1차 / 2차 / 3차 목표 구조)

#### 1차 목표 metric: 파이프라인 작동성

본 프로젝트의 **최소 합격선**. 작동 여부로 평가.

- **end-to-end 처리 성공률**: 입력 플로우 N건 → 리포트 N건 생성 (≥95% 목표)
- **라우팅 분기 비율 실측**: AUTO_ALERT / AUTO_DISMISS / Tier 1 / Tier 2 비율
- **Tier 1 평균 지연시간**: ≤5초 목표 (로컬 7B, RTX 5060 Ti)
- **Tier 2 배치 1회 실행 시간 및 토큰 사용량**: 5분 이내, 30K 토큰 이내 목표
- **HTML 리포트 생성 성공률**: 100%
- **CLI 단일 커맨드 작동 여부**: 입력 → 출력 한 번에

#### 2차 목표 metric: 컴포넌트 기여 검증

각 입력/산출물 단위가 실제로 의미 있는가를 ablation으로 측정. 발표본 기준으로는 Tier 1에 원천 컨텍스트를 층별로 모두 직접 넣는 비교가 아니라, **Tier 2가 생성한 Watchlist & Contexts의 유무와 품질**을 중심으로 비교한다.

**Ablation 평가 (골든 셋 50건 기준 정답 일치율)**:

| 구성 | Tier 1 입력 구성 | 기대 일치율 |
|---|---|---:|
| Baseline | ML only (라우팅, LLM 없음) | 60-70% |
| +Tier1 Basic | 플로우 요약 + ML/SHAP + 최근 활동 | 70-78% |
| +Watchlist | Basic + Tier 2 watchlist 매칭 | 78-85% |
| +Brief Context | Basic + watchlist + Tier 2 brief context | 80-88% |
| +Memory Feedback | Full + 이전 watchlist hit/miss 반영 | 83-90% |

**부가 측정**:
- **route_3 영역 F1 변화**: Tier 2 산출물 활성/비활성에서 측정
- **Tier 2 watchlist 적절성**: 사람 평가 5점 척도 (30개 사례)
- **Tier 1 일관성**: 동일 입력 5회 반복 시 verdict 일치율 (목표 ≥80%)
- **프롬프트 버전별 효과**: v1→v5의 골든 셋 일치율 변화 (3.7-D)

#### 3차 목표 metric: 리포트 품질 (정성 루브릭)

50-100건 수동 평가, 각 항목 1-5점.

| 항목 | 정의 | 목표 평균 |
|---|---|---:|
| 정확성 | 판정이 합리적인가 (원 라벨 또는 컨텍스트 기준) | ≥4.0 |
| 맥락 정합성 | 자산·시간·인텔이 서술에 반영됐는가 | ≥4.2 |
| 실행 가능성 | 권장 조치가 구체적인가 | ≥3.8 |
| 가독성 | 비전문가 이해 가능한가 | ≥4.0 |

### 6.3 시연 컴포넌트 (3차 목표의 시각적 증명)

발표 시 라이브 시연:
- Step-by-step Tier 2 산출물 주입 시연 (부록 C)
- Tier 2 watchlist 라이브 생성 (CVE 입력 → watchlist 출력)
- Tier 2 Watchlist & Contexts 주입 전/후 Tier 1 판정 변화 A/B
- 합성 kill chain 시나리오 Tier 2 재구성

### 6.4 베이스라인 비교

- Baseline A: ML only, 기본 임계치
- Baseline B: ML only, 튜닝 임계치
- Baseline C: ML + 단일 LLM (2티어 없음)
- Baseline D: ML + 2티어, watchlist 비활성 (Tier 1은 Tier 2 brief context만 참조)
- **Proposed**: ML + 2티어 + Watchlist & Contexts

### 6.5 평가 프레이밍의 정직성

원 라벨과 컨텍스트 기반 판정이 불일치할 수 있다. 이를 **기능으로 인정**하고 발표에서 정면으로 다룬다. 동시에 본 프로젝트의 1차 목표는 정확도가 아니라 **파이프라인 구축**이므로, 정확도 수치는 부차적 평가 항목임을 명시한다.

---

## 7. 기술 스택

| 영역 | 선택 | 비고 |
|---|---|---|
| 언어 | Python 3.11+ | |
| ML | XGBoost (hist + cuda), SHAP | NetFlow 53 피처 |
| Tier 1 LLM | 로컬 Ollama + Gemma/Qwen 7B | RTX 5060 Ti 16GB |
| Tier 2 LLM | 프론티어 API (Claude Opus 4.7, GPT-4.6) | 월 1-5만원 |
| Provider 추상화 | 자체 정의 (3.8-A) | 모델 swap 가능 |
| DB | SQLite | 리포트, 판정 이력, watchlist 버전 |
| 리포트 | Jinja2 + Chart.js | 정적 HTML |
| 인터페이스 | CLI + HTML | Streamlit은 확장 phase |
| 버전 관리 | Git/GitHub | 평가 대상 |
| AI 코딩 도구 | Cursor / Claude Code / GitHub Copilot | 적극 활용 (과제 요구) |

### 7.1 의도적 범위 외

- Isolation Forest, LSTM/Transformer 탐지 모델
- RAG (스코프 방어)
- 실시간 스트리밍 (배치 파일 입력)
- Streamlit 대시보드
- 엔드포인트 텔레메트리
- 파인튜닝
- 자산 카탈로그 관리 UI
- 다국어 (한국어 우선)

---

## 8. 수행 계획

| 단계 | 작업 | 산출물 |
|---|---|---|
| 단계 1 | **제안 발표**, repo 초기화, 미니 PoC | 제안 PDF, GitHub, PoC 결과 |
| 단계 2 | CICIDS2018 파이프라인, stratified 학습, SHAP, **Provider 추상화 인터페이스** | ML 베이스라인, 인터페이스 정의 |
| 단계 3 | 플로우/ML/운영 이력 기반 Tier 1 입력 조립, 라우팅, **Tier 1 프롬프트 v1**, **골든 셋 50건 구축** | Tier 1 프로토타입, 평가 데이터 |
| 단계 4 | **Tier 2 모듈, Watchlist & Contexts 생성·주입, HTML v1, MVP 데모** | 진행 발표, end-to-end |
| 단계 5 | 평가 프로토콜, **Ablation A/B (1차/2차 metric)**, QA 샘플링 | 평가 결과 1차 |
| 단계 6 | 프롬프트 튜닝 (v4-v5), **Attack Surface Brief**, 정성 평가, 시연 시나리오 | 평가 결과 2차 |
| 단계 7 | 최종 리포트, **데모 영상**, **최종 발표 (라이브 시연)** | 최종 PDF, 데모 |

### 8.1 리스크 테이블

| 리스크 | 영향 | 완화책 |
|---|---|---|
| Tier 2 프론티어 API 비용 초과 | 중 | 주 1회 cap, 월 예산 5만원 한도 |
| Tier 2 watchlist 품질 불안정 | 중 | 초기 수동 검토, 루브릭 반복 개선 |
| Tier 1 watchlist 주입 프롬프트 과부하 | 중 | 토큰 제한, priority_1만 전달 |
| 로컬 Gemma/Qwen 안정성 | 중 | Llama fallback, Claude Haiku 대체 |
| JSON 출력 일관성 | 중 | parser + fallback + uncertain 경로 |
| 한국어 품질 편차 | 중 | 루브릭 사전 작성, 반복 |
| 골든 셋 50건 작성 부담 | 중 | W11 집중 작업, 카테고리별 5건씩 분배 |
| watchlist 평가 ground truth 부재 | 중 | 합성 시나리오 + 루브릭 |
| 시간 부족 | 중 | 1차 목표 우선, 2차 목표 ablation 범위 축소 가능 |

---

## 9. 기대 결과물

- **소스코드** (GitHub, 커밋 이력)
- **재현 가능 실험 스크립트**
- **end-to-end 파이프라인** (CLI 단일 커맨드)
- **샘플 HTML 리포트** (이벤트 5-10건, Batch Summary 1-2건)
- **Attack Surface Brief 샘플** 1-2건
- **Watchlist 샘플** 2-3개 (갱신 주기별 전략 변화)
- **prompts/CHANGELOG.md** (프롬프트 버전 이력 + 변경 근거)
- **ablation 평가 결과 표**
- **최종 발표 자료 + 데모 영상** (라이브 시연 포함)
- **README.md** (과제 요구: 프로젝트 개요, AI 도구 활용 전략, 트러블슈팅 로그)

---

## 10. Future Work

### 10.1 단기 확장 (확장성 인터페이스 활용)
- 새 LLM Provider 추가 (Gemini, Llama 4 등 출시 모델)
- Ensemble Detector (XGBoost + LightGBM 조합)
- 외부 위협 인텔 통합 (GreyNoise, AbuseIPDB, MISP)
- CMDB 연동 자산 카탈로그

### 10.2 중기 확장
- Streamlit 대시보드
- RAG 기반 실시간 CVE/ATT&CK 조회
- 자산 카탈로그 CRUD UI (웹/API)
- 실제 UTM syslog 직접 입력 지원
- Slack/Email 리포트 채널

### 10.3 장기 연구
- 조직 특화 ML 베이스라인 자동 drift 감지
- 다단계 공격 ground truth 데이터셋 확보 시 Tier 2 kill chain 정량 평가
- 한국어 리포트 LoRA 파인튜닝
- Tier 2 자기 피드백 루프의 meta-learning화
- 실제 소규모 조직 파일럿 운영

---

## 부록 A. 제안 발표 10분 구성

| 시간 | 섹션 | 핵심 메시지 |
|---|---|---|
| 0:45 | **Mythos 오프닝** | "2026년 4월, 방어의 시간 축이 무너졌다. Glasswing 밖 소규모 조직은?" |
| 0:45 | 문제 정의 | 방어 비대칭 + ML 이분법 + 비전문가 |
| 1:30 | 실증 결과 | 3-데이터셋 비교 + 카테고리별 F1 격차 |
| 2:00 | 제안 아키텍처 | **2티어 LLM 다이어그램**. 메타 프롬프트 메커니즘 |
| 1:00 | Watchlist & Contexts 시연 프레임 | CVE 주입 시뮬 (실제 시연은 최종) |
| 0:30 | 확장성 | Plug-in 구조, 새 LLM/ML/위협 소스 등록 가능 |
| 0:30 | 차별점 | ML only, 단일 LLM, 상용 XDR, Glasswing과의 비교 |
| 0:45 | **평가 metric 3차 구조** | 작동성 → 컴포넌트 기여 → 시연. 골든 셋 + ablation |
| 0:30 | 수행 계획 | 단계별 + 리스크 |
| 1:15 | Q&A | |

---

## 부록 B. 예상 Q&A

**Q1. Mythos 서사 사실인가?**
A. 사실. 2026년 4월 Anthropic 공식 발표. AISI·CFR·Fortune 등 보도. IMF/세계은행 봄 회의에서 논의됨.

**Q2. 프론티어 API 비용 부담은?**
A. Tier 2 주 1회 배치, 월 1-5만원. 엔터프라이즈 XDR(월 수천 달러) 대비 1% 미만.

**Q3. Tier 2 watchlist 틀리면?**
A. 피드백 루프(자기 평가) + Tier 1 자체 판정 보존(매칭 미여부와 무관하게 자체 판단).

**Q4. 같은 피처에 모델만 바꾼다고 더 잘 판정?**
A. 아니다. 본 시스템 LLM은 Tier 2가 정리한 **Watchlist & Contexts**를 상속한다. 원천 자산·CVE·위협 인텔을 Tier 1에 그대로 밀어 넣는 것이 아니라, 프론티어 모델이 선별한 최신 판단 지침을 경량 모델이 참조한다.

**Q5. 정확도 향상 N% 같은 깔끔한 수치 있나?**
A. 1차 목표가 정확도가 아니라 **파이프라인 구축**. 2차 목표(컴포넌트 기여)는 ablation으로 측정. 데이터셋이 컨텍스트 평가에 부적합하다는 한계 인정. 정량 수치 + 정성 루브릭 + 시연 3축으로 평가.

**Q6. ML F1 0.97인데 LLM 필요한가?**
A. 카테고리별 극단적 편차. Infiltration 0.45, SlowHTTPTest 0.00. 저성능 영역에서 Tier 2가 만든 Batch Loop watchlist와 brief context를 참조해 판정하는 게 LLM 역할.

**Q7. 단일 LLM으로 안 되나?**
A. 시간 지평이 다른 두 문제를 푼다. 실시간 수천 플로우 = 비용 폭발, 조직 전체 통합 추론 = 7B 한계.

**Q8. 데이터셋 2018 오래된 것 아닌가?**
A. NetFlow 피처 공간은 실 UTM 출력과 동형. 본 기여는 공격 유형 탐지가 아닌 **방어 지식 활용 구조**.

**Q9. watchlist 메커니즘 새로움?**
A. SIEM correlation rule은 **정적**. 본 시스템은 프론티어 LLM이 **매 주기 새로 추론**. Post-Mythos 시간 단위 공격 환경 대응.

**Q10. 확장성 주장 근거?**
A. 5개 추상 인터페이스(LLMProvider, MLDetector, ThreatSource, AssetSource, ReportRenderer) 정의. 각 인터페이스의 첫 구현체가 MVP. 새 컴포넌트 추가는 클래스 등록만으로 가능.

**Q11. 프롬프트 엔지니어링 어떻게 평가?**
A. `prompts/CHANGELOG.md`에 버전별 변경 근거 기록. 골든 셋 50건에 대한 버전별 정답 일치율 측정. **메타 프롬프트(LLM이 LLM 입력 생성)** 측면이 본 시스템의 고유 기여.

---

## 부록 C. Tier 2 산출물 주입 A/B 시연

(v3와 동일 — 단계별 4 Step 시연 시나리오. 분량상 생략)

---

## 부록 D. 시스템 데이터 흐름도

(v3와 동일 — ASCII 다이어그램. 발표에서는 슬라이드용 그림으로 재작성)

---

## 부록 E. 사전 작동성 확인 (PoC 결과)

> **W9 제안 발표 직전 수행한 미니 PoC 결과**.
> Tier 2 watchlist 1건 생성 + Tier 1 시뮬 5건 처리.
>
> [발표 전 결과 채워 넣을 자리]

**확인 항목**:
- [ ] Tier 2 (Opus급)가 확정된 후보 입력으로 합리적 Watchlist & Contexts 생성
- [ ] Tier 1 (7B 또는 Haiku)이 플로우/ML/운영 이력 + Tier 2 Watchlist & Contexts를 받아 일관된 JSON 출력
- [ ] 5건 시나리오 중 N건 사전 정의 정답과 일치
- [ ] watchlist 매칭 시 자동 Alert 격상 작동

**예상 결과**: 5건 중 3-5건 정답 일치. Tier 2 watchlist 합리성 4-5점 (5점 만점).

---

*문서 작성 시점: 2026-04-21*
*v3에서 v4로의 개정은 (1) 1차 목표를 "파이프라인 구축"으로 재정의, (2) 평가 3차 구조 도입, (3) 확장성 인터페이스 명시, (4) 프롬프트 엔지니어링 전략 명문화를 반영한 것이다.*
