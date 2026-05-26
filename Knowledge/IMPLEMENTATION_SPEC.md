# Self LLM SOC — 구현 작업 명세서

> AI Coding IDE(Cursor, Claude Code, Copilot 등)에서 작업을 진행할 때 참조하는 마스터 문서.

---

## 진행 기록

### 2026-05-10 Tier 2 trigger quality and Tier 1 recall pass

- Watchlist schema now treats `alert_when` and `likely_benign_when` as first-class
  Tier 2 artifact fields. The Tier 2 prompt no longer conflicts with itself by
  asking for those fields while forbidding them in the allowed-key list.
- Added a Tier 2 watchlist quality step after parsing and before writing:
  `enhance_watchlist_quality()` preserves guidance fields, adds source-backed
  observable hints for weak P1 items when possible, and leaves unresolved weak
  P1 items to be marked `context_only` by the linter.
- Strong watchlist triggers are `behavior`, `threat_source`, and
  `policy_violation`. Scope-only matches (`asset_only`, `asset_service`) do not
  lower the review threshold.
- `SourceActivitySummary` is now structured in the Tier 1 prompt payload:
  flow count, distinct destinations, top ports, recent verdicts,
  same-source/same-destination counters, watchlist-hit count, and recent alert
  count are included. Tier 1 still receives no raw policy/assets/CVE/threat-feed
  YAML.
- The realtime matcher can evaluate source-activity hints and CIDR-style source
  policy hints, enabling Tier 2-curated patterns such as repeated VPN access,
  unauthorized DB access, workstation-to-backup SMB, and jumpbox SSH/RDP probes.

### 2026-05-04 Gemini Tier 2 provider

- Added `GeminiProvider` for the Tier 2 Batch Loop only. The default API model is
  `gemini-3.5-flash`; a Pro model string can be supplied later through
  `tier2.model`, but Flash is the intended cost-controlled path for now.
- Gemini API keys are read first from
  `26_AISecApp_Project_GEMINI_API_KEY`, with `GEMINI_API_KEY` and
  `GOOGLE_API_KEY` retained as fallbacks.
- The provider uses the official Gemini `generateContent` REST API shape with
  `system_instruction`, `contents`, and `generationConfig`. When
  `response_format: json`, it requests `responseMimeType: application/json`.
- This does not change the source boundary: Tier 2 receives source snapshots and
  writes curated watchlist, brief, and memory artifacts. Tier 1 still never
  receives raw asset/CVE/policy/threat-feed dumps.

### 2026-05-01 Real Time Loop hardening before Tier 2 work

Fixed Batch Loop source provider contract:

```text
Tier2InputCollector
  -> AssetInfoProvider
  -> PolicyInfoProvider
  -> CveInfoProvider
  -> ThreatInfoProvider
```

Future sessions must treat this as a settled implementation decision. MVP
implementations are YAML-backed providers for `config/assets.example.yaml`,
`config/policy.example.yaml`, `config/cve_feed.example.yaml`, and
`config/threat_feed.example.yaml`. Later DB/API providers must implement the
same contract.

Providers return a source snapshot:

```text
name: assets | policy | cve_feed | threat_feed | feedback | ...
status: used | missing | disabled | error
source_type: yaml | db | api
path_or_uri: file path, DB key, or API identifier
item_count: loaded record/rule count
content: normalized source payload
error: optional load/parse/fetch error text
```

Status metadata is required. It lets Tier 2 distinguish a real empty source
from a missing, disabled, or broken source. Tier 2 prompt builders include
content from `used` snapshots and include a compact status summary for every
configured source. Tier 2 outputs preserve this status summary, especially in
watchlist YAML. Tier 1 never reads these raw sources. `tier2_runs` persistence
and a formal Tier 2 DB summary contract are Batch Loop implementation work, not
Real Time Loop cleanup work.

- The default runtime path now uses the trained XGBoost binary router and queue
  mode against `data/sample/xgb_route_sample.csv`; fake Tier 1 remains the
  deterministic default provider for tests and laptop handoff.
- The optional multiclass XGBoost model is an attack-family hint only. It is
  evaluated after binary routing for `auto_alert` and `tier1_llm` evidence, and
  it never changes route selection.
- SHAP top5 remains limited to `tier1_llm` events so cheap `auto_dismiss` and
  `auto_alert` paths stay cheap.
- Tier 1 JSON is now schema-gated: only `benign|alert|uncertain` verdicts and
  `low|medium|high|critical` severities are accepted. Invalid JSON or invalid
  schema becomes an `uncertain/medium` LLM fallback.
- Tier 1 provider metadata now flows into storage: model name, latency, and
  token count are saved in `tier1_calls` when the provider returns them.
- This is the intended handoff point for Batch Loop work: Tier 2 should read
  SQLite history plus enabled organization/security inputs and produce curated
  watchlist/context artifacts, not raw context dumps for Tier 1.

### 2026-04-26 — Phase 1 scaffold and Docker baseline

- 발표자료의 Batch Loop / Real Time Loop 구조를 기준으로 프로젝트 뼈대를 생성했다.
- Docker 기반 Python 3.11 실행 환경을 추가해 노트북 이동 후에도 같은 명령으로 재현 가능하게 했다.
- Fake Tier 2가 `watchlist`, `brief`, `memory` 산출물을 만들고, Dummy ML + Fake Tier 1이 샘플 flow를 처리하는 end-to-end smoke path를 만들었다.
- `Knowledge/PROJECT_STRUCTURE.md`에 폴더 역할과 ASCII 구조도를 추가했다.
- 현재 검증 기준: `docker compose run --rm app python -m pytest` 통과.

---

## 0. 프로젝트 컨텍스트

**한 줄 요약**: ML + 2티어 LLM 기반 소규모 조직용 네트워크 보안 트리아지 파이프라인. Tier 2 (프론티어 LLM)가 Tier 1이 사용할 **Watchlist & Contexts** 파일을 생성하고, Tier 1 (경량 LLM)은 플로우/ML 근거와 이 파일을 함께 받아 실시간 플로우를 판정한다.

**핵심 설계 원칙**:
- ML 정확도 향상은 목표가 아니다. 1차 목표는 **end-to-end 파이프라인 작동성**.
- Tier 1은 원천 자산·CVE·위협 인텔·정책을 전부 직접 읽지 않는다. Tier 2가 큐레이션한 **Watchlist & Contexts**를 우선 참조한다.
- 모든 외부 의존성은 추상 인터페이스 뒤에 둔다. plug-in 가능해야 한다.
- 발표본이 proposal 문서보다 우선한다. proposal은 배경/발표용 서사가 많으므로, 구현자는 이 `IMPLEMENTATION_SPEC.md`를 1차 기준으로 삼는다.

**아직 미확정인 것**:
- Tier 2에 실제로 넣을 원천 입력 목록은 확정 전이다. 후보는 `assets.yaml`, `policy.yaml`, `cve_feed.yaml`, `threat_feed.yaml`, Tier 1 판정 DB, 이전 watchlist hit/miss, QA 샘플 결과다.
- 따라서 Tier 2 입력 수집기는 모듈식으로 만들고, 특정 입력이 없거나 비활성화되어도 배치가 돌도록 한다.
- Tier 1 입력은 확정에 가깝다: `Flow summary + ML/SHAP + 운영 이력 + Tier 2 Watchlist & Contexts`.

**산출 환경**:
- Python 3.11+
- 로컬 GPU: RTX 5060 Ti 16GB
- OS: Windows (WSL 또는 native)
- AI 코딩 IDE 적극 활용 (commit history가 평가 대상)

---

## 1. 리포지토리 구조

```
mini-llm-soc/
├── README.md
├── pyproject.toml
├── .gitignore
├── config/
│   ├── settings.example.yaml         # 모델 선택, 임계치 등
│   ├── assets.example.yaml           # 자산 카탈로그 샘플
│   ├── threat_feed.example.yaml      # 위협 인텔 샘플
│   ├── cve_feed.example.yaml         # CVE 공지 샘플
│   └── policy.example.yaml           # 정책 샘플
├── data/
│   └── .gitkeep                      # 데이터셋은 .gitignore. 처리된 결과만
├── src/
│   ├── soc/
│   │   ├── __init__.py
│   │   ├── ml/                       # ML 탐지 레이어
│   │   ├── context/                  # 컨텍스트 집계 레이어
│   │   ├── llm/                      # LLM 추상화 + Tier 1/2 구현
│   │   ├── routing/                  # ML 결과 → 분기 로직
│   │   ├── threat/                   # 위협 인텔 소스
│   │   ├── asset/                    # 자산 카탈로그 소스
│   │   ├── report/                   # HTML 리포트 생성
│   │   ├── storage/                  # SQLite DB 추상화
│   │   ├── tier2/                    # Tier 2 배치 작업
│   │   └── cli/                      # 진입점
├── prompts/
│   ├── tier1_system.md               # Tier 1 system prompt
│   ├── tier2_system.md               # Tier 2 system prompt
│   ├── CHANGELOG.md                  # 프롬프트 버전 이력 (평가 대상!)
│   └── archive/                      # 이전 버전들
├── test_cases/
│   ├── README.md                     # test case 작성 규칙
│   ├── case_A_*.yaml                 # 명백 공격 (15건)
│   ├── case_B_*.yaml                 # 명백 정상 (15건)
│   ├── case_C_*.yaml                 # 컨텍스트 의존 (10건)
│   └── case_D_*.yaml                 # ML 약점 영역 (10건)
├── tests/
│   ├── unit/
│   ├── integration/
│   └── ablation/                     # ablation 평가 스크립트
├── scripts/
│   ├── ml_train.py                   # XGBoost 학습
│   ├── ml_evaluate.py                # 모델 평가
│   ├── tier2_batch.py                # Tier 2 중요 자산/위협 업데이트 또는 일정 주기 배치 실행
│   ├── pipeline_run.py               # end-to-end 실행
│   └── ablation_run.py               # ablation 평가
├── notebooks/
│   ├── 01_eda.ipynb
│   ├── 02_ml_training.ipynb
│   └── 03_evaluation.ipynb
└── output/
    ├── reports/                      # HTML 리포트 출력
    ├── watchlists/                   # 실행 주기별 watchlist
    ├── briefs/                       # 실행 주기별 brief context
    └── memory/                       # Tier 2 누적 기억
```

### 1.1 구현상 소스 오브 트루스

- `Knowledge/IMPLEMENTATION_SPEC.md`: 구현 기준 문서. 이후 작업자는 이 파일만 보고 작업 가능해야 한다.
- `Knowledge/Project_Proposal_v4.md`: 발표/제안 논리. 구현 기준과 충돌하면 본 문서가 우선한다.
- `Knowledge/AISecApp Proposal.pptx`: 발표본. 아키텍처 표현은 PPTX가 proposal보다 우선한다.

### 1.2 핵심 파일 산출물 계약

Tier 2는 Tier 1이 읽을 수 있는 파일을 생성한다. MVP에서는 최신 파일을 복사본으로 유지한다. Windows 환경을 고려해 symlink에 의존하지 않는다.

```
output/
├── watchlists/
│   ├── watchlist_20260505T090000.yaml
│   └── latest.yaml
├── briefs/
│   ├── brief_context_20260505T090000.md
│   └── latest.md
└── memory/
    ├── attack_surface_memory_20260505T090000.md
    └── latest.md
```

`latest.*` 파일은 Tier 1 파이프라인의 기본 입력이다. 실행 주기별 파일은 평가와 시연용 버전 이력이다.

---

## 2. 추상화 인터페이스 정의

본 프로젝트의 확장성 핵심. 5개 인터페이스를 가장 먼저 만든다.

### 2.1 LLMProvider (`src/soc/llm/provider.py`)

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class LLMResponse:
    content: str
    tokens_used: int
    model_name: str
    latency_ms: float

class LLMProvider(ABC):
    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,  # Tier 1 default; Tier 2 passes its own larger cap
        temperature: float = 0.3,
        response_format: str = "text"  # or "json"
    ) -> LLMResponse: ...

class OllamaProvider(LLMProvider): ...      # 로컬 (Tier 1)
class GeminiProvider(LLMProvider): ...      # API-backed Tier 2 Flash/Pro
class ClaudeAPIProvider(LLMProvider): ...   # 프론티어 (Tier 2)
class OpenAIProvider(LLMProvider): ...      # 대체
```

설정으로 선택:
```yaml
tier1:
  llm:
    provider: "ollama"
    model: "gemma:7b"
    max_tokens: 4096
    retry_attempts: 1
    retry_backoff_seconds: 2
tier2:
  provider: "gemini"
  model: "gemini-3.5-flash"
  gemini_api_key_env: "26_AISecApp_Project_GEMINI_API_KEY"
```

Tier 1 retries only transient provider/API failures such as timeout, connection
reset, HTTP 429, and HTTP 5xx. It does not retry `finishReason=MAX_TOKENS`;
increase `tier1.llm.max_tokens` for that case.

### 2.2 MLDetector (`src/soc/ml/detector.py`)

```python
@dataclass
class MLResult:
    prob: float  # 이진 분류 확률
    category_hint: str  # 다중 분류 카테고리 추정
    category_confidence: float
    shap_top5: list[tuple[str, float, float]]  # (feature, value, contribution)

class MLDetector(ABC):
    @abstractmethod
    def predict(self, flow_features: dict) -> MLResult: ...
    @abstractmethod
    def explain(self, flow_features: dict) -> list: ...

class XGBoostDetector(MLDetector): ...
```

### 2.3 ThreatSource (`src/soc/threat/source.py`)

```python
@dataclass
class ThreatInfo:
    is_known_malicious: bool
    tags: list[str]
    advisories: list[dict]  # CVE, 업계 공지 등

class ThreatSource(ABC):
    @abstractmethod
    def lookup_ip(self, ip: str) -> ThreatInfo: ...
    @abstractmethod
    def get_recent_advisories(self, since_days: int = 7) -> list[dict]: ...

class StaticYAMLThreatSource(ThreatSource): ...   # MVP
# 향후: GreyNoiseThreatSource, AbuseIPDBThreatSource
```

### 2.4 AssetSource (`src/soc/asset/source.py`)

```python
@dataclass
class AssetInfo:
    ip: str
    role: str
    services: list[str]
    criticality: str  # low/medium/high
    rationale: str
    found: bool  # 매칭 자체가 됐는지

class AssetSource(ABC):
    @abstractmethod
    def lookup(self, ip: str) -> AssetInfo: ...
    @abstractmethod
    def get_zone(self, ip: str) -> str: ...

class StaticYAMLAssetSource(AssetSource): ...
```

### 2.5 ReportRenderer (`src/soc/report/renderer.py`)

```python
class ReportRenderer(ABC):
    @abstractmethod
    def render_event(self, event: dict, output_path: str) -> None: ...
    @abstractmethod
    def render_summary(self, summary_data: dict, output_path: str) -> None: ...

class HTMLRenderer(ReportRenderer): ...   # MVP, Jinja2 + Chart.js
```

---

## 3. 핵심 데이터 모델

### 3.1 Flow

```python
@dataclass
class Flow:
    flow_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    features: dict  # NetFlow 43+ 피처
    raw_label: str | None = None  # 평가용, 운영시엔 None
```

### 3.2 Verdict (Tier 1 LLM 출력)

```python
@dataclass
class Verdict:
    verdict: str  # benign / alert / uncertain
    severity: str  # low / medium / high / critical
    rationale_ko: str
    recommended_action_ko: str
    watchlist_matched: str | None
    confidence: float  # LLM 자신감
```

### 3.3 Tier2Output

```python
@dataclass
class Tier2Output:
    cycle_id: str  # "20260505T090000+0900"
    watchlist: dict  # watchlist.yaml 구조
    brief_context: str  # brief_context.md 텍스트
    attack_surface_memory: str  # attack_surface_memory.md 텍스트
    summary_html: str  # 실행 주기 요약 HTML
    metadata: dict  # 토큰, 비용, 모델
```

### 3.4 Tier1Input (Tier 1 프롬프트 조립 단위)

Tier 1에는 원천 컨텍스트를 층층이 전부 넣지 않는다. 다음 구조를 만들어 프롬프트 렌더러에 전달한다.

```python
@dataclass
class FlowSummary:
    flow_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration_ms: float | None
    bytes_in: int | None
    bytes_out: int | None
    packets_in: int | None
    packets_out: int | None

@dataclass
class SourceActivitySummary:
    window_minutes: int
    flow_count: int
    distinct_dst_count: int
    top_dst_ports: list[int]
    recent_verdicts: list[str]  # 예: ["benign", "uncertain", "alert"]
    summary_ko: str
    same_src_same_dst_count: int
    same_src_same_dst_port_count: int
    watchlist_hit_count: int
    recent_alert_count: int

@dataclass
class WatchlistMatch:
    matched: bool
    priority: str | None  # priority_1 / priority_2 / priority_3
    item_id: str | None
    reason: str | None
    matched_conditions: list[str]
    scope_conditions: list[str]
    matched_trigger_hints: list[str]
    unmatched_trigger_hints: list[str]
    matched_benign_hints: list[str]
    trigger_completeness: str  # none / scope_only / partial / required_met / strong
    alert_when: list[str]
    likely_benign_when: list[str]
    match_strength: str  # asset_only / asset_service / behavior / threat_source / policy_violation
    context_only: bool
    escalation_hint: str | None
    routing_policy: dict | None

@dataclass
class Tier1Input:
    flow: FlowSummary
    ml: MLResult
    source_activity: SourceActivitySummary
    watchlist_match: WatchlistMatch
    brief_context_excerpt: str  # Tier 2 brief에서 이번 플로우와 관련된 짧은 발췌/요약
```

### 3.5 RouteDecision

라우터는 모든 플로우에 대해 분기 결과를 남긴다.

```python
@dataclass
class RouteDecision:
    route: str  # auto_dismiss / auto_alert / tier1_llm
    reason: str
    threshold_low: float
    threshold_high: float
    adjusted_by_watchlist: bool
    ml_prob: float
    effective_review_threshold: float | None
    dynamic_threshold_applied: bool
    dynamic_threshold_reason: str | None
```

기본 임계치:
- `prob < 0.30`: `auto_dismiss`
- `prob > 0.95`: `auto_alert`
- 그 외: `tier1_llm`

watchlist `priority_1` 매칭 시 MVP 정책:
- `auto_dismiss` 하한을 낮추지 않는다. 너무 낮은 확률은 여전히 자동 기각할 수 있다.
- Tier 1 진입 임계는 완화한다. 예: `priority_1_llm_threshold = 0.20`
- `prob >= 0.20`이고 `priority_1` 매칭이면 `tier1_llm` 또는 정책상 `auto_alert`로 격상 가능하게 구현한다. 기본값은 `tier1_llm`이다.

Dynamic review-threshold layer:
- Global ML thresholds stay unchanged: `threshold_low=0.30`, `threshold_high=0.95`.
- Tier 2 may add `routing_policy` to a priority_1 watchlist item when source-backed evidence says a low-score but strongly matched flow should still be reviewed.
- MVP allows only `action: tier1_llm`; this layer never creates `auto_alert`.
- `review_threshold` is valid only from `0.04` through the global low threshold. Invalid policies are ignored and linted.
- Dynamic threshold drops apply only when the watchlist trigger is complete
  (`required_met` or `strong`). Scope-only and partial matches keep the normal
  ML review boundary and pass their unmatched trigger hints / benign hints to
  Tier 1 if they are reviewed for another reason.
- Dynamic thresholding applies only to complete machine-readable review matches:
  `review_candidate`, `behavioral_review`, `behavior`, `threat_source`,
  `policy_violation`, or `critical_forbidden` with `trigger_completeness`
  `required_met` or `strong`. `asset_only`, `asset_service`, `context_only`,
  `scope_only`, and `partial` matches do not lower the review threshold.
- Route decisions persist `effective_review_threshold`, `dynamic_threshold_applied`, and `dynamic_threshold_reason` for reports and evaluation metrics.

### 3.6 Watchlist YAML 최소 스키마

Tier 2가 생성하는 YAML은 사람이 읽을 수 있어야 하고, parser가 실패해도 fallback 가능해야 한다.

```yaml
watchlist_version: "20260505T090000+0900"
generated_at: "2026-04-21T09:00:00+09:00"
valid_until: "2026-04-27T23:59:59+09:00"
generated_by: "claude-opus-4-7"
source_status:
  assets: "used"          # used / missing / disabled
  cve_feed: "used"
  threat_feed: "used"
  policy: "used"
priority_1:
  - id: "P1-20260505T0900000900-001"
    target_assets:
      - ip: "172.31.69.28"
        role: "web-application-server"
    reason: "Apache RCE 영향 가능성과 외부 접근 증가"
    detection_hints:
      - field: "dst_port"
        operator: "in"
        value: [80, 443]
      - field: "src_zone"
        operator: "eq"
        value: "external-unknown"
    routing_policy:
      review_threshold: 0.10
      max_threshold_drop: 0.20
      action: "tier1_llm"
      reason: "Tier 2 source-backed low-score review"
    escalation_rule: "prob >= 0.20이면 Tier 1 LLM으로 보냄"
priority_2: []
priority_3: []
```

MVP parser 요구사항:
- `priority_1/2/3`가 없으면 빈 리스트로 처리한다.
- `detection_hints`가 구조화되어 있지 않거나 문자열이면 warning 후 사람이 읽는 근거로만 보관한다.
- YAML 파싱 실패 시 `empty watchlist`로 계속 실행하고 에러를 `tier2_runs` 또는 로그에 남긴다.

### 3.7 Brief Context 최소 형식

`brief_context.md`는 Tier 1 프롬프트에 그대로 전체 주입하지 않는다. MVP에서는 최대 글자 수를 제한해 앞부분 또는 관련 watchlist item 주변 문단만 사용한다.

권장 섹션:
- `조직 현황 요약`
- `이번 실행 주기 주의 자산`
- `이번 실행 주기 주의 외부 대역/위협`
- `Tier 1 판정 지침`

Tier 1 프롬프트 조립 시 기본 제한:
- `brief_context_excerpt_max_chars = 1200`
- watchlist 매칭이 있으면 해당 item의 reason과 brief excerpt를 함께 제공
- 매칭이 없으면 일반 지침 요약만 제공

---

## 4. 작업 단위 (Task Breakdown)

### Phase 1: 기반 (W10 전반)

**Task 1.1: 리포지토리 초기화**
- pyproject.toml, .gitignore, README.md 초안
- 폴더 구조 생성
- 첫 커밋: "Initial project structure"

**Task 1.2: 설정 시스템**
- `config/settings.yaml` 로더 (pydantic 권장)
- `.example` 파일들 작성
- 환경 변수로 API 키 (`ANTHROPIC_API_KEY`)

**Task 1.3: 추상화 인터페이스 정의**
- 위 5개 ABC 클래스 작성 (구현 없이)
- 데이터 모델 정의
- import 가능 확인

### Phase 2: ML 레이어 (W10 후반)

**Task 2.1: 데이터셋 로더**
- NF-CIC-IDS-2018-v3 parquet/csv 로딩
- 피처 정제 (TTL 등 아티팩트 제외 옵션)
- stratified train/test split

**Task 2.2: XGBoost 학습 스크립트**
- `scripts/ml_train.py`
- GPU 사용 (`device='cuda'`)
- 모델 저장 (`output/models/xgb_v1.json`)
- 학습 메트릭 로깅

**Task 2.3: SHAP 통합**
- TreeSHAP으로 explainer 생성
- predict + explain 통합 인터페이스
- `XGBoostDetector` 구현

**Task 2.4: 라우팅 로직**
- prob < 0.30 → AUTO_DISMISS
- prob > 0.95 → AUTO_ALERT (템플릿)
- 그 외 → Tier 1 LLM
- Watchlist priority_1 매칭 시 임계 하향 적용

### Phase 3: 컨텍스트 + 자산 + 위협 레이어 (W11)

**Task 3.1: 자산 카탈로그**
- `StaticYAMLAssetSource` 구현
- IP/CIDR 매칭 (정확 매칭 → CIDR fallback)
- port_based_roles 보조 매칭

**Task 3.2: 위협 인텔**
- `StaticYAMLThreatSource` 구현
- known_malicious_ips 매칭
- custom_threat_context 로딩

**Task 3.3: 정책 평가**
- 업무 시간 판정
- elevated_risk_rules 평가
- asset_specific_policies 매칭

**Task 3.4: 직전 판정 이력 조회**
- SQLite에서 같은 src_ip 최근 N분 판정 조회
- 자연어 요약 생성

### Phase 4: Tier 1 LLM (W11 후반 ~ W12 전반)

**Task 4.1: OllamaProvider 구현**
- HTTP 호출 (Ollama API)
- JSON 응답 파싱 + fallback
- 지연 시간 측정

**Task 4.2: Tier 1 system prompt v1**
- `prompts/tier1_system.md` 초안 작성
- 입력: 플로우 + ML + Watchlist + Brief Context
- 출력 스키마: Verdict JSON

**Task 4.3: Tier 1 호출 파이프라인**
- 라우팅에서 LLM 경로 진입 시 호출
- 결과를 DB에 저장
- 실패 시 fallback (uncertain 판정)

**Task 4.4: 골든 셋 시뮬레이션**
- test case 5건으로 Tier 1 동작 확인
- JSON 파싱 일관성 측정

### Phase 5: Tier 2 LLM (W12)

**Task 5.1: ClaudeAPIProvider 구현**
- anthropic SDK 사용
- 에러 처리, 재시도 로직
- 토큰 카운트 + 비용 계산

**Task 5.2: Tier 2 system prompt v1**
- `prompts/tier2_system.md` 작성
- 입력: 확정된 Tier 2 후보 입력들. 현재 후보는 자산, CVE, 위협 인텔, 정책, 이전 메모리, Tier 1 통계이며 최종 조합은 미확정
- 출력: 3개 산출물 (watchlist, brief_context, memory). 이 중 watchlist와 brief_context가 Tier 1에 주입되는 핵심 파일

**Task 5.3: Tier 2 배치 실행기**
- `scripts/tier2_batch.py`
- 입력 수집 → 프롬프트 조립 → API 호출 → 출력 분리/저장
- 결과를 `output/watchlists/`, `output/briefs/`, `output/memory/`에 저장

**Task 5.4: Watchlist 파서**
- 생성된 yaml을 라우팅 레이어가 사용 가능한 형태로 로드
- priority_1/2/3 매칭 함수 구현

### Phase 6: 통합 (W12 후반)

**Task 6.1: end-to-end CLI**
- `scripts/pipeline_run.py --input flows.csv --output reports/`
- 플로우 입력 → ML → 라우팅 → Tier 1 → 리포트
- 진행 상황 출력

**Task 6.2: HTML 리포트 생성**
- Jinja2 템플릿 (이벤트, 실행 주기 요약)
- Chart.js 차트 (시간대 분포, 카테고리 분포)
- 한국어 출력

**Task 6.3: SQLite 저장소**
- 스키마: flows, verdicts, tier1_calls, tier2_runs
- 마이그레이션 스크립트
- 조회 함수들

**Task 6.4: MVP 데모 — W12 발표용**
- 샘플 입력으로 전체 파이프라인 실행
- 샘플 HTML 리포트 5개 + 실행 주기 Summary 1개 생성
- Watchlist + Brief Context + Memory 샘플 1실행 주기 생성

### Phase 7: 평가 (W13)

**Task 7.1: Test case 50건 작성**
- `test_cases/` 디렉토리에 카테고리별 yaml
- 작성 규칙 README
- 각 case에 expected_verdict + scoring_rubric

**Task 7.2: Ablation 평가 스크립트**
- 기본 5개 구성 (A: ML only, B: +Tier1, C: +Watchlist, D: +Context, E: +Memory) + 비용 검증용 `tier1_only_raw_context` baseline
- 각 구성에서 50건 처리 → 일치율 계산
- 결과 표로 출력

**Task 7.3: QA 샘플링**
- AUTO_DISMISS의 10% 무작위 샘플
- Tier 2가 재판정
- 반전율 측정

**Task 7.4: 정성 루브릭 평가**
- 50건 샘플의 한국어 리포트
- 4개 항목 1-5점 평가 시트

### Phase 8: 마무리 (W14-15)

**Task 8.1: 프롬프트 튜닝 (v2-v5)**
- 평가 결과 기반 개선
- 각 변경을 `prompts/CHANGELOG.md`에 commit message와 함께
- 버전별 일치율 추적

**Task 8.2: Tier 2 Attack Surface Brief 시연 데이터**
- 가상 시나리오 시계열 데이터 작성
- 2-3실행 주기의 Tier 2 메모리 진화 보여주기

**Task 8.3: 시연 시나리오 준비**
- Tier 2 산출물 단계별 주입 시연 (Step 1-4)
- CVE 주입 전후 A/B
- Watchlist 활성/비활성 비교

**Task 8.4: 데모 영상 + 최종 발표**
- 화면 녹화 영상 (5-10분)
- 슬라이드 업데이트 (실증 결과 반영)
- 라이브 데모 리허설

### 4.1 MVP 구현 상세 기준

아래 기준은 이후 작업자가 proposal을 다시 읽지 않아도 구현할 수 있도록 적은 구체 계약이다.

#### Phase 1 상세: 프로젝트 뼈대

필수 파일:
- `pyproject.toml`: Python 3.11+, `src` layout, pytest 설정.
- `.gitignore`: `Dataset/`, `data/raw/`, `output/`, `.venv/`, `__pycache__/`, 모델 파일 기본 제외. 단, `output/.gitkeep`류는 허용.
- `README.md`: 프로젝트 개요, 실행 방법, AI 도구 활용 전략, 트러블슈팅 로그 placeholder.
- `config/*.example.yaml`: 실제 키/대용량 데이터 없이 실행 가능한 샘플.

권장 의존성:
- Runtime: `pydantic`, `pydantic-settings`, `pyyaml`, `jinja2`, `httpx`, `rich`, `typer`
- ML: `pandas`, `scikit-learn`, `xgboost`, `shap`, `pyarrow`
- LLM API: `anthropic`는 optional extra로 둔다. API 키가 없어도 unit test는 돌아야 한다.

검증:
- `python -m pytest`가 import error 없이 시작되어야 한다.
- `python -m soc.cli --help` 또는 최종 CLI entrypoint help가 출력되어야 한다.

#### Phase 2 상세: ML 레이어와 라우팅

MVP 구현 순서:
1. `src/soc/models.py`에 공통 dataclass를 둔다. 순환 import를 피한다.
2. `src/soc/ml/detector.py`에 `MLDetector`, `MLResult`, `DummyDetector`, `XGBoostDetector`를 둔다.
3. 실제 모델 파일이 없을 때도 파이프라인을 검증할 수 있도록 `DummyDetector`를 먼저 구현한다.
4. `src/soc/routing/router.py`는 `MLResult`, `WatchlistMatch`, 설정 임계치를 받아 `RouteDecision`을 반환한다.

`DummyDetector` 정책:
- `features["mock_prob"]`가 있으면 그 값을 사용.
- 없으면 `0.5`를 반환해 Tier 1 경로를 테스트하기 쉽게 한다.

`XGBoostDetector` 정책:
- 모델 파일 경로는 config에서 받는다.
- 모델 파일이 없으면 명확한 에러를 내되, CLI에는 `--detector dummy` 옵션을 둬 end-to-end smoke test가 가능해야 한다.
- SHAP이 실패하면 `shap_top5=[]`로 두고 warning을 남긴다. 파이프라인을 죽이지 않는다.

#### Phase 3 상세: Tier 1 입력 조립

구현 대상:
- `src/soc/context/activity.py`: SQLite 또는 in-memory 저장소에서 출발지 최근 활동 요약.
- `src/soc/tier2/watchlist.py`: `latest.yaml` 로드, 파싱, 매칭.
- `src/soc/context/tier1_builder.py`: `Flow + MLResult + SourceActivitySummary + WatchlistMatch + brief excerpt`를 `Tier1Input`으로 조립.

중요한 경계:
- `AssetSource`, `ThreatSource`, `policy` 원천 데이터는 Tier 1 builder가 직접 다루지 않는 것을 기본으로 한다.
- 필요해 보이더라도 Tier 1에 자산/CVE/정책 raw yaml을 통째로 넣지 않는다.
- Tier 1이 참조하는 전략 맥락은 Tier 2가 만든 `watchlists/latest.yaml`, `briefs/latest.md`를 통해 들어간다.

watchlist 매칭 MVP:
- `target_assets.ip == flow.dst_ip`이면 자산 매칭.
- `detection_hints` 중 구조화된 `dst_port in [...]`, `src_zone eq ...` 정도만 구현한다.
- `src_zone` 계산은 `config/assets.example.yaml`의 `trust_zones` 또는 간단한 CIDR 목록으로 구현 가능하다. 이 부분도 없으면 `unknown`으로 처리한다.

#### Phase 4 상세: Tier 1 LLM

구현 대상:
- `src/soc/llm/provider.py`: `LLMProvider`, `LLMResponse`, `OllamaProvider`, `FakeLLMProvider`.
- `src/soc/llm/json_utils.py`: JSON 추출, schema validation, fallback.
- `src/soc/llm/tier1.py`: `Tier1Analyzer` 또는 동등한 orchestration class.
- `prompts/tier1_system.md`: 한국어 verdict JSON을 강제하는 system prompt.

`FakeLLMProvider` 정책:
- 테스트와 오프라인 smoke test용.
- 입력에 `priority_1` 또는 `watchlist` 매칭이 있으면 `alert/high`를 반환.
- 아니면 `uncertain/medium` 또는 설정된 fixture를 반환.

Tier 1 출력 fallback:
- provider 호출 실패: `verdict="uncertain"`, `severity="medium"`, rationale에 실패 사유 요약.
- JSON 파싱 실패: 원문 일부를 `raw_response`로 저장하고 fallback verdict 생성.
- `confidence`가 없으면 `0.5`.

#### Phase 5 상세: Tier 2 LLM

구현 대상:
- `src/soc/tier2/input_collectors.py`: 후보 입력 수집기. 각 입력은 없으면 `missing` 상태로 기록.
- `src/soc/tier2/prompt_builder.py`: 확정된 입력만 모아 Tier 2 user prompt 생성.
- `src/soc/tier2/parser.py`: watchlist YAML, brief markdown, memory markdown 분리.
- `src/soc/tier2/batch.py`: 배치 실행 orchestration.
- `scripts/tier2_batch.py`: CLI wrapper.
- `prompts/tier2_system.md`: Watchlist & Contexts 생성 목적을 명확히 하는 system prompt.

Tier 2 입력 정책:
- 입력 후보는 발표본 기준으로 둔다. 단, 구현에서 하드코딩하지 말고 config로 켜고 끈다.
- `assets`, `policy`, `cve_feed`, `threat_feed`, `tier1_stats`, `previous_watchlist_feedback`, `qa_samples` 각각 `used/missing/disabled` 상태를 metadata에 남긴다.
- 입력이 부족해도 샘플 watchlist를 만들 수 있어야 한다.

Tier 2 출력 정책:
- API 키가 없으면 `--provider fake`로 샘플 산출물을 생성한다.
- provider raw output이 세 파일로 분리되지 않으면 최대한 복구하고, 실패 시 `output/tier2_failed_*.txt`에 원문 저장.
- `output/watchlists/latest.yaml`, `output/briefs/latest.md`, `output/memory/latest.md`는 항상 최신 성공 결과로 갱신한다.

#### Phase 6 상세: end-to-end CLI

`scripts/pipeline_run.py` 또는 `src/soc/cli/pipeline.py`가 제공해야 하는 기본 옵션:

```bash
python scripts/pipeline_run.py \
  --input data/sample/flows.csv \
  --output output/reports \
  --detector dummy \
  --tier1-provider fake \
  --watchlist output/watchlists/latest.yaml \
  --brief output/briefs/latest.md
```

처리 흐름:
1. CSV를 `Flow` 리스트로 로드.
2. detector가 `MLResult` 생성.
3. watchlist를 로드하고 매칭.
4. router가 `RouteDecision` 생성.
5. `auto_dismiss`: verdict를 자동 생성하고 DB 저장.
6. `auto_alert`: 템플릿 verdict를 생성하고 DB 저장.
7. `tier1_llm`: `Tier1Input` 조립 → Tier 1 provider 호출 → verdict 저장.
8. 각 플로우별 HTML 리포트 생성.
9. summary JSON 또는 CSV를 출력해 라우팅 분기 비율을 확인.

smoke test 합격 기준:
- 샘플 CSV 5건이 외부 API 없이 처리된다.
- HTML 리포트 5개가 생성된다.
- DB에 flows/verdicts/tier1_calls 또는 대응 테이블 row가 생성된다.
- watchlist 파일이 없어도 empty watchlist로 실행된다.

#### Phase 7 상세: 평가

골든 셋 YAML 최소 필드:

```yaml
case_id: "case_C_001"
category: "context_dependent"
flow:
  src_ip: "18.221.219.4"
  dst_ip: "172.31.69.28"
  src_port: 51515
  dst_port: 443
  protocol: "TCP"
features:
  mock_prob: 0.42
expected:
  verdict: "alert"
  severity_min: "high"
rubric:
  rationale_must_include: ["watchlist", "external"]
```

ablation 구성은 발표 정합성을 위해 다음처럼 둔다:
- `ml_only`: ML 임계치 기반 자동 판정만.
- `tier1_basic`: 플로우/ML/운영 이력만 Tier 1 제공.
- `tier1_watchlist`: basic + watchlist 매칭 제공.
- `tier1_full_context`: watchlist + brief context excerpt 제공.
- `tier1_memory_feedback`: full + 이전 watchlist hit/miss나 memory 요약 반영.
- `tier1_only_raw_context`: 비교 실험 전용. Tier 2 없이 Tier 1에 자산, 정책, CVE, threat feed 등 원천 컨텍스트를 직접 넣는다. 실제 설계안은 아니며, 교수 피드백에 답하기 위한 비용/성능 baseline이다.

교수 피드백 반영: Tier 1/2 분리 구조가 정말 토큰 비용을 줄이는지 별도 검증한다. 핵심 가설은 "Tier 2는 배치로 적게 실행되고, 그 산출물이 여러 flow에 재사용되므로 총 토큰 비용은 raw context를 매번 Tier 1에 넣는 방식보다 낮다"이다.

비용 평가 방법:
- 동일한 test case 세트를 같은 순서로 실행한다.
- `tier1_only_raw_context`와 `tier1_full_context` 또는 `tier1_memory_feedback`을 비교한다.
- 모든 LLM 호출에 대해 `prompt_tokens`, `completion_tokens`, `total_tokens`, `latency_ms`, `model_name`, `unit_price`, `estimated_cost_usd`를 기록한다.
- Tier 1/2 구조의 총비용은 `Tier 2 배치 1회 비용 + Tier 1 실시간 호출 N건 비용`으로 계산한다.
- Tier 1 only baseline의 총비용은 `raw context를 포함한 Tier 1 호출 N건 비용`으로 계산한다.
- N을 5, 30, 50, 100처럼 늘려 break-even point를 찾는다. 즉, 몇 건 이상 처리할 때 Tier 2 배치 비용이 상쇄되는지 표로 보여준다.
- API가 실제 token usage를 제공하면 그 값을 우선 사용하고, fake/local provider에서는 같은 tokenizer 또는 provider별 추정 함수를 사용해 입력/출력 토큰을 산정한다.

성능 평가 방법:
- 비용만 비교하지 않는다. 동일 test case에 대해 verdict 일치율, severity 일치율, high/critical recall, false positive 수, JSON 파싱 실패율을 함께 기록한다.
- `context_dependent` 케이스는 별도 집계한다. 이 범주에서 Tier 2 curated context가 raw context 대비 성능을 유지하거나 올리는지가 발표의 핵심 근거다.
- 최종 표는 `구성`, `총 토큰`, `flow당 평균 토큰`, `추정 비용`, `정확도/일치율`, `high recall`, `평균 지연시간`, `비고`를 포함한다.

#### Phase 8 상세: 문서화와 제출 산출물

최소 산출물:
- `README.md`
- `prompts/CHANGELOG.md`
- 샘플 `output/watchlists/watchlist_*.yaml` 2개 이상
- 샘플 `output/briefs/brief_context_*.md` 1개 이상
- 샘플 `output/memory/attack_surface_memory_*.md` 1개 이상
- HTML 이벤트 리포트 5개 이상
- ablation 결과 표

---

## 5. README 필수 항목 (과제 요구사항)

`README.md`에 반드시 포함:

```markdown
# mini LLM SOC

## 프로젝트 개요
[한 줄 + 단락 설명]

## AI 도구 활용 전략
- Cursor / Claude Code 사용 영역과 인간 검토 영역 명시
- 프롬프트 엔지니어링 접근 방식 (단순/병렬/검증)
- AI 생성 코드의 검증 방법

## 트러블슈팅 로그
- 주요 디버깅 사례 (각 사례마다: 증상 → 시도한 것 → 해결)
- AI 도구가 만든 잘못된 코드 패턴 + 수정한 방법
- 데이터셋 한계로 발생한 평가 이슈

## 실행 방법
[CLI 사용법]

## 결과
[샘플 리포트, watchlist 링크]

## 한계와 Future Work
```

---

## 6. 평가 체크리스트 (제출 전 확인)

- [ ] Git commit 50개 이상 (점진적 작업 증명)
- [ ] 프롬프트 CHANGELOG에 5개 이상 버전
- [ ] Test case 50건 yaml 형식으로 존재
- [ ] Ablation 평가 표 (기본 5개 구성 + raw context baseline × 일치율)
- [ ] Tier 1/2 분리 vs Tier 1 only raw context 토큰/비용 비교표
- [ ] 두 방식의 분류 성능 비교표
- [ ] 정성 루브릭 평가 결과 (50건)
- [ ] 샘플 HTML 리포트 5+개
- [ ] 샘플 Watchlist 2+개 (실행 주기별 변화 보여주기)
- [ ] 샘플 Attack Surface Memory 2+개
- [ ] CLI 단일 커맨드로 end-to-end 실행 가능
- [ ] 데모 영상 (5-10분)
- [ ] README의 4가지 필수 섹션
- [ ] 모든 추상 인터페이스의 첫 구현체 동작 확인

---

## 7. 시간 가이드 (느슨하게)

| Phase | 작업 | 예상 시간 |
|---|---|---|
| 1 | 기반 | 4-6시간 |
| 2 | ML 레이어 | 8-12시간 |
| 3 | 컨텍스트/자산/위협 | 6-10시간 |
| 4 | Tier 1 LLM | 8-12시간 |
| 5 | Tier 2 LLM | 8-12시간 |
| 6 | 통합 + MVP | 8-12시간 |
| 7 | 평가 | 10-15시간 |
| 8 | 마무리 | 8-12시간 |
| **합계** | | **60-91시간** |

AI 코딩 도구 활용 시 보수적으로 잡은 수치. 실제로는 Phase 1-3이 빠르게 끝나고 Phase 5(Tier 2)와 Phase 7(평가)에 시간이 몰릴 가능성 높음.

---

## 8. 우선순위 (시간 부족 시)

**반드시 (1차 목표)**:
- Phase 1, 2, 3, 4, 6 (end-to-end 작동 확인)

**중요 (2차 목표)**:
- Phase 5 (Tier 2 — 차별화 핵심)
- Phase 7 일부 (test case 30건이라도)

**가능하면 (3차 목표)**:
- Phase 8 전체
- Test case 50건 풀 채우기
- 실행 주기별 Tier 2 메모리 진화 시연

시간 진짜 부족하면: **Tier 2 watchlist만이라도 한 번 생성하고, Tier 1이 그걸 받아서 동작하는 것까지가 발표의 마지노선**. Attack Surface Memory와 ablation은 그 다음.

---

## 9. AI 코딩 도구 활용 가이드라인

**적극 활용**:
- 보일러플레이트 (인터페이스 구현, 데이터 모델, 테스트 케이스)
- 잘 알려진 패턴 (Jinja2 템플릿, SQLite 스키마, FastAPI 등)
- 디버깅 첫 단계 (에러 메시지 해석)
- 한국어 문구 다듬기

**주의해서 활용**:
- LLM 프롬프트 작성 → AI에게 맡기되 너의 의도 명시. 결과는 반드시 직접 검토하고 test로 검증.
- 평가 로직 → AI가 만든 metric 계산은 반드시 손으로 검산
- Tier 2 출력 파싱 → AI 생성 yaml 파싱 코드는 잘못된 yaml에 약함. fallback 충실히.

**직접 해야 함**:
- 평가 결과 해석 (왜 이 결과가 나왔는가)
- 프롬프트 변경의 의도와 검증 (CHANGELOG는 너의 사고 기록)
- Test case의 정답 라벨 (이게 평가의 ground truth)
- 시연 시나리오 구성

**커밋 메시지 규칙**:
- AI 도구 사용 시 명시: `feat: implement OllamaProvider (with Cursor)`
- 프롬프트 변경 시 근거 포함: `prompt: tier1 v3 — JSON parsing failure 감소 위해 출력 예시 추가`
- 디버깅 발견 시: `fix: handle empty SHAP values when prob < 0.05`

---

*이 문서는 살아있는 작업 명세다. 작업 진행 중 변경/추가 사항이 생기면 업데이트하라.*
