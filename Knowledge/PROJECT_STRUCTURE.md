# Project Structure

이 문서는 폴더와 파일의 역할을 쉽게 설명하는 안내서입니다. 작업을 하면서 구조나 책임이 바뀌면 이 문서도 같이 갱신합니다.

## 한 줄 요약

이 프로젝트는 발표자료의 구조를 따라갑니다.

- Slow Loop: Tier 2가 조직 지식과 보안 입력을 정리해서 Watchlist & Contexts를 만듭니다.
- Real Time Loop: NetFlow/flow가 ML을 먼저 지나고, 필요한 경우 Tier 1이 Watchlist & Contexts를 참고해 판정합니다.

## 전체 그림

```text
                         [ Slow Loop ]

  config/assets.example.yaml
  config/policy.example.yaml
  config/cve_feed.example.yaml
  config/threat_feed.example.yaml
  SQLite Event Store + previous feedback
             |
             v
      Tier 2 strategy layer
             |
             +--> output/watchlists/latest.yaml
             +--> output/briefs/latest.md
             +--> output/memory/latest.md
             +--> Tier 1 consumes latest curated files


                      [ Real Time Loop ]

  data/sample/flows.csv or NetFlow logs
             |
             v
       ML Binary Router
             |
             v
       Route Decision
      /      |       \
 dismiss   alert    Tier 1 LLM
             |       |
             v       v
       optional Multiclass Hint
       (explanation only; never routing)
     \       |       /
      \      |      /
       v     v     v
          SQLite Event Store
             |
             v
      output/reports/*.html
```

## ML Runtime Addendum

The CICIDS2018 binary XGBoost v1 router has been trained on the GPU workstation
and copied into this repository as a small committed runtime artifact. The goal
of the current ML layer is cheap routing, not final SOC judgment.

```text
src/soc/ml/features.py
  Defines the binary ML feature contract:
  - fixed feature order
  - excluded leak-prone fields
  - categorical feature list
  - attack hint label mapping for the later multiclass helper model
  It also builds the detector input dict from a Flow so core fields such as
  L4_DST_PORT and PROTOCOL are present during inference.

scripts/ml_train.py
  GPU-workstation training entrypoint for the CICIDS2018 binary XGBoost router.
  It uses stratified train/validation/test as the primary split, records
  time-split diagnostics, selects routing thresholds on validation, and writes
  model, metadata, metrics, and thresholds under output/models/.
  The default auto-dismiss attack leak target is 1.0%, with 0.5% recorded as
  the ideal best-effort target.

scripts/ml_train_multiclass.py
  GPU-workstation training entrypoint for the optional attack-family hint model.
  It uses the same CICIDS2018 feature contract as the binary router, filters to
  attack rows only, maps the raw Attack column through ATTACK_HINT_LABEL_MAP, and
  writes xgb_attack_hint_v1 model, metadata, and metrics artifacts under
  output/models/. This model is explanation evidence only, not route selection.

output/models/xgb_binary_v1*.json
  Trained XGBoost model artifacts copied from the GPU workstation. These
  small v1 artifacts are kept in Git so the project can move cleanly between
  development machines without retraining.
  The runtime routing default uses:
    low_threshold = 0.30
    high_threshold = 0.95

src/soc/ml/detector.py
  DummyDetector remains the offline smoke-test detector.
  XGBoostDetector now loads the trained model and metadata, validates the
  feature contract, applies categorical encoders, and returns MLResult.prob.
  XGBoostDetector can also load the optional xgb_attack_hint_v1 multiclass model.
  The pipeline calls it only after binary routing for auto_alert and tier1_llm
  events. auto_dismiss records category_hint=not_evaluated. SHAP top5 is still
  computed only for the tier1_llm route, so auto_dismiss and auto_alert stay
  cheap.

src/soc/cli/pipeline.py
  Supports:
    --config config/settings.example.yaml
    --detector dummy
    --detector xgboost --model ... --metadata ... --thresholds ...
    --category-model ... --category-metadata ...
    --llm fake
    --llm ollama --llm-model gemma4:e4b --ollama-url ...
    --sqlite output/soc_events.sqlite
    --no-storage
    --tier1-mode sequential
    --tier1-mode queue --tier1-workers ... --tier1-queue-max-size ...
  The pipeline passes L4_DST_PORT and PROTOCOL back into the detector feature
  surface so training and inference use the same feature order.
  It also keeps SHAP evidence limited to tier1_llm events before report/LLM
  rendering. Category hints are route-after evidence only and never change
  binary route decisions.
  Queue mode runs as a producer-consumer bounded queue. The producer routes each
  flow through cheap ML, completes auto_dismiss and auto_alert immediately, and
  enqueues only tier1_llm events. Worker tasks consume the queue concurrently.
  When storage is enabled, every flow writes flow, ML result, route decision,
  verdict, and Tier 1 call/fallback metadata to SQLite before HTML rendering.
  Queue overflow, timeout, or call-limit cases produce uncertain/medium fallback
  verdicts instead of silently dropping events.
  CLI options override config file values. This keeps the YAML file as the
  dashboard-friendly source of runtime settings while preserving quick one-off
  experiments from the terminal.

data/sample/xgb_route_sample.csv
  Small tracked sample generated from CICIDS2018 for model-backed route smoke
  testing. It contains examples for auto_dismiss, tier1_llm, and auto_alert.
  The XGBoost integration test uses it to verify SHAP evidence appears in the
  tier1_llm HTML report.

output/reports_xgb_sample/
  Local generated HTML sample from the XGBoost route smoke path. It is useful
  for manual inspection but remains an output artifact.
  It also has a --preflight-only mode for new machines. That mode loads and
  validates the dataset, prints distribution counts, and stops before training.
  Full training prints timestamped progress logs and periodic XGBoost evaluation
  output so long GPU runs are observable.

requirements-ml.txt
  ML runtime and training dependencies. Docker installs this file so the
  XGBoost detector path is reproducible across both development machines.

Knowledge/GPU_TRAINING_HANDOFF.md
  Exact handoff instructions for the GPU Codex session. It explains the fixed
  feature contract, split policy, threshold policy, SHAP policy, and which
  output files must be copied back.
```

## 2026-05-01 Real Time Loop Hardening

The Real Time Loop is now treated as model-backed by default while staying
repeatable without a live local LLM.

```text
config/settings.example.yaml
  runtime.input: data/sample/xgb_route_sample.csv
  detector.provider: xgboost
  tier1.queue.mode: queue
  tier1.llm.provider: fake
```

Use `--llm ollama --llm-model gemma4:e4b --ollama-url ...` when validating the
real local Tier 1 model. The fake provider remains the default because it keeps
Docker tests and laptop handoff runs deterministic.

Tier 1 LLM response handling:

```text
soc.llm.tier1.judge_flow
  -> calls provider
  -> parses JSON
  -> accepts only verdict in benign/alert/uncertain
  -> accepts only severity in low/medium/high/critical
  -> invalid JSON or invalid schema becomes uncertain/medium fallback
  -> preserves provider model, token count, and latency metadata

SQLiteEventStore.tier1_calls
  -> records provider, model_name, latency_ms, tokens_used, success,
     fallback_reason for every Tier 1 path event when storage is enabled
```

Multiclass attack-family hint boundary:

```text
XGBoostDetector.predict()
  -> binary probability only; this decides routing thresholds

XGBoostDetector.predict_category_hint()
  -> optional attack-family hint model
  -> evaluated only after binary routing
  -> used for auto_alert and tier1_llm evidence
  -> never changes auto_dismiss / tier1_llm / auto_alert route selection

XGBoostDetector.explain()
  -> SHAP top5 evidence
  -> computed only for tier1_llm to keep cheap paths cheap
```

Slow Loop work should build on this boundary. Tier 2 should consume SQLite
history and enabled organization/security inputs, then curate watchlist,
brief, and memory files. It should not push raw asset/CVE/policy/threat-feed
dumps into Tier 1.

## Slow Loop Source Boundary Decision

This decision is fixed for future sessions and should not be reopened unless
the user explicitly asks to redesign the architecture.

```text
config/assets.example.yaml
config/policy.example.yaml
config/cve_feed.example.yaml
config/threat_feed.example.yaml
        |
        v
YAML-backed InfoProviders for the MVP
        |
        v
SourceSnapshot(name, status, source_type, path_or_uri, item_count, content, error)
        |
        v
Tier2InputCollector
        |
        v
Tier 2 LLM prompt builder
        |
        v
watchlist + brief + memory
        |
        v
Tier 1 consumes curated outputs only
```

The MVP reads the planned YAML files through provider implementations. That is
not a raw Tier 1 context dump. It is the first implementation of a stable
provider boundary that can later support DB-backed or API-backed providers:

```text
YamlAssetInfoProvider    -> later DbAssetInfoProvider
YamlPolicyInfoProvider   -> later DbPolicyInfoProvider
YamlCveInfoProvider      -> later ApiCveInfoProvider
YamlThreatInfoProvider   -> later ThreatIntelApiProvider
```

Each provider returns a source snapshot with:

```text
name: assets | policy | cve_feed | threat_feed | feedback | ...
status: used | missing | disabled | error
source_type: yaml | db | api
path_or_uri: config/assets.example.yaml or API/DB identifier
item_count: number of loaded records or rules
content: normalized provider payload
error: parse/load/fetch error text, or null
```

`status` metadata is required because Tier 2 must distinguish a legitimately
empty source from a missing, disabled, or broken source. Tier 2 prompt builders
should include content only from `used` snapshots, while still including a
compact status summary for all enabled or configured sources. Tier 2 outputs
should preserve this status summary, especially in `watchlists/latest.yaml`.

`tier2_runs` persistence and a formal Tier 2 DB summary contract are Slow Loop
implementation tasks. They are not required to declare the current Real Time
Loop complete.

Current ML boundary:

```text
Repository:
  trained XGBoost v1 model + metadata + thresholds are present
  Docker installs the ML runtime dependencies
  tests cover dummy smoke and XGBoost+SHAP route smoke

GPU workstation:
  used only when retraining xgb_binary_v1 or creating a later model version
```

## 폴더 역할

```text
.
|-- AGENTS.md
|   다음 작업자가 반드시 기억해야 할 프로젝트 규칙입니다.
|
|-- Knowledge/
|   발표자료, 구현 명세, 제안서, 쉬운 구조 설명을 둡니다.
|
|-- config/
|   Slow Loop가 읽을 조직/보안 입력 예시입니다.
|
|-- data/
|   샘플 입력 데이터입니다. 큰 원본 데이터셋은 Dataset/에 있고 Git에는 올리지 않습니다.
|
|-- src/soc/
|   실제 Python 패키지입니다.
|
|-- scripts/
|   사람이 직접 실행하는 CLI wrapper입니다.
|
|-- prompts/
|   Tier 1, Tier 2 프롬프트와 변경 이력입니다.
|
|-- tests/
|   단위 테스트와 통합 smoke test입니다.
|
|-- output/
|   실행 결과가 생성되는 위치입니다. 최신 watchlist, brief, memory, report가 여기에 생깁니다.
|
|-- Dockerfile
|   Python 3.11 실행 환경을 Docker 이미지로 고정합니다. 테스트와 XGBoost 런타임 의존성을 함께 설치합니다.
|
|-- compose.yaml
|   Docker 명령을 짧게 실행하기 위한 설정입니다.
|
|-- .dockerignore
|   Docker 이미지 빌드에 필요 없는 큰 파일과 로컬 산출물을 제외합니다.
|
|-- .venv/
|   선택 사항인 로컬 Python 가상환경입니다. Git에는 올리지 않고, 노트북 이전 기준 실행은 Docker를 우선합니다.
```

## 핵심 파일 역할

```text
src/soc/models.py
  Flow, MLResult, Verdict 같은 공통 데이터 모양을 정의합니다.

src/soc/io.py
  CSV flow 파일을 읽어 Flow 객체로 바꿉니다.

src/soc/ml/detector.py
  ML 탐지기 인터페이스, DummyDetector, XGBoostDetector가 있습니다.
  XGBoostDetector는 학습된 binary 모델과 metadata를 로드하고, 선택적으로 multiclass
  category hint 모델을 로드합니다. category hint는 auto_alert와 tier1_llm에만
  route 이후 설명용으로 붙고, tier1_llm 경로에만 SHAP top5 근거를 제공합니다.

src/soc/routing/router.py
  ML 확률을 보고 auto_dismiss, auto_alert, tier1_llm 중 하나로 보냅니다.

src/soc/context/watchlist.py
  Tier 2가 만든 latest.yaml을 읽고 flow가 watchlist에 걸리는지 확인합니다.

src/soc/context/activity.py
  같은 출발지의 최근 활동을 간단히 요약합니다.

  Storage enabled runs use SQLite history for same-source activity. Storage
  disabled runs keep the previous same-run in-memory fallback.

src/soc/storage/sqlite.py
  SQLiteEventStore owns the MVP operational history for the Real Time Loop:
  flows, ml_results, route_decisions, verdicts, and tier1_calls. It also
  summarizes recent same-source DB history for Tier 1 context.

src/soc/asset/source.py
  조직 자산 카탈로그를 읽는 AssetSource 인터페이스입니다.
  지금은 껍데기만 있고, 다음 단계에서 YAML 구현체를 채웁니다.

src/soc/threat/source.py
  위협 인텔을 읽는 ThreatSource 인터페이스입니다.
  지금은 껍데기만 있고, 다음 단계에서 YAML 구현체를 채웁니다.

src/soc/llm/provider.py
  LLMProvider 인터페이스, FakeLLMProvider, OllamaProvider가 있습니다.
  OllamaProvider는 /api/generate를 stream=false로 호출하고 JSON 응답 모드에서
  Tier 1 verdict를 받습니다. Docker에서 Windows host의 Ollama를 사용할 때는
  --ollama-url http://host.docker.internal:11434 를 사용합니다.

src/soc/llm/tier1.py
  Tier 1 입력을 조립하고 LLM 판정 결과를 Verdict로 바꿉니다.
  prompts/tier1_system.md를 system prompt로 읽고, provider 실패나 JSON 파싱 실패는
  uncertain/medium fallback verdict로 안전하게 처리합니다.

src/soc/config/settings.py
  Typed runtime settings loader for the Real Time Loop. It reads YAML settings,
  validates detector / LLM / queue choices, and applies CLI overrides. The same
  loader can later be reused by a dashboard or API layer.
  StorageSettings controls whether SQLite persistence is enabled and where the
  event database is written.

src/soc/tier2/batch.py
  FakeTier2Runner가 Slow Loop 산출물을 만듭니다.

src/soc/tier2/writer.py
  watchlist, brief, memory를 주차별 파일과 latest 파일로 저장합니다.

src/soc/report/renderer.py
  각 flow 결과를 HTML 리포트로 저장합니다.
  Summary HTML also includes Tier 1 queue statistics: mode, worker count,
  queued calls, actual LLM calls, total fallbacks, queue fallbacks, LLM/provider
  fallbacks, timeouts, overflow count, call-limit skips, and wait-time metrics.

src/soc/cli/pipeline.py
  Real Time Loop를 CLI에서 실행합니다.

  Persists operational records to SQLite when storage is enabled, then renders
  the same HTML reports as before.

scripts/tier2_batch.py
  Slow Loop 껍데기를 실행합니다.

scripts/pipeline_run.py
  Real Time Loop 껍데기를 실행합니다.

requirements-dev.txt
  테스트 실행에 필요한 개발용 패키지 목록입니다. 현재는 pytest가 들어 있습니다.

requirements-ml.txt
  XGBoost 런타임과 학습에 필요한 패키지 목록입니다. Docker 이미지에도 설치됩니다.

tests/integration/test_xgboost_pipeline.py
  학습 완료 XGBoost 모델로 샘플 flow를 라우팅하고 tier1_llm HTML에 SHAP 근거가 포함되는지 확인합니다.
```

## 지금 상태

현재 구현은 XGBoost 기반 cheap routing과 Ollama 기반 로컬 Tier 1 LLM 호출까지 들어온 상태입니다. FakeLLMProvider는 오프라인 smoke test용으로 유지합니다.

```text
FakeTier2Runner
  -> output/watchlists/latest.yaml 생성
  -> output/briefs/latest.md 생성
  -> output/memory/latest.md 생성

DummyDetector + FakeLLMProvider
  -> data/sample/flows.csv 처리
  -> output/reports/*.html 생성

XGBoostDetector + FakeLLMProvider
  -> data/sample/xgb_route_sample.csv 처리
  -> auto_dismiss / tier1_llm / auto_alert 라우팅 확인
  -> auto_alert / tier1_llm 리포트에 category hint 표시
  -> tier1_llm HTML 리포트에만 SHAP top5 근거 표시

XGBoostDetector + OllamaProvider
  -> Docker 컨테이너에서 host.docker.internal:11434의 Ollama API 호출
  -> gemma4:e4b 같은 로컬 모델로 Tier 1 verdict JSON 생성
  -> provider 실패 또는 JSON 파싱 실패 시 uncertain/medium fallback

Tier 1 queue mode
  -> ML/router가 모든 flow를 먼저 빠르게 분류
  -> auto_dismiss / auto_alert는 LLM queue를 기다리지 않고 verdict 생성
  -> tier1_llm만 producer-consumer bounded queue에 넣고 worker가 동시에 처리
  -> priority_1 watchlist match는 watchlist_first 정책에서 queued backlog 안에서 먼저 처리
  -> queue full / timeout / max calls 제한은 queue fallback으로 기록
  -> Ollama/API 실패와 JSON 파싱 실패는 LLM fallback으로 따로 기록
  -> summary.html에 tier1_calls, tier1_queued, queue/LLM fallback, wait time 기록
```

## 현재 PC에서 실행하는 법

이 컴퓨터에는 Docker Desktop과 WSL2가 준비되어 있으므로 Docker 실행을 우선 사용합니다.

```powershell
docker compose run --rm app python -m pytest
docker compose run --rm app python scripts/tier2_batch.py --config config/settings.example.yaml
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml
docker compose run --rm app python scripts/pipeline_run.py --config config/settings.example.yaml --input data/sample/xgb_route_sample.csv --output output/reports_ollama_queue --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://host.docker.internal:11434 --tier1-mode queue --tier1-workers 1 --tier1-queue-max-size 50 --tier1-queue-timeout 300 --tier1-overflow-policy fallback --tier1-priority-policy watchlist_first
```

로컬 Python을 쓰는 경우에는 프로젝트 루트의 `.venv`를 사용합니다.

```powershell
.\.venv\Scripts\python.exe scripts\tier2_batch.py --config config\settings.example.yaml
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\flows.csv --output output\reports --detector dummy --llm fake
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\xgb_route_sample.csv --output output\reports_xgb_sample --detector xgboost --llm fake
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\xgb_route_sample.csv --output output\reports_ollama --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://localhost:11434
.\.venv\Scripts\python.exe scripts\pipeline_run.py --input data\sample\xgb_route_sample.csv --output output\reports_ollama_queue --detector xgboost --llm ollama --llm-model gemma4:e4b --ollama-url http://localhost:11434 --tier1-mode queue --tier1-workers 1
.\.venv\Scripts\python.exe -m pytest
```

## 다음 작업: Tier 1 처리 운영화

Real Time Loop는 이제 FakeLLMProvider, OllamaProvider, bounded Tier 1 queue를
지원합니다. 다음 목표는 queue 옵션을 설정 파일로 옮기고, 실제 품질 평가와 저장소
연동을 붙이는 것입니다.

```text
Need:
  실제 로컬 LLM 품질 평가
  queue policy evaluation: sequential vs queue, call-limit fallback, timeout behavior
  Tier 2 reads SQLite event history for feedback-aware slow loop summaries

Not yet:
  Tier 2 실제 LLM 배치
```

## 추가 평가 작업: 토큰 비용 검증

교수 피드백에 따라 Tier 1/2 분리 구조가 실제로 비용 효율적인지 정량 검증해야 합니다.

비교 대상은 두 가지입니다.

```text
Current architecture
  Tier 2 batch
    -> assets / policy / CVE / threat feed / feedback을 주기적으로 압축
    -> watchlist + brief + memory 생성
  Tier 1 realtime
    -> flow + ML/SHAP + activity + watchlist/brief excerpt로 판정

Baseline for experiment only
  Tier 1 only raw context
    -> flow마다 assets / policy / CVE / threat feed를 직접 포함
    -> Tier 2 없이 한 번에 판정
```

측정해야 할 값:
- 토큰/비용: prompt tokens, completion tokens, total tokens, estimated cost, latency.
- 총비용 공식: Tier 1/2 구조는 `Tier 2 배치 1회 + Tier 1 N건`, baseline은 `raw context Tier 1 N건`.
- break-even point: flow 수 N이 커질수록 Tier 2 배치 비용이 언제 상쇄되는지 확인.
- 성능: verdict 일치율, severity 일치율, high/critical recall, false positive 수, JSON 파싱 실패율.

## 다음에 바꿀 가짜 부품

```text
DummyDetector     -> XGBoostDetector for model-backed runs
FakeLLMProvider   -> OllamaProvider first, API providers later
FakeTier2Runner   -> 실제 Tier 2 LLM 배치
StaticYAMLAssetSource / StaticYAMLThreatSource -> 실제 YAML 로더
HTMLRenderer      -> 더 읽기 좋은 한국어 리포트
SQLiteEventStore  -> Tier 2 feedback queries and richer SOC operations
```
